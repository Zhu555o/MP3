# server.py
import os
import sys
import uuid
import filetype
import time
import logging
from logging.handlers import RotatingFileHandler
import json
import re
import urllib.parse # 导入 urllib.parse
import concurrent.futures
from io import BytesIO
from datetime import datetime
import sqlite3
from functools import wraps, lru_cache
# --- Flask 及扩展导入 ---
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, make_response, abort, send_from_directory, Response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf # 确保导入
# --- 配置文件处理 ---
import configparser
# --- OSS SDK 导入 ---
try:
    import oss2
    OSS_AVAILABLE = True
except ImportError:
    OSS_AVAILABLE = False
    print("警告: OSS SDK (oss2) 未安装，云存储功能不可用")
# --- Celery 导入 ---
try:
    from celery import Celery
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    print("警告: Celery 未安装，异步任务功能不可用")
# --- 音频验证库 (示例) ---
# pip install mutagen
try:
    from mutagen.mp3 import MP3
    MUTAGEN_AVAILABLE = True
except ImportError:
    MUTAGEN_AVAILABLE = False
    print("提示: Mutagen 未安装，将仅使用基础文件类型检查。")
# --- 导入 Celery Worker 模块以注册任务 ---
import celery_worker
# --- 配置文件路径 ---
config_path = 'server_config.ini'
# --- 辅助函数：安全获取配置值 (优先环境变量) ---
def get_config_value(section, key, default_value='', env_var_name=None):
    """从环境变量或配置文件获取配置值，环境变量优先"""
    if env_var_name:
        env_value = os.getenv(env_var_name)
        if env_value is not None:
            return env_value
    config = configparser.ConfigParser()
    if os.path.exists(config_path):
        config.read(config_path, encoding='utf-8')
        if config.has_option(section, key):
            return config.get(section, key)
    return default_value
# --- 用户数据库初始化 ---
def init_user_db():
    """初始化用户数据库"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # 创建用户表
    c.execute('''CREATE TABLE IF NOT EXISTS users
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                is_active BOOLEAN DEFAULT 1,
                created_by_admin BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    # 创建待审核密码修改表
    c.execute('''CREATE TABLE IF NOT EXISTS pending_password_changes
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                new_password_hash TEXT NOT NULL,
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id))''')
    # 创建操作日志表
    c.execute('''CREATE TABLE IF NOT EXISTS user_logs
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id))''')
    # 创建默认管理员账户 (如果不存在)
    try:
        c.execute("INSERT INTO users (username, password_hash, is_admin, created_by_admin) VALUES (?, ?, ?, ?)",
                ('admin', get_config_value('USER', 'PASSWORD_HASH', ''), 1, 1))
    except sqlite3.IntegrityError:
        # 管理员已存在
        pass
    conn.commit()
    conn.close()

# 在应用启动时调用
init_user_db()
# --- 创建默认配置文件 ---
if not os.path.exists(config_path):
    config = configparser.ConfigParser()
    config['SERVER'] = {
        'HOST': '0.0.0.0',
        'PORT': '5000',
        'UPLOAD_FOLDER': 'uploads',
        'MAX_WORKERS': '4'
    }
    config['DOWNLOAD'] = {
        'DOWNLOAD_HOST_1': '127.0.0.1',
        'DOWNLOAD_PORT_1': '5000',
        'DOWNLOAD_HOST_2': '127.0.0.1',
        'DOWNLOAD_PORT_2': '5000'
    }
    config['FLASK_APP'] = {
        'SECRET_KEY': 'dev-secret-key-change-in-production' # 建议在生产环境更改
    }
    config['UPLOAD_SETTINGS'] = {
        'MAX_FILE_SIZE_MB': '100'
    }
    config['SECURITY'] = {
        'DELETE_PASSWORD': 'change-this-password', # 建议在生产环境更改
        'IP_BAN_ENABLED': 'false' # 启用 IP 封禁、白名单、黑名单功能
    }
    # 添加默认 OSS 配置
    config['OSS'] = {
        'ENABLED': 'false', # 默认关闭
        'PROVIDER': 'aliyun_oss',
        'ACCESS_KEY_ID': 'YOUR_PLACEHOLDER_ACCESS_KEY_ID',
        'ACCESS_KEY_SECRET': 'YOUR_PLACEHOLDER_ACCESS_KEY_SECRET',
        'BUCKET_NAME': 'your-unique-mp3-bucket',
        'ENDPOINT': 'oss-cn-hangzhou.aliyuncs.com', # 示例
        'REGION': 'cn-hangzhou', # 示例
        'CDN_DOMAIN': ''
    }
    # 添加默认用户配置
    config['USER'] = {
        'USERNAME': 'admin', # 默认用户名
        'PASSWORD_HASH': '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.PZvO.S' # 'password' 的 bcrypt 哈希 (示例)
    }
    # 添加 Flask-Limiter 配置
    config['RATE_LIMIT'] = {
        'STORAGE_URL': 'memory://', # 可改为 redis://localhost:6379/1
        'UPLOAD_LIMIT': '10 per minute',
        'ASYNC_UPLOAD_LIMIT': '20 per minute',
        'DELETE_LIMIT': '30 per minute'
    }
    # 添加 Celery 配置
    config['CELERY'] = {
        'BROKER_URL': 'redis://localhost:6379/0', # 可改为 pyamqp://guest@localhost//
        'RESULT_BACKEND': 'redis://localhost:6379/0' # 可改为 rpc://
    }
    with open(config_path, 'w', encoding='utf-8') as f:
        config.write(f)
    print(f"默认配置文件已创建在 {config_path}。")
    print("请务必编辑该文件，特别是 [FLASK_APP] 下的 SECRET_KEY，[DOWNLOAD] 下的 DOWNLOAD_HOST_1/PORT_1 和 DOWNLOAD_HOST_2/PORT_2，[SECURITY] 下的 DELETE_PASSWORD 和 IP_BAN_ENABLED，[USER] 下的 USERNAME 和 PASSWORD_HASH，以及 [OSS], [RATE_LIMIT], [CELERY] 下的相关配置。")
    print("或者，您可以通过设置对应的环境变量来覆盖配置文件中的值。")
else:
    config = configparser.ConfigParser()
    config.read(config_path, encoding='utf-8')
# --- 读取配置值 (使用新的辅助函数) ---
# Server & App Settings
SERVER_HOST = get_config_value('SERVER', 'HOST', '0.0.0.0', 'SERVER_HOST')
SERVER_PORT = int(get_config_value('SERVER', 'PORT', '5000', 'SERVER_PORT'))
UPLOAD_FOLDER = get_config_value('SERVER', 'UPLOAD_FOLDER', 'uploads', 'UPLOAD_FOLDER')
MAX_WORKERS = int(get_config_value('SERVER', 'MAX_WORKERS', '4', 'MAX_WORKERS'))
FLASK_SECRET_KEY = get_config_value('FLASK_APP', 'SECRET_KEY', 'dev-secret-key-change-in-production', 'FLASK_SECRET_KEY')
MAX_FILE_SIZE_MB = int(get_config_value('UPLOAD_SETTINGS', 'MAX_FILE_SIZE_MB', '100', 'MAX_FILE_SIZE_MB'))
# Download Settings
DOWNLOAD_HOST_1 = get_config_value('DOWNLOAD', 'DOWNLOAD_HOST_1', '127.0.0.1', 'DOWNLOAD_HOST_1')
DOWNLOAD_PORT_1 = int(get_config_value('DOWNLOAD', 'DOWNLOAD_PORT_1', '5000', 'DOWNLOAD_PORT_1'))
DOWNLOAD_HOST_2 = get_config_value('DOWNLOAD', 'DOWNLOAD_HOST_2', '127.0.0.1', 'DOWNLOAD_HOST_2')
DOWNLOAD_PORT_2 = int(get_config_value('DOWNLOAD', 'DOWNLOAD_PORT_2', '5000', 'DOWNLOAD_PORT_2'))
# Security Settings
DELETE_PASSWORD = get_config_value('SECURITY', 'DELETE_PASSWORD', 'change-this-password', 'DELETE_PASSWORD')
IP_BAN_ENABLED_STR = get_config_value('SECURITY', 'IP_BAN_ENABLED', 'false', 'IP_BAN_ENABLED')
IP_BAN_ENABLED = IP_BAN_ENABLED_STR.lower() in ('true', '1', 'yes', 'on')
# OSS Settings
OSS_ENABLED_STR = get_config_value('OSS', 'ENABLED', 'false', 'OSS_ENABLED')
OSS_ENABLED = OSS_ENABLED_STR.lower() in ('true', '1', 'yes', 'on')
OSS_PROVIDER = get_config_value('OSS', 'PROVIDER', '', 'OSS_PROVIDER')
OSS_ACCESS_KEY_ID = os.getenv('OSS_ACCESS_KEY_ID') or get_config_value('OSS', 'ACCESS_KEY_ID', '', 'OSS_ACCESS_KEY_ID') # 优先环境变量
OSS_ACCESS_KEY_SECRET = os.getenv('OSS_ACCESS_KEY_SECRET') or get_config_value('OSS', 'ACCESS_KEY_SECRET', '', 'OSS_ACCESS_KEY_SECRET') # 优先环境变量
OSS_BUCKET_NAME = get_config_value('OSS', 'BUCKET_NAME', '', 'OSS_BUCKET_NAME')
OSS_ENDPOINT = get_config_value('OSS', 'ENDPOINT', '', 'OSS_ENDPOINT')
OSS_REGION = get_config_value('OSS', 'REGION', '', 'OSS_REGION')
OSS_CDN_DOMAIN = get_config_value('OSS', 'CDN_DOMAIN', '', 'OSS_CDN_DOMAIN')
# User Settings
USER_USERNAME = get_config_value('USER', 'USERNAME', 'admin', 'USER_USERNAME')
USER_PASSWORD_HASH = get_config_value('USER', 'PASSWORD_HASH', '', 'USER_PASSWORD_HASH')
# Rate Limit Settings
RATE_LIMIT_STORAGE_URL = get_config_value('RATE_LIMIT', 'STORAGE_URL', 'memory://', 'RATE_LIMIT_STORAGE_URL')
UPLOAD_LIMIT = get_config_value('RATE_LIMIT', 'UPLOAD_LIMIT', '10 per minute', 'UPLOAD_LIMIT')
ASYNC_UPLOAD_LIMIT = get_config_value('RATE_LIMIT', 'ASYNC_UPLOAD_LIMIT', '20 per minute', 'ASYNC_UPLOAD_LIMIT')
DELETE_LIMIT = get_config_value('RATE_LIMIT', 'DELETE_LIMIT', '30 per minute', 'DELETE_LIMIT')
# Celery Settings
CELERY_BROKER_URL = get_config_value('CELERY', 'BROKER_URL', 'redis://localhost:6379/0', 'CELERY_BROKER_URL')
CELERY_RESULT_BACKEND = get_config_value('CELERY', 'RESULT_BACKEND', 'redis://localhost:6379/0', 'CELERY_RESULT_BACKEND')
# --- IP 封禁、白名单、黑名单配置 ---
# 定义文件路径
WHITELIST_FILE = 'whitelist.txt'
BLACKLIST_FILE = 'blacklist.txt'
BANLIST_FILE = 'banlist.txt' # 用于存储自动封禁的 IP

# --- 创建默认的白名单和黑名单文件 (如果不存在) ---
def create_default_list_files():
    """创建默认的白名单和黑名单文件"""
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'w') as f:
            f.write("# IP 白名单\n")
            f.write("# 每行一个 IP 地址\n")
            f.write("# 127.0.0.1\n") # 示例，可选添加本地地址
        print(f"默认白名单文件已创建在 {WHITELIST_FILE}。")

    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'w') as f:
            f.write("# IP 黑名单\n")
            f.write("# 每行一个 IP 地址\n")
        print(f"默认黑名单文件已创建在 {BLACKLIST_FILE}。")

    if not os.path.exists(BANLIST_FILE):
        with open(BANLIST_FILE, 'w') as f:
            f.write("# 自动封禁的 IP 列表\n")
            f.write("# 每行一个 IP 地址\n")
        print(f"默认封禁列表文件已创建在 {BANLIST_FILE}。")

# 在应用启动时调用
create_default_list_files()

# --- 辅助函数：读取 IP 列表文件 ---
def load_ip_list(filepath):
    """从文件加载 IP 列表，忽略注释和空行"""
    ip_set = set()
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    # 忽略空行和注释行
                    if line and not line.startswith('#'):
                        ip_set.add(line)
        except Exception as e:
            logger.error(f"读取 IP 列表文件 {filepath} 时出错: {e}")
    return ip_set

# --- 辅助函数：保存 IP 列表到文件 ---
def save_banlist(ip_set):
    """将封禁的 IP 集合保存到文件"""
    try:
        with open(BANLIST_FILE, 'w') as f:
            f.write("# 自动封禁的 IP 列表\n")
            f.write("# 每行一个 IP 地址\n")
            for ip in sorted(ip_set): # 排序后写入，便于查看
                f.write(f"{ip}\n")
    except Exception as e:
        logger.error(f"保存封禁列表到 {BANLIST_FILE} 时出错: {e}")

# --- 辅助函数：获取客户端真实 IP ---
def get_real_ip():
    """尝试获取客户端的真实 IP 地址"""
    # 优先检查常见的代理/负载均衡头
    if request.environ.get('HTTP_X_FORWARDED_FOR') is not None:
        # X-Forwarded-For 可能包含多个 IP，第一个通常是客户端 IP
        ip = request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    elif request.environ.get('HTTP_X_REAL_IP') is not None:
        ip = request.environ['HTTP_X_REAL_IP']
    else:
        # 如果没有代理，则使用 REMOTE_ADDR
        ip = request.environ.get('REMOTE_ADDR')
    return ip

# --- 初始化 Flask 应用 ---
app = Flask(__name__, template_folder='templates')
app.secret_key = FLASK_SECRET_KEY # Flask-Login 和 CSRF 需要 secret_key
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE_MB * 1024 * 1024
# --- 初始化 Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录以访问此页面。'
# --- 初始化 Flask-Limiter ---
limiter = Limiter(
    app=app,  # <-- 明确使用关键字参数 'app'
    key_func=get_remote_address,
    storage_uri=RATE_LIMIT_STORAGE_URL, # 从配置读取
    default_limits=[] # 默认无限制，按需设置
)
# --- 初始化 Flask-WTF CSRF 保护 (确保这行存在并正确执行) ---
csrf = CSRFProtect(app)
# --- 重构 User 类 ---
class User(UserMixin):
    def __init__(self, user_id, username, is_admin=False, is_active=True):
        self.id = user_id
        self.username = username
        self.is_admin = is_admin
        self._is_active = is_active

    def get_id(self):
        return str(self.id)
    # --- 新增：重写 is_active 属性 ---
    @property
    def is_active(self):
        return self._is_active
# --- 更新用户加载回调 ---
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, is_admin, is_active FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        return User(user_data[0], user_data[1], bool(user_data[2]), bool(user_data[3]))
    return None
from flask import get_flashed_messages
# --- 新增：权限检查装饰器 ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403) # Forbidden
        return f(*args, **kwargs)
    return decorated_function
# --- 辅助函数：记录用户操作日志的函数 ---
def log_user_action(action, details=""):
    """记录用户操作日志"""
    if not current_user.is_authenticated:
        return
# --- OSS 客户端初始化 ---
oss_client = None
if OSS_ENABLED and OSS_AVAILABLE:
    try:
        auth = oss2.Auth(OSS_ACCESS_KEY_ID, OSS_ACCESS_KEY_SECRET)
        if OSS_PROVIDER == 'aliyun_oss':
            oss_client = oss2.Bucket(auth, OSS_ENDPOINT, OSS_BUCKET_NAME)
            print("阿里云 OSS 客户端已初始化")
        # ... 其他提供商 ...
        else:
            print(f"未知的 OSS 提供商: {OSS_PROVIDER}")
            OSS_ENABLED = False
    except Exception as e:
        print(f"初始化 OSS 客户端失败: {e}")
        OSS_ENABLED = False
else:
    print("OSS 功能未启用或 SDK 不可用")
# --- 确保上传目录存在 ---
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# --- 日志配置 ---
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
log_handler = RotatingFileHandler('server.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.INFO)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)
logger = app.logger
# --- 文件类型检查 (增强版) ---
def check_file_type(filepath):
    """检查文件类型是否为MP3 (增强版)"""
    try:
        # 1. 使用 filetype 库进行初步检查
        kind = filetype.guess(filepath)
        if kind is None or kind.mime != 'audio/mpeg':
             logger.warning(f"文件类型检查失败 (filetype): {filepath}")
             return False
        # 2. 使用 Mutagen 进行更严格的音频格式验证 (可选)
        if MUTAGEN_AVAILABLE:
            try:
                audio = MP3(filepath)
                # 如果能成功加载 MP3 对象，说明是有效的 MP3 文件
                # 可以在这里添加更多检查，如比特率、采样率等
                logger.debug(f"Mutagen 验证成功: {filepath}")
            except Exception as e:
                 logger.warning(f"Mutagen 验证失败: {filepath}, Error: {e}")
                 return False # 如果 Mutagen 无法解析，则认为无效
        else:
             logger.info(f"Mutagen 未安装，跳过深度音频验证: {filepath}")
        return True
    except Exception as e:
        logger.error(f"文件类型检查时发生错误: {filepath}, Error: {e}")
        return False
# --- 辅助函数：清理文件名中的特殊字符 ---
def sanitize_filename(filename, max_length=200):
    """清理文件名中的特殊字符"""
    if not filename:
        return ""
    # 移除路径分隔符和一些危险字符
    filename = re.sub(r'[\\/:*?"<>|\x00-\x1f]', '', filename)
    # 移除或替换可能导致问题的点 (例如，以点开头或结尾)
    filename = filename.strip('.')
    # 防止目录遍历
    filename = filename.replace('..', '_')
    # 限制长度
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        # 确保扩展名不被截断
        if ext:
            filename = name[:max_length-len(ext)] + ext
        else:
            filename = filename[:max_length]
    return filename
# --- 辅助函数：生成安全的文件名 ---
def generate_safe_filename(base_name, extension):
    """生成唯一且安全的文件名"""
    base_name = sanitize_filename(base_name)
    if not base_name:
        base_name = "untitled"
    filename = f"{base_name}{extension}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    counter = 1
    max_attempts = 100
    max_base_length = 255 - len(extension) - 10 # 为数字和分隔符留空间
    while os.path.exists(filepath) and counter < max_attempts:
        new_base_name = f"{base_name}_{counter}"
        if len(new_base_name) > max_base_length:
            new_base_name = new_base_name[:max_base_length]
        filename = f"{new_base_name}{extension}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        counter += 1
    if counter >= max_attempts:
        # 如果尝试次数过多，使用UUID
        unique_id = str(uuid.uuid4())[:8]
        new_base_name = f"{base_name}_{unique_id}"
        if len(new_base_name) > max_base_length:
            new_base_name = new_base_name[:max_base_length]
        filename = f"{new_base_name}{extension}"
    return filename
# --- 辅助函数：路径安全检查 ---
def is_safe_path(basedir, path):
    """检查路径是否安全，防止路径遍历攻击"""
    return os.path.realpath(path).startswith(os.path.realpath(basedir))
# --- 辅助函数：上传文件到 OSS ---
def upload_file_to_oss(local_filepath, oss_object_name):
    """上传文件到 OSS"""
    if not oss_client:
        logger.error("OSS 客户端未初始化")
        return False
    try:
        if OSS_PROVIDER == 'aliyun_oss':
            oss_client.put_object_from_file(oss_object_name, local_filepath)
            logger.info(f"文件 {oss_object_name} 已同步上传到 OSS。")
            return True
        # ... 其他提供商 ...
    except Exception as e:
        logger.error(f"上传文件 {oss_object_name} 到 OSS 失败: {e}")
    return False
# --- 辅助函数：格式化文件大小 ---
def format_file_size(size_bytes):
    """将字节大小格式化为可读的字符串"""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.1f} {size_names[i]}"
# --- 辅助函数：格式化时间 ---
def format_file_time(timestamp):
    """将时间戳转换为两种格式的时间显示"""
    dt = datetime.fromtimestamp(timestamp)
    # 格式1: YYYY-MM-DD HH:MM:SS
    format1 = dt.strftime("%Y-%m-%d %H:%M:%S")
    # 格式2: MM:SS (如果是一天内) 或 HH:MM:SS
    if dt.date() == datetime.now().date():
        format2 = dt.strftime("%H:%M:%S")
    else:
        format2 = dt.strftime("%m-%d %H:%M")
    return format1, format2
# --- 辅助函数：检查文件是否允许上传 ---
ALLOWED_EXTENSIONS = {'mp3'}
def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
# --- 辅助函数：生成下载URL ---
def generate_download_url(filename):
    """生成文件下载URL (本地)"""
    # Flask 会自动处理 URL 编码
    return url_for('serve_uploaded_file', filename=filename)
# --- 辅助函数：获取和更新元数据 ---
def get_file_metadata(filepath):
    """获取文件的元数据"""
    metadata_path = filepath + '.meta'
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"读取元数据文件失败 {metadata_path}: {e}")
    return {}
def update_file_metadata(filepath, uploaded_to_oss):
    """更新文件的元数据"""
    metadata_path = filepath + '.meta'
    metadata = get_file_metadata(filepath)
    metadata['uploaded_to_oss'] = uploaded_to_oss
    metadata['last_updated'] = time.time()
    try:
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f)
    except Exception as e:
        logger.error(f"更新元数据文件失败 {metadata_path}: {e}")
# --- 辅助函数：清除文件列表缓存 ---
def clear_file_cache():
    """清除文件列表缓存"""
    # 这里可以使用更复杂的缓存失效策略
    # 例如，使用 Redis 或简单的文件时间戳检查
    # 当前实现中，缓存是基于时间的，每分钟失效一次
    pass # 由 @lru_cache(maxsize=128) 和 cache_key 控制
# --- 安全头和 CSP ---
def add_security_headers(response):
    """添加安全头"""
    # 内容安全策略 (CSP)
    # 为了提高安全性，移除了 'unsafe-inline'。
    # 所有内联脚本和样式已移至外部文件。
    # nonce 或 hash 是更高级的方法，这里使用了更严格的策略。
    # media-src 允许加载同源音频/视频 (关键修改)
    # connect-src 允许同源 AJAX/Fetch
    csp_policy = (
        "default-src 'none'; "
        "script-src 'self'; " # 仅允许同源脚本
        "style-src 'self'; "  # 仅允许同源样式
        "img-src 'self' ; " # 允许同源图片和 data: URLs (如默认头像)
        "font-src 'self'; "
        "connect-src 'self'; " # 仅允许同源连接 (AJAX/Fetch)
        "media-src 'self' https: ; " # 允许同源和 HTTPS 链接的媒体 (关键，支持 OSS)
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # 注意：Strict-Transport-Security 应在 HTTPS 服务器 (如 Nginx) 中设置
    return response
@app.after_request
def after_request(response):
    """在每个请求后添加安全头"""
    return add_security_headers(response)

# --- IP 封禁检查 (在所有请求前执行) ---
@app.before_request
def check_ip_ban():
    """在每个请求前检查 IP 是否被封禁或需要处理"""
    if not IP_BAN_ENABLED:
        return None # 如果未启用，直接跳过检查

    client_ip = get_real_ip()

    # 1. 加载最新的白名单、黑名单和封禁列表 (实时读取)
    whitelist_ips = load_ip_list(WHITELIST_FILE)
    blacklist_ips = load_ip_list(BLACKLIST_FILE)
    banlist_ips = load_ip_list(BANLIST_FILE)

    # 2. 白名单检查 (最高优先级)
    if client_ip in whitelist_ips:
        logger.debug(f"IP {client_ip} 在白名单中，允许访问。")
        return None # 允许访问

    # 3. 黑名单检查
    if client_ip in blacklist_ips:
        logger.warning(f"IP {client_ip} 在黑名单中，拒绝访问。")
        abort(403) # Forbidden

    # 4. 封禁列表检查
    if client_ip in banlist_ips:
        logger.warning(f"IP {client_ip} 已被封禁，拒绝访问。")
        abort(403) # Forbidden

    # 注意：404 错误的检查和封禁逻辑放在 @app.errorhandler(404) 中
    # 这里只处理白名单、黑名单和已封禁列表

    # 如果 IP 未被任何列表拦截，则允许请求继续
    return None

# --- 自动封禁 IP (通用处理函数和错误处理器) ---

def ban_ip_for_error(client_ip, error_code, request_info):
    """
    当触发特定错误时，根据配置自动封禁客户端 IP。
    
    :param client_ip: 客户端 IP 地址
    :param error_code: 触发封禁的 HTTP 错误码 (int)
    :param request_info: 相关请求信息 (str)
    :return: None
    """
    if not IP_BAN_ENABLED:
        logger.debug(f"IP 封禁功能已禁用，未封禁 IP {client_ip} (错误码: {error_code})。")
        return

    logger.info(f"IP {client_ip} 触发了 {error_code} 错误: {request_info}")

    # 1. 检查白名单 (最高优先级)
    whitelist_ips = load_ip_list(WHITELIST_FILE)
    if client_ip in whitelist_ips:
        logger.debug(f"IP {client_ip} 在白名单中，即使触发 {error_code} 也不封禁。")
        return

    # 2. 执行封禁逻辑
    try:
        # 重新加载封禁列表，以防其他进程修改
        banlist_ips = load_ip_list(BANLIST_FILE)
        
        # 避免重复添加
        if client_ip not in banlist_ips:
            banlist_ips.add(client_ip)
            save_banlist(banlist_ips)
            logger.warning(f"IP {client_ip} 因触发 {error_code} 错误而被自动封禁。")
        else:
            logger.debug(f"IP {client_ip} 触发 {error_code}，但已在封禁列表中。")
            
    except Exception as e:
        logger.error(f"尝试封禁 IP {client_ip} (因 {error_code}) 时出错: {e}")


# --- 错误处理器 ---

@app.errorhandler(400)
def handle_bad_request(error):
    """处理 400 Bad Request 错误"""
    client_ip = get_real_ip()
    request_info = f"{request.method} {request.url}"
    ban_ip_for_error(client_ip, 400, request_info)
    # 返回标准 400 响应
    # 如果有自定义 400 页面，可以使用 render_template('400.html')
    return f"Bad Request: {error.description if hasattr(error, 'description') and error.description else str(error)}", 400

@app.errorhandler(401)
def handle_unauthorized(error):
    """处理 401 Unauthorized 错误"""
    client_ip = get_real_ip()
    request_info = f"{request.method} {request.url}"
    ban_ip_for_error(client_ip, 401, request_info)
    # 返回标准 401 响应
    return "Unauthorized", 401

@app.errorhandler(403)
def handle_forbidden(error):
    """处理 403 Forbidden 错误"""
    # 注意：此处理器也会捕获由 check_ip_ban() 主动 abort(403) 的情况。
    # 在那种情况下，IP 已经被处理过了。这里的逻辑是针对应用逻辑产生的 403。
    client_ip = get_real_ip()
    request_info = f"{request.method} {request.url}"
    ban_ip_for_error(client_ip, 403, request_info)
    # 返回标准 403 响应
    return "Forbidden", 403

@app.errorhandler(404)
def handle_not_found(error):
    """处理 404 Not Found 错误"""
    client_ip = get_real_ip()
    request_info = f"{request.method} {request.url}"
    ban_ip_for_error(client_ip, 404, request_info)
    # 返回标准 404 响应
    # 如果有自定义 404 页面，可以使用 render_template('404.html')
    return "Page Not Found", 404

@app.errorhandler(413)
def handle_payload_too_large(error):
    """处理 413 Payload Too Large 错误"""
    client_ip = get_real_ip()
    request_info = f"{request.method} {request.url}"
    ban_ip_for_error(client_ip, 413, request_info)
    # 返回标准 413 响应
    return "Payload Too Large", 413

@app.errorhandler(414)
def handle_uri_too_long(error):
    """处理 414 URI Too Long 错误"""
    client_ip = get_real_ip()
    request_info = f"{request.method} {request.url}"
    ban_ip_for_error(client_ip, 414, request_info)
    # 返回标准 414 响应
    return "URI Too Long", 414

@app.errorhandler(415)
def handle_unsupported_media_type(error):
    """处理 415 Unsupported Media Type 错误"""
    client_ip = get_real_ip()
    request_info = f"{request.method} {request.url}"
    ban_ip_for_error(client_ip, 415, request_info)
    # 返回标准 415 响应
    return "Unsupported Media Type", 415

# --- (可选) 为 500 错误添加日志记录，但通常不建议因 500 封禁 IP ---
# @app.errorhandler(500)
# def handle_internal_error(error):
#     """处理 500 Internal Server Error"""
#     client_ip = get_real_ip()
#     request_info = f"{request.method} {request.url}"
#     logger.error(f"IP {client_ip} 导致 500 错误: {request_info} - Error: {error}")
#     # 注意：500 错误通常是服务器内部问题，封禁 IP 可能会误伤正常用户
#     # ban_ip_for_error(client_ip, 500, request_info) # 谨慎启用
#     return "Internal Server Error", 500


# --- 路由：主页/文件列表 ---
@app.route('/')
@login_required
def index():
    """主页，显示文件列表和上传表单"""
    # 传递 CSRF Token 给模板 (确保这行存在)
    return render_template('index.html', is_authenticated=current_user.is_authenticated,is_admin=current_user.is_admin, csrf_token=generate_csrf())
@app.route('/static/admin_config.js')
@login_required
def serve_dynamic_admin_config_js():
    """动态生成并提供 admin_config.js 文件"""
    # 生成 JavaScript 内容
    js_content = f"window.GLOBAL_IS_ADMIN = {'true' if current_user.is_admin else 'false'};"
    # 返回 JavaScript 内容，设置正确的 MIME 类型
    response = make_response(js_content)
    response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    return response
# --- 修改登录路由 ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    """登录页面"""
    if request.method == 'GET':
        # 可选：清除可能存在的旧 flash 消息，让登录页更干净
        get_flashed_messages()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT id, username, password_hash, is_admin, is_active FROM users WHERE username = ?", (username,))
        user_data = c.fetchone()
        conn.close()
        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data[2].encode('utf-8')):
            if not user_data[4]:  # is_active
                flash('账户已被禁用', 'error')
                return render_template('login.html', csrf_token=generate_csrf())
            user = User(user_data[0], user_data[1], bool(user_data[3]), bool(user_data[4]))
            login_user(user)
            log_user_action("LOGIN", f"User {username} logged in")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('用户名或密码错误', 'error')
    return render_template('login.html', csrf_token=generate_csrf())
# --- 新增：用户注册路由 ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    # 检查待审核队列
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users WHERE created_by_admin = 0 AND is_active = 0")
    pending_count = c.fetchone()[0]
    conn.close()
    if pending_count >= 5:
        flash('注册人数已达上限，请稍后再试', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('用户名和密码不能为空', 'error')
            return render_template('register.html', csrf_token=generate_csrf())
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password_hash, created_by_admin, is_active) VALUES (?, ?, ?, ?)",
                    (username, password_hash, 0, 0)) # is_active=0 表示待管理员审核
            conn.commit()
            flash('注册成功，等待管理员审核', 'success')
            log_user_action("REGISTER_REQUEST", f"User {username} requested registration")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('用户名已存在', 'error')
        finally:
            conn.close()
    return render_template('register.html', csrf_token=generate_csrf())
# --- 新增：管理员用户管理页面 ---
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # 获取所有用户
    c.execute("SELECT id, username, is_admin, is_active, created_by_admin, created_at FROM users ORDER BY created_at DESC")
    users = c.fetchall()
    # 获取待审核的注册用户
    c.execute("SELECT id, username, created_at FROM users WHERE created_by_admin = 0 AND is_active = 0")
    pending_registrations = c.fetchall()
    # 获取待审核的密码修改
    c.execute("""SELECT p.id, u.username, p.requested_at 
                 FROM pending_password_changes p 
                 JOIN users u ON p.user_id = u.id""")
    pending_password_changes = c.fetchall()
    conn.close()
    return render_template('admin_users.html', 
                         users=users, 
                         pending_registrations=pending_registrations,
                         pending_password_changes=pending_password_changes,
                         csrf_token=generate_csrf())
# --- 新增：管理员重置用户密码 ---
@app.route('/admin/reset_password/<int:user_id>', methods=['POST'], endpoint='reset_password')
@login_required
@admin_required
def reset_password(user_id):
    """管理员重置用户密码为 '123'"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # 获取用户名，用于记录日志
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    if not user_data:
        flash('用户不存在', 'error')
        conn.close()
        return redirect(url_for('admin_users'))
    username = user_data[0]
    # 生成 '123' 的密码哈希
    new_password_hash = bcrypt.hashpw('123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    # 更新数据库
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, user_id))
    conn.commit()
    conn.close()
    # 记录日志
    log_user_action("RESET_PASSWORD", f"Admin reset password for user {username}")
    flash(f'用户 {username} 的密码已重置为 "123"', 'success')
    return redirect(url_for('admin_users'))

# --- 新增：管理员批准/拒绝用户注册 ---
@app.route('/admin/approve_user/<int:user_id>', methods=['POST'], endpoint='approve_user')
@login_required
@admin_required
def approve_user(user_id):
    action = request.form.get('action') # 'approve' or 'reject'
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    if action == 'approve':
        c.execute("UPDATE users SET is_active = 1 WHERE id = ?", (user_id,))
        c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username = c.fetchone()[0]
        log_user_action("APPROVE_USER", f"Approved user {username}")
        flash('用户已激活', 'success')
    elif action == 'reject':
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        log_user_action("REJECT_USER", f"Rejected user registration {user_id}")
        flash('用户注册已拒绝', 'success')
    conn.commit()
    conn.close()
    return redirect(url_for('admin_users'))

# --- 新增：管理员创建用户 ---
@app.route('/admin/create_user', methods=['POST'], endpoint='create_user')
@login_required
@admin_required
def create_user():
    username = request.form.get('username')
    password = request.form.get('password')
    is_admin = request.form.get('is_admin') == 'on'
    if not username or not password:
        flash('用户名和密码不能为空', 'error')
        return redirect(url_for('admin_users'))
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash, is_admin, created_by_admin, is_active) VALUES (?, ?, ?, ?, ?)",
                  (username, password_hash, is_admin, 1, 1))
        conn.commit()
        log_user_action("CREATE_USER", f"Created user {username}")
        flash('用户创建成功', 'success')
    except sqlite3.IntegrityError:
        flash('用户名已存在', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin_users'))

# --- 新增：管理员删除用户 ---
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'], endpoint='delete_user')
@login_required
@admin_required
def delete_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    username = c.fetchone()[0]
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    # 同时删除该用户的所有待审核密码修改
    c.execute("DELETE FROM pending_password_changes WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    log_user_action("DELETE_USER", f"Deleted user {username}")
    flash('用户已删除', 'success')
    return redirect(url_for('admin_users'))


# --- 新增：管理员封禁/解封用户 ---
@app.route('/admin/toggle_user_status/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # 查询当前用户状态
    c.execute("SELECT username, is_active FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    if not user_data:
        flash('用户不存在', 'error')
        conn.close()
        return redirect(url_for('admin_users'))
    
    # 切换状态: 1 (活跃) -> 0 (禁用), 0 (禁用) -> 1 (活跃)
    new_status = 0 if user_data[1] else 1
    c.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
    
    # 记录操作日志
    action = "UNBAN_USER" if new_status else "BAN_USER"
    log_user_action(action, f"User {user_data[0]} status changed to {new_status}")
    
    conn.commit()
    conn.close()
    
    flash('用户状态已更新', 'success')
    return redirect(url_for('admin_users'))

# --- 新增：用户修改密码请求 ---
@app.route('/request_password_change', methods=['POST'])
@login_required
def request_password_change():
    new_password = request.form.get('new_password')
    if not new_password:
        return jsonify({'success': False, 'message': '新密码不能为空'}), 400
    new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO pending_password_changes (user_id, new_password_hash) VALUES (?, ?)",
              (current_user.id, new_password_hash))
    conn.commit()
    conn.close()
    log_user_action("REQUEST_PASSWORD_CHANGE")
    return jsonify({'success': True, 'message': '密码修改请求已提交，等待管理员审核'})

# --- 新增：管理员审核密码修改 ---
@app.route('/admin/approve_password_change/<int:change_id>', methods=['POST'])
@login_required
@admin_required
def approve_password_change(change_id):
    action = request.form.get('action') # 'approve' or 'reject'
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    if action == 'approve':
        c.execute("SELECT user_id, new_password_hash FROM pending_password_changes WHERE id = ?", (change_id,))
        change_data = c.fetchone()
        if change_data:
            c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (change_data[1], change_data[0]))
            c.execute("SELECT username FROM users WHERE id = ?", (change_data[0],))
            username = c.fetchone()[0]
            log_user_action("APPROVE_PASSWORD_CHANGE", f"Approved password change for {username}")
    # 无论批准或拒绝，都删除请求
    c.execute("DELETE FROM pending_password_changes WHERE id = ?", (change_id,))
    conn.commit()
    conn.close()
    flash('操作已完成', 'success')
    return redirect(url_for('admin_users'))

# --- 新增：管理员查看操作日志 ---
@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("""SELECT l.id, u.username, l.action, l.details, l.ip_address, l.timestamp 
                 FROM user_logs l 
                 JOIN users u ON l.user_id = u.id 
                 ORDER BY l.timestamp DESC LIMIT ? OFFSET ?""", (per_page, offset))
    logs = c.fetchall()
    c.execute("SELECT COUNT(*) FROM user_logs")
    total_logs = c.fetchone()[0]
    total_pages = (total_logs + per_page - 1) // per_page
    conn.close()
    return render_template('admin_logs.html', 
                         logs=logs, 
                         current_page=page, 
                         total_pages=total_pages,
                         csrf_token=generate_csrf())

# --- 路由：登出 ---
@app.route('/logout')
@login_required # 需要登录才能登出
def logout():
    logout_user()
    flash('您已成功登出', 'success')
    return redirect(url_for('index'))
# --- 新增：用户修改密码页面 ---
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """用户修改密码页面"""
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not old_password or not new_password or not confirm_password:
            flash('所有字段都必须填写', 'error')
            return render_template('change_password.html', csrf_token=generate_csrf())
        if new_password != confirm_password:
            flash('新密码和确认密码不一致', 'error')
            return render_template('change_password.html', csrf_token=generate_csrf())
        # 验证旧密码
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT password_hash FROM users WHERE id = ?", (current_user.id,))
        user_data = c.fetchone()
        conn.close()
        if not user_data or not bcrypt.checkpw(old_password.encode('utf-8'), user_data[0].encode('utf-8')):
            flash('旧密码错误', 'error')
            return render_template('change_password.html', csrf_token=generate_csrf())
        # 更新密码
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, current_user.id))
        conn.commit()
        conn.close()
        flash('密码修改成功！请使用新密码重新登录。', 'success')
        logout_user() # 强制用户重新登录
        return redirect(url_for('login'))
    return render_template('change_password.html', csrf_token=generate_csrf())

# --- 新增：忘记密码页面 ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """忘记密码页面"""
    if request.method == 'POST':
        username = request.form.get('username')
        if not username:
            flash('请输入您的用户名', 'error')
            return render_template('forgot_password.html', csrf_token=generate_csrf())
        # 检查用户是否存在
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT id, is_active FROM users WHERE username = ?", (username,))
        user_data = c.fetchone()
        conn.close()
        if not user_data:
            flash('用户名不存在', 'error')
            return render_template('forgot_password.html', csrf_token=generate_csrf())
        if not user_data[1]: # is_active
            flash('该账户已被禁用', 'error')
            return render_template('forgot_password.html', csrf_token=generate_csrf())
        # 记录日志，通知管理员
        log_user_action("FORGOT_PASSWORD_REQUEST", f"User {username} requested password reset")
        flash('密码重置请求已提交！管理员会将您的密码重置为 "123"，请稍后联系管理员确认。', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html', csrf_token=generate_csrf())
# 处理浏览器自动请求 favicon.ico，避免 404 错误
@app.route('/favicon.ico')
def favicon():
    """提供 favicon.ico 文件"""
    # 方法一：重定向到 static 文件夹
    # return redirect(url_for('static', filename='favicon.ico'))

    # 方法二：直接发送 static 文件夹中的文件 (推荐)
    try:
        return send_from_directory(os.path.join(app.root_path, 'static'),
                                   'favicon.ico', mimetype='image/vnd.microsoft.icon')
    except FileNotFoundError:
        # 如果文件不存在，可以返回一个空的图标或 404
        # 这里选择返回 404，但不会记录为严重错误（因为它是自动请求）
        app.logger.debug("Favicon.ico not found in static folder.")
        abort(404) # 或者返回一个空图标 (见方法 2)
# --- 路由：提供上传的文件 ---
@app.route('/uploads/<path:filename>')
def serve_uploaded_file(filename):
    """提供上传的文件（支持断点续传）"""
    try:
        # 解码 URL 中的文件名 (Flask/Werkzeug 通常会自动处理)
        # 但为了安全，最好再次检查
        decoded_filename = urllib.parse.unquote(filename)
        # 清理文件名
        safe_filename = sanitize_filename(decoded_filename)
        if safe_filename != decoded_filename:
             logger.warning(f"文件名清理导致不匹配: {decoded_filename} -> {safe_filename}")
             abort(404) # 或 400
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
        # 路径安全检查
        if not is_safe_path(app.config['UPLOAD_FOLDER'], filepath):
            logger.warning(f"不安全的文件路径请求: {filepath}")
            abort(404)
        if not os.path.exists(filepath):
            logger.warning(f"请求的文件不存在: {filepath}")
            abort(404)
        # 获取文件大小
        file_size = os.path.getsize(filepath)
        # 处理 Range 请求头以支持断点续传
        range_header = request.headers.get('Range', None)
        if range_header:
            try:
                # 解析 Range 头，例如 "bytes=500-999"
                byte1, byte2 = 0, None
                m = re.search(r'(\d+)-(\d*)', range_header)
                g = m.groups()
                if g[0]:
                    byte1 = int(g[0])
                if g[1]:
                    byte2 = int(g[1])
                length = file_size - byte1
                if byte2 is not None:
                    length = byte2 - byte1 + 1
                # 读取文件指定范围的数据
                with open(filepath, 'rb') as f:
                    f.seek(byte1)
                    data = f.read(length)
                # 构造 206 Partial Content 响应
                rv = Response(data, 206, mimetype="audio/mpeg", direct_passthrough=True)
                rv.headers.add('Content-Range', f'bytes {byte1}-{byte1 + length - 1}/{file_size}')
                rv.headers.add('Accept-Ranges', 'bytes')
                return rv
            except ValueError as e:
                logger.error(f"Range header 解析错误: {range_header}, Error: {e}")
                # 返回 416 Range Not Satisfiable
                rv = Response("Requested Range Not Satisfiable", 416)
                rv.headers.add('Content-Range', f'bytes */{file_size}')
                return rv
        # 如果没有 Range 头，返回整个文件 200 OK
        return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename, as_attachment=False)
    except FileNotFoundError:
        logger.error(f"文件未找到: {filename}")
        abort(404)
    except Exception as e:
        logger.error(f"提供文件时发生错误: {filename}, Error: {e}")
        abort(500) # 内部服务器错误
# --- API路由：获取文件列表 (核心修改：合并本地和OSS列表, 需要登录) ---
@app.route('/api/files', methods=['GET'])
@login_required # 限制访问
def api_get_files():
    """API接口：获取文件列表，支持分页和搜索 (包含存储状态，合并本地和OSS)"""
    try:
        # 1. 获取本地文件列表
        local_mp3_filenames = []
        if os.path.exists(app.config['UPLOAD_FOLDER']):
            local_mp3_filenames = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if f.endswith('.mp3')]
        # 2. 获取 OSS 文件列表 (如果启用)
        oss_object_names = set()
        if OSS_ENABLED and oss_client:
            try:
                # 列出 OSS Bucket 中的对象
                for obj in oss2.ObjectIterator(oss_client):
                    if obj.key.endswith('.mp3'):
                        oss_object_names.add(obj.key)
            except Exception as e:
                logger.error(f"获取 OSS 文件列表失败: {e}")
        # 3. 合并文件信息
        merged_file_dict = {}
        # 3a. 处理本地文件
        for filename in local_mp3_filenames:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(filepath): # 再次确认文件存在（虽然缓存了，但可能有并发删除）
                stat = os.stat(filepath)
                file_size = stat.st_size
                file_mtime = stat.st_mtime
                size_formatted = format_file_size(file_size)
                time_format1, time_format2 = format_file_time(file_mtime)
                download_url_1 = generate_download_url(filename) # 本地链接
                # 关键修改：明确初始化和设置 storage_status
                storage_status = "local_only" # 默认为仅本地
                download_url_2 = "" # 默认 OSS 链接为空
                # 如果启用了 OSS，检查同步状态
                if OSS_ENABLED and oss_client:
                    # 检查元数据 (推荐，更快)
                    try:
                        metadata = get_file_metadata(filepath)
                        if metadata.get('uploaded_to_oss', False):
                            storage_status = "synced"
                            # 生成 OSS 链接
                            if OSS_CDN_DOMAIN:
                                download_url_2 = f"{OSS_CDN_DOMAIN}/{urllib.parse.quote(filename, safe='')}"
                            else:
                                if OSS_PROVIDER == 'aliyun_oss':
                                    download_url_2 = f"https://{OSS_BUCKET_NAME}.{OSS_ENDPOINT}/{urllib.parse.quote(filename, safe='')}"
                                # ... 其他提供商 ...
                    except Exception as meta_e:
                        logger.error(f"读取元数据失败 {filepath}: {meta_e}")
                merged_file_dict[filename] = {
                    'name': filename,
                    'size': file_size,
                    'size_formatted': size_formatted,
                    'mtime': file_mtime,
                    'time_format1': time_format1,
                    'time_format2': time_format2,
                    'download_url_1': download_url_1,
                    'download_url_2': download_url_2, # 可能为空
                    'host_1': DOWNLOAD_HOST_1,
                    'port_1': DOWNLOAD_PORT_1,
                    'host_2': DOWNLOAD_HOST_2, # 前端可能需要根据实际链接动态调整
                    'port_2': DOWNLOAD_PORT_2, # 前端可能需要根据实际链接动态调整
                    'storage_status': storage_status # 确保设置
                }
        # 3b. 处理仅在 OSS 上的文件
        oss_only_names = oss_object_names - set(local_mp3_filenames) # 集合差集运算
        for obj_name in oss_only_names:
            try:
                # 尝试从 OSS 获取对象的元信息（大小、最后修改时间）
                obj_meta = oss_client.get_object_meta(obj_name)
                oss_file_size = int(obj_meta.headers.get('Content-Length', 0))
                # 注意：OSS 的 Last-Modified 时间格式可能需要转换
                # oss_last_modified_str = obj_meta.headers.get('Last-Modified', '')
                # ... (需要解析 HTTP 日期字符串为时间戳) ...
                # 这里简化处理，使用当前时间或一个默认值
                oss_mtime_timestamp = time.time() # 或者尝试解析 oss_last_modified_str
                size_formatted = format_file_size(oss_file_size)
                time_format1, time_format2 = format_file_time(oss_mtime_timestamp)
                # 本地链接为空，因为文件不存在于本地
                download_url_1 = ""
                # OSS 链接
                download_url_2 = "" # 初始化
                if OSS_CDN_DOMAIN:
                    download_url_2 = f"{OSS_CDN_DOMAIN}/{urllib.parse.quote(obj_name, safe='')}"
                else:
                    if OSS_PROVIDER == 'aliyun_oss':
                        download_url_2 = f"https://{OSS_BUCKET_NAME}.{OSS_ENDPOINT}/{urllib.parse.quote(obj_name, safe='')}"
                    # ... 其他 ...
                merged_file_dict[obj_name] = {
                    'name': obj_name,
                    'size': oss_file_size,
                    'size_formatted': size_formatted,
                    'mtime': oss_mtime_timestamp,
                    'time_format1': time_format1,
                    'time_format2': time_format2,
                    'download_url_1': download_url_1, # 空
                    'download_url_2': download_url_2, # OSS 链接
                    'host_1': DOWNLOAD_HOST_1,
                    'port_1': DOWNLOAD_PORT_1,
                    'host_2': DOWNLOAD_HOST_2, # 前端可能需要根据实际链接动态调整
                    'port_2': DOWNLOAD_PORT_2, # 前端可能需要根据实际链接动态调整
                    'storage_status': 'oss_only' # 标记为仅在 OSS
                }
            except oss2.exceptions.NoSuchKey:
                # 理论上不应该发生，因为我们刚从列表中获取
                logger.warning(f"OSS 对象 {obj_name} 在获取元数据时不存在")
            except Exception as meta_e:
                logger.error(f"获取 OSS 对象 {obj_name} 元数据失败: {meta_e}")
                # 可以选择跳过或创建一个带有错误信息的条目
        # 4. 转换为列表并排序
        file_infos = list(merged_file_dict.values())
        file_infos.sort(key=lambda x: x['mtime'], reverse=True) # 按修改时间排序
        logger.debug(f"合并后的文件列表: {[f['name'] + ' (' + f['storage_status'] + ')' for f in file_infos]}") # 添加调试日志
        return jsonify({'files': file_infos})
    except Exception as e:
        logger.error(f"获取文件列表失败: {e}")
        return jsonify({'files': [], 'error': str(e)}), 500
# --- 路由：上传文件 (同步) ---
@app.route('/upload', methods=['POST'])
@limiter.limit(UPLOAD_LIMIT) # 速率限制：从配置读取
@login_required
def upload_file():
    """同步上传文件"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': '没有选择文件'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': '没有选择文件'}), 400
        # 获取自定义文件名 (如果提供)
        custom_filename_input = request.form.get('custom_filename', '').strip()
        # 检查文件类型
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'message': '文件类型不允许，只允许MP3文件'}), 400
        # 处理文件名
        original_filename_ext = '.' + file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if not original_filename_ext:
            return jsonify({'success': False, 'message': '文件没有扩展名，或不是允许的类型。'}), 400
        if custom_filename_input:
            # 使用自定义文件名
            processed_filename_base = sanitize_filename(custom_filename_input, max_length=80)
            if not processed_filename_base:
                return jsonify({'success': False, 'message': '自定义文件名无效或被安全过滤为空，请尝试其他名称。'}), 400
            filename_base = processed_filename_base
        else:
            # 使用原始文件名（去掉扩展名）
            original_name = file.filename.rsplit('.', 1)[0]
            filename_base = sanitize_filename(original_name, max_length=80)
            if not filename_base:
                filename_base = "untitled"
        # 生成安全的完整文件名
        filename = generate_safe_filename(filename_base, original_filename_ext)
        # 使用UUID作为临时文件名防止并发写入问题
        temp_filename = str(uuid.uuid4()) + original_filename_ext
        temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
        final_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # 路径安全检查
        if not is_safe_path(app.config['UPLOAD_FOLDER'], temp_filepath) or \
           not is_safe_path(app.config['UPLOAD_FOLDER'], final_filepath):
            logger.warning(f"上传路径不安全: temp={temp_filepath}, final={final_filepath}")
            return jsonify({'success': False, 'message': '文件路径不安全'}), 400
        # 保存文件到临时位置
        file.save(temp_filepath)
        # 增强的文件类型检查
        if not check_file_type(temp_filepath):
             os.remove(temp_filepath) # 清理临时文件
             return jsonify({'success': False, 'message': '文件内容不符合 MP3 格式要求'}), 400
        # 原子性地重命名为最终文件名
        os.rename(temp_filepath, final_filepath)
        # 清除文件列表缓存
        clear_file_cache()
        # 上传到 OSS 并更新元数据
        oss_uploaded = False
        if OSS_ENABLED and oss_client:
            oss_object_name = filename
            oss_uploaded = upload_file_to_oss(final_filepath, oss_object_name)
            if oss_uploaded:
                logger.info(f"文件 {filename} 已同步上传到 OSS。")
            else:
                logger.warning(f"文件 {filename} 上传到 OSS 失败。")
        # 更新元数据文件，记录 OSS 上传状态
        update_file_metadata(final_filepath, uploaded_to_oss=oss_uploaded)
        # 获取文件信息
        stat = os.stat(final_filepath)
        file_size = stat.st_size
        size_formatted = format_file_size(file_size)
        # 生成下载链接
        download_url_1 = generate_download_url(filename)
        # 修改：download_url_2 指向 OSS
        download_url_2 = download_url_1 # 默认为本地
        if OSS_ENABLED and oss_client:
            try:
                if OSS_CDN_DOMAIN:
                    download_url_2 = f"{OSS_CDN_DOMAIN}/{urllib.parse.quote(filename, safe='')}"
                else:
                    if OSS_PROVIDER == 'aliyun_oss':
                        download_url_2 = f"https://{OSS_BUCKET_NAME}.{OSS_ENDPOINT}/{urllib.parse.quote(filename, safe='')}"
                    # ... 其他 ...
            except Exception as e:
                logger.error(f"生成 OSS 下载链接失败 ({filename}): {e}")
        logger.info(f"文件 '{filename}' 上传成功，保存至 '{final_filepath}'。直链1：{download_url_1}，直链2：{download_url_2}")
        return jsonify({'success': True,
                        'message': f'文件上传成功！',
                        'filename': filename,
                        'size': file_size,
                        'size_formatted': size_formatted,
                        'download_url_1': download_url_1,
                        'download_url_2': download_url_2,
                        'storage_status': 'synced' if oss_uploaded else 'local_only' # 可选返回状态
                       })
    except Exception as e:
        logger.error(f"文件上传失败: {e}")
        # 清理可能残留的临时文件
        if 'temp_filepath' in locals() and os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except Exception as cleanup_e:
                logger.error(f"清理临时文件失败 {temp_filepath}: {cleanup_e}")
        return jsonify({'success': False, 'message': '服务器处理文件时发生错误。'}), 500
# --- 路由：上传文件 (异步) ---
@app.route('/upload_async', methods=['POST'])
@limiter.limit(ASYNC_UPLOAD_LIMIT) # 速率限制：从配置读取
@login_required
def upload_file_async():
    """异步上传文件"""
    if not CELERY_AVAILABLE:
        return jsonify({'success': False, 'message': '服务器未配置异步任务功能'}), 500
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': '没有选择文件'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': '没有选择文件'}), 400
        # 获取自定义文件名 (如果提供)
        custom_filename_input = request.form.get('custom_filename', '').strip()
        # 检查文件类型
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'message': '文件类型不允许，只允许MP3文件'}), 400
        # 处理文件名
        original_filename_ext = '.' + file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if not original_filename_ext:
            return jsonify({'success': False, 'message': '文件没有扩展名，或不是允许的类型。'}), 400
        if custom_filename_input:
            processed_filename_base = sanitize_filename(custom_filename_input, max_length=80)
            if not processed_filename_base:
                return jsonify({'success': False, 'message': '自定义文件名无效或被安全过滤为空，请尝试其他名称。'}), 400
            filename_base = processed_filename_base
        else:
            original_name = file.filename.rsplit('.', 1)[0]
            filename_base = sanitize_filename(original_name, max_length=80)
            if not filename_base:
                filename_base = "untitled"
        # 生成安全的完整文件名
        filename = generate_safe_filename(filename_base, original_filename_ext)
        # 使用UUID作为临时文件名防止并发写入问题
        temp_filename = str(uuid.uuid4()) + original_filename_ext
        temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
        final_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # 路径安全检查
        if not is_safe_path(app.config['UPLOAD_FOLDER'], temp_filepath) or \
           not is_safe_path(app.config['UPLOAD_FOLDER'], final_filepath):
            logger.warning(f"异步上传路径不安全: temp={temp_filepath}, final={final_filepath}")
            return jsonify({'success': False, 'message': '文件路径不安全'}), 400
        # 保存文件到临时位置
        file.save(temp_filepath)
        # 提交异步任务
        task = celery_worker.async_upload_file.delay(temp_filepath, final_filepath, filename) # 传递 filename
        logger.info(f"文件 '{filename}' 已提交异步处理，任务ID: {task.id}")
        return jsonify({'success': True, 'message': '文件已提交异步处理，请稍后查看结果。', 'task_id': task.id})
    except Exception as e:
        logger.error(f"提交异步上传任务失败: {e}")
        # 清理可能残留的临时文件
        if 'temp_filepath' in locals() and os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except Exception as cleanup_e:
                logger.error(f"清理临时文件失败 {temp_filepath}: {cleanup_e}")
        return jsonify({'success': False, 'message': '提交异步任务时发生错误。'}), 500
# --- API路由：查询异步任务状态 ---
@app.route('/api/task_status/<task_id>', methods=['GET'])
@login_required
def get_task_status(task_id):
    """API接口：查询异步任务状态"""
    if not CELERY_AVAILABLE:
        return jsonify({'state': 'FAILURE', 'status': '服务器未配置异步任务功能'}), 500
    task = celery_worker.async_upload_file.AsyncResult(task_id)
    if task.state == 'PENDING':
        response = {
            'state': task.state,
            'status': '任务正在等待执行...'
        }
    elif task.state == 'PROGRESS':
        response = {
            'state': task.state,
            'status': task.info.get('status', ''),
            'result': task.info.get('result', {})
        }
    elif task.state == 'SUCCESS':
        response = {
            'state': task.state,
            'status': '任务已完成',
            'result': task.info  # 包含 filename, size, download_url_1, download_url_2
        }
    elif task.state == 'FAILURE':
        response = {
            'state': task.state,
            'status': str(task.info),  # 错误信息
        }
    else:
        response = {
            'state': task.state,
            'status': f'未知任务状态: {task.state}'
        }
    return jsonify(response)
# --- 路由：删除文件 ---
@app.route('/api/delete/<path:filename>', methods=['POST'])
@limiter.limit(DELETE_LIMIT) # 速率限制：从配置读取
@login_required
@admin_required
def delete_file(filename):
    """删除文件 (包括本地和OSS)"""
    try:
        # 解码 URL 中的文件名
        decoded_filename = urllib.parse.unquote(filename)
        # 清理文件名 (安全检查)
        safe_filename = sanitize_filename(decoded_filename)
        if safe_filename != decoded_filename:
             logger.warning(f"删除文件名清理导致不匹配: {decoded_filename} -> {safe_filename}")
             return jsonify({'success': False, 'message': '文件名无效'}), 400
        # 验证删除密码
        data = request.get_json()
        delete_password_input = data.get('delete_password', '')
        if not delete_password_input:
            return jsonify({'success': False, 'message': '请输入删除密码'}), 400
        # 使用 bcrypt 验证密码
        if not bcrypt.checkpw(delete_password_input.encode('utf-8'), DELETE_PASSWORD.encode('utf-8')):
            logger.warning(f"删除密码错误: {safe_filename}")
            return jsonify({'success': False, 'message': '删除密码错误'}), 403 # 403 Forbidden 更合适
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
        metadata_path = filepath + '.meta'
        deleted_anything = False
        error_messages = []
        # 1. 删除本地文件
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                deleted_anything = True
                logger.info(f"本地文件已删除: {filepath}")
            except Exception as e:
                error_msg = f"删除本地文件失败: {e}"
                logger.error(error_msg)
                error_messages.append(error_msg)
        # 2. 删除本地元数据文件
        if os.path.exists(metadata_path):
            try:
                os.remove(metadata_path)
                logger.info(f"本地元数据文件已删除: {metadata_path}")
            except Exception as e:
                error_msg = f"删除本地元数据文件失败: {e}"
                logger.error(error_msg)
                # error_messages.append(error_msg) # 元数据删除失败不阻止主流程
        # 3. 删除 OSS 文件 (如果启用)
        if OSS_ENABLED and oss_client:
            try:
                oss_client.delete_object(safe_filename)
                deleted_anything = True
                logger.info(f"OSS 文件已删除: {safe_filename}")
            except oss2.exceptions.NoSuchKey:
                logger.info(f"OSS 上不存在文件: {safe_filename} (可能仅在本地)")
            except Exception as e:
                error_msg = f"删除 OSS 文件失败: {e}"
                logger.error(error_msg)
                error_messages.append(error_msg)
        # 清除文件列表缓存
        clear_file_cache()
        if deleted_anything:
            if error_messages:
                message = f"文件 {safe_filename} 删除完成，但遇到以下问题: " + "; ".join(error_messages)
                logger.warning(message)
                return jsonify({'success': True, 'message': message})
            else:
                message = f"文件 {safe_filename} 已成功删除。"
                logger.info(message)
                return jsonify({'success': True, 'message': message})
        else:
            if error_messages:
                message = f"删除文件 {safe_filename} 时遇到错误: " + "; ".join(error_messages)
                logger.error(message)
                return jsonify({'success': False, 'message': message}), 500
            else:
                message = f"文件 {safe_filename} 未找到 (本地或 OSS)。"
                logger.info(message)
                return jsonify({'success': False, 'message': message})
    except Exception as e:
        logger.error(f"删除文件时发生错误: {filename}, Error: {e}")
        return jsonify({'success': False, 'message': '服务器处理删除请求时发生错误。'}), 500
def multi_thread_download(url, file_size, num_threads=4):
    """使用多线程下载文件"""
    if file_size <= 0 or num_threads <= 0:
        raise ValueError("Invalid file size or number of threads")
    # --- 确保 logger 可用 ---
    # 如果这个函数在 server.py 内部，可以直接使用 logger 或 app.logger
    # 否则需要传入 logger 实例
    local_logger = logging.getLogger(__name__) # 或者使用全局 logger
    try:
        chunk_size = file_size // num_threads
        futures = []
        expected_starts = [] # 记录预期的分块起始位置
        # 使用 ThreadPoolExecutor 管理线程
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            for i in range(num_threads):
                start = i * chunk_size
                # 确保最后一个分块包含所有剩余数据
                end = start + chunk_size - 1 if i < num_threads - 1 else file_size - 1
                expected_starts.append(start) # 记录这个分块的预期起始位置
                # 提交任务到线程池
                futures.append(executor.submit(download_chunk, url, start, end))
            # 收集结果
            chunks = {} # 键是 start (分块起始字节)，值是数据
            for future in concurrent.futures.as_completed(futures):
                chunk_id, chunk_data = future.result() # chunk_id 是 start
                if chunk_data is not None:
                    # 存储成功下载的分块
                    chunks[chunk_id] = chunk_data
                    local_logger.debug(f"分块下载成功: 起始={chunk_id}")
                else:
                    # 如果任何一个分块下载失败，则抛出异常
                    error_msg = f"分块 {chunk_id} 下载失败"
                    local_logger.error(error_msg)
                    raise Exception(error_msg)
            # --- 修正后的组合逻辑 ---
            # 1. 检查是否所有预期的分块都已下载
            missing_chunks = []
            for expected_start in expected_starts:
                if expected_start not in chunks:
                    missing_chunks.append(expected_start)
            if missing_chunks:
                error_msg = f"缺少分块，起始位置: {missing_chunks}"
                local_logger.error(error_msg)
                raise Exception(error_msg)
            # 2. 按照分块的起始位置顺序组合数据
            combined_data = BytesIO()
            sorted_starts = sorted(chunks.keys()) # 按 start 排序
            for start in sorted_starts:
                combined_data.write(chunks[start])
                local_logger.debug(f"已写入分块: 起始={start}, 大小={len(chunks[start])} bytes")
            combined_data.seek(0)
            local_logger.info("所有分块下载并组合成功。")
            # 返回组合后的字节数据
            return combined_data.getvalue()
    except Exception as e: # 捕获所有在 try 块中发生的异常
        local_logger.error(f"多线程下载失败: {e}")
        # --- 可选：降级到单线程下载 ---
        try:
            local_logger.info("尝试降级到单线程下载...")
            with urllib.request.urlopen(url, timeout=60) as response:
                if response.getcode() == 200:
                    data = response.read()
                    local_logger.info("单线程下载成功。")
                    return data
                else:
                    error_msg = f"单线程下载失败，HTTP状态码: {response.getcode()}"
                    local_logger.error(error_msg)
                    raise Exception(error_msg)
        except Exception as fallback_e:
            local_logger.error(f"单线程下载也失败了: {fallback_e}")
            # 重新抛出最初的多线程下载错误，或者可以选择抛出降级错误
            # raise fallback_e # 抛出降级错误
            raise e # 通常抛出主错误更合适
# --- 辅助函数：下载单个分块 (保持不变或根据需要微调) ---
def download_chunk(url, start, end, timeout=60):
    """下载文件的一个分块"""
    headers = {'Range': f'bytes={start}-{end}'}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.getcode() == 206: # Partial Content
                data = response.read()
                # 假设 logger 在此作用域或通过其他方式可用
                # logging.getLogger(__name__).debug(f"下载分块成功: {start}-{end}, 大小: {len(data)} bytes")
                return start, data # 返回 start 作为 chunk_id
            else:
                error_msg = f"分块下载失败，HTTP状态码: {response.getcode()} for range {start}-{end}"
                # logging.getLogger(__name__).error(error_msg)
                print(error_msg) # 临时打印，或使用 logger
                return start, None # 即使失败也返回 start
    except Exception as e: # 捕获所有异常
        error_msg = f"下载分块时发生异常 ({start}-{end}): {e}"
        # logging.getLogger(__name__).error(error_msg)
        print(error_msg) # 临时打印，或使用 logger
        return start, None # 确保在任何异常下都返回 start 和 None
@app.route('/api/download_multi/<path:filename>', methods=['GET'])
@login_required
def download_file_multi(filename):
    """多线程下载文件 (优先从 OSS, 回退到本地)"""
    try:
        # --- 1. 基础文件名校验 ---
        decoded_filename = urllib.parse.unquote(filename)
        safe_filename = sanitize_filename(decoded_filename)
        if safe_filename != decoded_filename:
            logger.warning(f"下载文件名清理导致不匹配: {decoded_filename} -> {safe_filename}")
            abort(404) # 或 400
        # --- 2. 尝试从 OSS 下载 ---
        if OSS_ENABLED and oss_client:
            try:
                oss_object_name = safe_filename
                logger.debug(f"[多线程下载] 尝试从 OSS 下载: {oss_object_name}")
                # 检查 OSS 文件是否存在并获取大小
                obj_meta = oss_client.get_object_meta(oss_object_name)
                file_size = int(obj_meta.headers.get('Content-Length', 0))
                if file_size <= 0:
                    logger.error(f"OSS 文件大小无效: {oss_object_name}")
                    # 不立即 abort，尝试回退到本地
                    raise oss2.exceptions.NoSuchKey("Invalid size") # 触发回退
                # 生成签名 URL (用于多线程下载)
                signed_url = oss_client.sign_url('GET', oss_object_name, 3600) # 1小时有效
                logger.debug(f"[多线程下载] OSS 签名 URL 生成成功")
                # 使用 multi_thread_download 从 Signed URL 下载
                # 注意：Signed URL 本身可能支持 Range 请求，multi_thread_download 内部的 Range 请求应该也能工作
                # 如果 Signed URL 不支持 Range，multi_thread_download 会降级
                file_data = multi_thread_download(signed_url, file_size, MAX_WORKERS)
                logger.info(f"[多线程下载] 从 OSS 成功下载文件: {oss_object_name}")
                # 返回文件数据
                safe_filename_for_header = sanitize_filename(decoded_filename) # 用于 Content-Disposition
                response = app.response_class(
                    file_data,
                    mimetype='audio/mpeg',
                    headers={
                        "Content-Disposition": f"attachment; filename*=UTF-8''{urllib.parse.quote(safe_filename_for_header)}"
                    }
                )
                return response
            except oss2.exceptions.NoSuchKey:
                logger.warning(f"[多线程下载] OSS 文件不存在: {oss_object_name}")
                # 继续执行，尝试回退到本地
            except Exception as e:
                logger.error(f"[多线程下载] 从 OSS 多线程下载文件失败: {oss_object_name}, Error: {e}")
                # 继续执行，尝试回退到本地
        else:
            logger.debug(f"[多线程下载] OSS 未启用，跳过 OSS 下载尝试。")
        # --- 3. 回退到本地文件系统 ---
        logger.debug(f"[多线程下载] 尝试从本地文件系统下载: {safe_filename}")
        local_filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
        if os.path.exists(local_filepath) and os.path.isfile(local_filepath):
            try:
                file_size = os.path.getsize(local_filepath)
                if file_size <= 0:
                    logger.error(f"[多线程下载] 本地文件大小无效: {local_filepath}")
                    abort(500) # 内部服务器错误
                logger.debug(f"[多线程下载] 本地文件存在，大小: {file_size} bytes")
                # --- 模拟多线程下载逻辑 (读取本地文件) ---
                # 注意：对于本地文件，真正的并发 Range 请求没有意义，因为数据就在本地磁盘上。
                # 但为了接口一致性或处理大文件，我们可以读取文件内容并返回。
                # 如果需要模拟分块读取（例如为了流式处理或内存管理），可以在这里实现。
                # 当前实现：简单地读取整个文件。
                # 方式一：直接读取整个文件 (最简单)
                # with open(local_filepath, 'rb') as f:
                #     file_data = f.read()
                # 方式二：使用类似 multi_thread_download 的分块读取逻辑 (模拟)
                # 这里定义一个本地文件的“分块读取”函数
                def read_local_chunk(filepath, start, end):
                    """模拟从本地文件读取一个分块"""
                    try:
                        with open(filepath, 'rb') as f:
                            f.seek(start)
                            # 计算实际要读取的字节数
                            bytes_to_read = end - start + 1
                            data = f.read(bytes_to_read)
                            logger.debug(f"[本地读取分块] 成功: {start}-{end}, 大小: {len(data)} bytes")
                            return start, data
                    except Exception as e:
                        logger.error(f"[本地读取分块] 失败 ({start}-{end}): {e}")
                        return start, None
                # --- 使用本地分块读取模拟多线程下载 ---
                num_threads = min(MAX_WORKERS, 4) # 使用配置的线程数，但不超过4作为示例
                if file_size < 1024 * 1024: # 如果文件小于1MB，使用单线程
                     num_threads = 1
                chunk_size = file_size // num_threads
                chunks = {}
                logger.debug(f"[本地多线程模拟] 文件大小: {file_size}, 线程数: {num_threads}, 块大小: {chunk_size}")
                # 串行读取分块 (模拟“多线程”)
                for i in range(num_threads):
                    start = i * chunk_size
                    # 确保最后一个分块包含所有剩余数据
                    end = start + chunk_size - 1 if i < num_threads - 1 else file_size - 1
                    chunk_id, chunk_data = read_local_chunk(local_filepath, start, end)
                    if chunk_data is not None:
                        chunks[chunk_id] = chunk_data
                    else:
                        raise Exception(f"[本地多线程模拟] 读取分块 {chunk_id} 失败")
                # 按顺序组合所有分块
                combined_data = BytesIO()
                sorted_starts = sorted(chunks.keys())
                for start in sorted_starts:
                    combined_data.write(chunks[start])
                    logger.debug(f"[本地多线程模拟] 已写入分块: 起始={start}")
                combined_data.seek(0)
                file_data = combined_data.getvalue()
                combined_data.close() # 关闭 BytesIO
                logger.info(f"[多线程下载] 从本地文件系统成功读取并模拟多线程处理完成: {local_filepath}")
                # --- 返回文件数据 ---
                safe_filename_for_header = sanitize_filename(decoded_filename)
                response = app.response_class(
                    file_data,
                    mimetype='audio/mpeg',
                    headers={
                        "Content-Disposition": f"attachment; filename*=UTF-8''{urllib.parse.quote(safe_filename_for_header)}"
                    }
                )
                return response
            except Exception as local_e:
                logger.error(f"[多线程下载] 从本地文件系统读取文件失败: {local_filepath}, Error: {local_e}")
                abort(500) # 内部服务器错误
        else:
            logger.warning(f"[多线程下载] 文件在本地也未找到: {local_filepath}")
            message = f"文件 {safe_filename} 未找到 (OSS 或 本地)。"
            logger.info(message)
            # 可以选择返回 404 或一个包含信息的 JSON
            # return jsonify({'success': False, 'message': message}), 404
            abort(404) # 文件未找到
    except Exception as e:
        logger.error(f"[多线程下载] 处理多线程下载请求时发生未预期错误: {filename}, Error: {e}")
        abort(500) # 内部服务器错误
# --- 启动应用 ---
if __name__ == '__main__':
    # 确保上传目录存在
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # 确保 IP 列表文件存在
    create_default_list_files()
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False) # 生产环境应关闭 debug
