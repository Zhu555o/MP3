# celery_worker.py
import os
import time
import logging
from logging.handlers import RotatingFileHandler
import json
import tempfile
import shutil

# --- Celery 导入 ---
from celery import Celery
from celery.signals import setup_logging

# --- 配置文件处理 ---
import configparser

# --- OSS SDK 导入 ---
try:
    import oss2
    OSS_AVAILABLE = True
except ImportError:
    OSS_AVAILABLE = False
    print("警告: OSS SDK (oss2) 未安装，Worker 中云存储功能不可用")

# --- 音频验证库 (示例) ---
# pip install mutagen
# 修复：将导入移到文件顶部
try:
    from mutagen.mp3 import MP3
    MUTAGEN_AVAILABLE = True
except ImportError:
    MUTAGEN_AVAILABLE = False
    print("提示: Mutagen 未安装，Worker 将仅使用基础文件类型检查。")

# --- 配置文件路径 ---
config_path = 'server_config.ini' # Worker 与 Server 共享配置文件

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

# --- 读取配置值 (使用新的辅助函数) ---
# 从环境变量或配置文件读取 Celery 和 OSS 配置
CELERY_BROKER_URL = get_config_value('CELERY', 'BROKER_URL', 'redis://localhost:6379/0', 'CELERY_BROKER_URL')
CELERY_RESULT_BACKEND = get_config_value('CELERY', 'RESULT_BACKEND', 'redis://localhost:6379/0', 'CELERY_RESULT_BACKEND')

OSS_ENABLED_WORKER_STR = get_config_value('OSS', 'ENABLED', 'false', 'OSS_ENABLED')
OSS_ENABLED_WORKER = OSS_ENABLED_WORKER_STR.lower() in ('true', '1', 'yes', 'on')
OSS_PROVIDER_WORKER = get_config_value('OSS', 'PROVIDER', '', 'OSS_PROVIDER')
OSS_ACCESS_KEY_ID_WORKER = os.getenv('OSS_ACCESS_KEY_ID') or get_config_value('OSS', 'ACCESS_KEY_ID', '', 'OSS_ACCESS_KEY_ID') # 优先环境变量
OSS_ACCESS_KEY_SECRET_WORKER = os.getenv('OSS_ACCESS_KEY_SECRET') or get_config_value('OSS', 'ACCESS_KEY_SECRET', '', 'OSS_ACCESS_KEY_SECRET') # 优先环境变量
OSS_BUCKET_NAME_WORKER = get_config_value('OSS', 'BUCKET_NAME', '', 'OSS_BUCKET_NAME')
OSS_ENDPOINT_WORKER = get_config_value('OSS', 'ENDPOINT', '', 'OSS_ENDPOINT')
OSS_REGION_WORKER = get_config_value('OSS', 'REGION', '', 'OSS_REGION')
OSS_CDN_DOMAIN_WORKER = get_config_value('OSS', 'CDN_DOMAIN', '', 'OSS_CDN_DOMAIN')

# --- 初始化 OSS 客户端 (Worker 版) ---
oss_client_for_worker = None
if OSS_ENABLED_WORKER and OSS_AVAILABLE:
    try:
        if OSS_PROVIDER_WORKER == 'aliyun_oss':
            auth = oss2.Auth(OSS_ACCESS_KEY_ID_WORKER, OSS_ACCESS_KEY_SECRET_WORKER)
            oss_client_for_worker = oss2.Bucket(auth, OSS_ENDPOINT_WORKER, OSS_BUCKET_NAME_WORKER)
            print("Celery Worker: 阿里云 OSS 客户端已初始化")
        # ... 其他提供商 ...
        else:
            print(f"Celery Worker: 未知的 OSS 提供商: {OSS_PROVIDER_WORKER}")
            OSS_ENABLED_WORKER = False
    except Exception as e:
        print(f"Celery Worker: 初始化 OSS 客户端失败: {e}")
        OSS_ENABLED_WORKER = False
else:
    print("Celery Worker: OSS 功能未启用或 SDK 不可用")

# --- Celery 应用配置 ---
# 从配置读取
celery_app = Celery('mp3_upload_worker', broker=CELERY_BROKER_URL, backend=CELERY_RESULT_BACKEND)

# --- 自定义日志配置 ---
def setup_task_logger_factory():
    """设置 Celery 任务日志工厂"""
    if not os.path.exists('logs'):
        os.makedirs('logs')
    handler = RotatingFileHandler('logs/celery_worker.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(processName)s:%(threadName)s:%(funcName)s(%(lineno)d) %(message)s'
    ))
    logger = logging.getLogger('celery_worker')
    logger.handlers.clear() # 清除默认处理器
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

# --- 获取 Celery 专用 logger ---
def setup_celery_logger():
    """获取配置好的 Celery logger"""
    return logging.getLogger('celery_worker')

# --- Worker 中的元数据更新函数 ---
def get_metadata_filepath(filepath):
    """获取与文件关联的元数据文件路径 (Worker 版)"""
    return filepath + '.meta'

def update_file_metadata_worker(filepath, uploaded_to_oss):
    """更新文件的元数据 (Worker 版)"""
    metadata_path = get_metadata_filepath(filepath)
    metadata = {}
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
        except Exception as e:
            print(f"[Worker] 读取元数据文件失败 {metadata_path}: {e}")

    metadata['uploaded_to_oss'] = uploaded_to_oss
    metadata['last_updated'] = time.time()

    try:
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f)
        print(f"[Worker] 元数据已更新: {metadata_path}")
    except Exception as e:
        print(f"[Worker] 更新元数据文件失败 {metadata_path}: {e}")

# --- 文件类型检查 (增强版 - Worker 版) ---
def check_file_type_worker(filepath):
    """检查文件类型是否为MP3 (增强版 - Worker 版)"""
    try:
        import filetype # 确保 Worker 环境也安装了 filetype
        # 1. 使用 filetype 库进行初步检查
        kind = filetype.guess(filepath)
        if kind is None or kind.mime != 'audio/mpeg':
             print(f"[Worker] 文件类型检查失败 (filetype): {filepath}")
             return False

        # 2. 使用 Mutagen 进行更严格的音频格式验证 (可选)
        # 修复：移除函数内部的 from mutagen.mp3 import MP3
        if MUTAGEN_AVAILABLE: # 直接使用在文件顶部导入的 MP3
            try:
                # from mutagen.mp3 import MP3 # <-- 移除这行
                audio = MP3(filepath) # <-- 直接使用 MP3
                # 如果能成功加载 MP3 对象，说明是有效的 MP3 文件
                print(f"[Worker] Mutagen 验证成功: {filepath}")
            except Exception as e:
                 print(f"[Worker] Mutagen 验证失败: {filepath}, Error: {e}")
                 return False # 如果 Mutagen 无法解析，则认为无效
        else:
             print(f"[Worker] Mutagen 未安装，跳过深度音频验证: {filepath}")

        return True
    except Exception as e:
        print(f"[Worker] 文件类型检查时发生错误: {filepath}, Error: {e}")
        return False

# --- Celery 任务定义 ---
@celery_app.task(bind=True,
                 # autoretry_for=(Exception,), # 修改：排除不应重试的永久性错误
                 autoretry_for=(ConnectionError, TimeoutError), # 只对临时性错误重试
                 retry_kwargs={'max_retries': 3, 'countdown': 5},
                 retry_backoff=True,
                 soft_time_limit=30,   # 软超时
                 time_limit=60)        # 硬超时
def async_upload_file(self, temp_filepath, final_filepath, filename): # 添加 filename 参数
    """异步处理文件上传任务"""
    start_time = time.time()
    task_id = self.request.id

    # 设置日志工厂
    setup_task_logger_factory()
    # 获取 Celery 专用 logger
    logger = setup_celery_logger()

    try:
        logger.info(f"开始处理文件: {filename}")

        # 路径安全校验 (简化版，Worker 应该信任传入的路径，但检查仍然重要)
        # 这里假设 temp_filepath 和 final_filepath 是由 server.py 生成的安全路径
        # 如果需要更严格的检查，可以复制 server.py 中的 is_safe_path 逻辑
        if not os.path.exists(temp_filepath):
             error_msg = f"临时文件不存在: {temp_filepath}"
             logger.error(error_msg)
             self.update_state(state='FAILURE', meta={'status': error_msg})
             raise FileNotFoundError(error_msg)

        # 增强的文件类型检查 (在 Worker 中)
        if not check_file_type_worker(temp_filepath):
             os.remove(temp_filepath) # 清理临时文件
             error_msg = f"文件内容不符合 MP3 格式要求: {filename}"
             logger.error(error_msg)
             self.update_state(state='FAILURE', meta={'status': error_msg})
             raise ValueError(error_msg)

        # 原子性地移动文件到最终位置
        directory = os.path.dirname(final_filepath)
        if not os.access(directory, os.W_OK):
            raise PermissionError(f"没有写入目录的权限: {directory}")
        shutil.move(temp_filepath, final_filepath)
        logger.info(f"文件已移动到最终位置: {final_filepath}")

        # 上传到 OSS 并更新元数据 (在 Worker 中)
        oss_uploaded = False
        if OSS_ENABLED_WORKER and oss_client_for_worker and OSS_AVAILABLE: # 使用 Worker 的配置和客户端
            oss_object_name = filename
            try:
                # 重新实现或调用上传逻辑 (因为 Worker 环境不同)
                # 示例 (阿里云 OSS):
                if OSS_PROVIDER_WORKER == 'aliyun_oss':
                    oss_client_for_worker.put_object_from_file(oss_object_name, final_filepath)
                    oss_uploaded = True
                    logger.info(f"[异步 Worker] 文件 {filename} 已同步上传到 OSS。")
                # ... 其他提供商 ...
                # 注意：这里需要处理 Worker 的 OSS 配置加载和客户端初始化
            except Exception as oss_e:
                logger.error(f"[异步 Worker] 上传文件 {filename} 到 OSS 失败: {oss_e}")

        # 更新元数据文件 (Worker 版)
        update_file_metadata_worker(final_filepath, uploaded_to_oss=oss_uploaded)

        # 获取文件信息
        stat = os.stat(final_filepath)
        file_size = stat.st_size
        # 假设有一个 format_file_size 函数在 Worker 中可用或复制过来
        def format_file_size(size_bytes):
            if size_bytes == 0: return "0 B"
            size_names = ["B", "KB", "MB", "GB", "TB"]
            i = 0
            while size_bytes >= 1024 and i < len(size_names) - 1:
                size_bytes /= 1024.0
                i += 1
            return f"{size_bytes:.1f} {size_names[i]}"
        size_formatted = format_file_size(file_size)

        # 生成下载链接 (Worker 中生成，供回调使用)
        # 注意：Worker 不直接处理 HTTP 请求，所以这些链接是给 server.py 用的
        download_url_1 = f"/uploads/{filename}" # 本地链接
        download_url_2 = download_url_1 # 默认为本地
        # 从环境变量获取 OSS 配置以生成链接
        if OSS_ENABLED_WORKER and oss_client_for_worker:
            try:
                import urllib.parse
                if OSS_CDN_DOMAIN_WORKER:
                    download_url_2 = f"{OSS_CDN_DOMAIN_WORKER}/{urllib.parse.quote(filename, safe='')}"
                else:
                    if OSS_PROVIDER_WORKER == 'aliyun_oss':
                        # 注意：需要从环境变量获取 BUCKET_NAME 和 ENDPOINT
                        bucket_name = os.getenv('OSS_BUCKET_NAME') or OSS_BUCKET_NAME_WORKER
                        endpoint = os.getenv('OSS_ENDPOINT') or OSS_ENDPOINT_WORKER
                        download_url_2 = f"https://{bucket_name}.{endpoint}/{urllib.parse.quote(filename, safe='')}"
                    # ... 其他 ...
            except Exception as link_e:
                logger.error(f"[异步 Worker] 生成 OSS 下载链接失败 ({filename}): {link_e}")

        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"异步任务完成: {filename}, 耗时: {duration:.2f}秒")

        # 返回成功结果，供前端轮询获取
        return {
            'message': f'文件 {filename} 异步上传成功！',
            'filename': filename,
            'size': file_size,
            'size_formatted': size_formatted,
            'download_url_1': download_url_1,
            'download_url_2': download_url_2,
            'storage_status': 'synced' if oss_uploaded else 'local_only'
        }

    except PermissionError as e:
        # PermissionError 也可能是永久性的
        error_msg = f"权限不足 (永久性错误): {str(e)}"
        logger.error(error_msg)
        self.update_state(state='FAILURE', meta={'status': error_msg})
        raise e
    except Exception as e:
        # 捕获其他所有异常 (如临时性错误)
        error_msg = f"处理失败: {str(e)}"
        logger.error(error_msg)
        # 清理临时文件
        if os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
                logger.info(f"已清理临时文件: {temp_filepath}")
            except Exception as cleanup_e:
                logger.error(f"清理临时文件失败 {temp_filepath}: {cleanup_e}")
        self.update_state(state='FAILURE', meta={'status': error_msg})
        # 这些异常会根据 autoretry_for 决定是否重试
        raise e
