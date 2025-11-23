// static/admin_config.js
// 这个文件由 Flask 在 index.html 中动态生成并注入
// 我们在这里定义全局变量
window.GLOBAL_IS_ADMIN = {{ 'true' if is_admin else 'false' }};