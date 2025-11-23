// static/admin.js
document.addEventListener('DOMContentLoaded', function() {
    // 为“删除用户”表单添加确认
    document.querySelectorAll('.delete-user-form').forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!confirm('确定要永久删除此用户吗？')) {
                e.preventDefault(); // 阻止表单提交
            }
        });
    });
    // 为“重置密码”表单添加确认
    document.querySelectorAll('.reset-password-form').forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!confirm('确定要将此用户的密码重置为 "123" 吗？')) {
                e.preventDefault(); // 阻止表单提交
            }
        });
    });
});