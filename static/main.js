// static/main.js
// 等待 DOM 加载完成
document.addEventListener('DOMContentLoaded', function () {
    // 从隐藏的 script 标签中获取配置数据
    let MAX_FILE_SIZE_MB = 100;
    let GLOBAL_CSRF_TOKEN = '';
    const configScript = document.getElementById('config-data');
    if (configScript) {
        try {
            const configData = JSON.parse(configScript.textContent);
            MAX_FILE_SIZE_MB = configData.MAX_FILE_SIZE_MB || MAX_FILE_SIZE_MB;
            GLOBAL_CSRF_TOKEN = configData.GLOBAL_CSRF_TOKEN || GLOBAL_CSRF_TOKEN;
        } catch (e) {
            console.error("解析配置数据失败:", e);
        }
    }
    const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

    // 文件列表数据
    let allFiles = [];
    let filteredFiles = [];
    let currentPage = 1;
    const itemsPerPage = 10;
    let isLoading = false;

    // --- 工具函数 ---
    function escapeHtml(text) {
        const map = { '&': '&amp;', '<': '<', '>': '>', '"': '&quot;', "'": '&#039;' };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    function showMessage(message, type = 'success') {
        const messagesDiv = document.querySelector('.messages') || document.createElement('div');
        messagesDiv.className = 'messages';
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        messageDiv.innerHTML = message; // 注意：这里假设 message 是安全的或已转义
        messagesDiv.appendChild(messageDiv);
        document.querySelector('.container').insertBefore(messagesDiv, document.querySelector('.container').firstChild);
        setTimeout(() => {
            messageDiv.remove();
            if (messagesDiv.children.length === 0) {
                messagesDiv.remove();
            }
        }, 5000);
    }

    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }


    // --- 文件列表加载与渲染 ---
    function loadFileList() {
        if (isLoading) return;
        isLoading = true;
        const searchTerm = document.getElementById('searchInput').value.trim().toLowerCase();
        fetch('/api/files')
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    throw new Error(data.error);
                }
                allFiles = data.files || [];
                const safeSearchTerm = escapeHtml(searchTerm);
                filteredFiles = allFiles.filter(file =>
                    escapeHtml(file.name.toLowerCase()).includes(safeSearchTerm) ||
                    escapeHtml(file.size_formatted.toLowerCase()).includes(safeSearchTerm)
                );
                currentPage = 1;
                renderFileList();
                isLoading = false;
            })
            .catch(error => {
                console.error('加载文件列表失败:', error);
                showMessage('加载文件列表失败: ' + escapeHtml(error.message), 'error');
                isLoading = false;
            });
    }

    function renderFileList() {
        const totalPages = Math.ceil(filteredFiles.length / itemsPerPage);
        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = Math.min(startIndex + itemsPerPage, filteredFiles.length);
        const pageFiles = filteredFiles.slice(startIndex, endIndex);

        const fileList = document.getElementById('fileList');
        if (pageFiles.length === 0) {
            fileList.innerHTML = '<p>还没有上传任何 MP3 文件。</p>';
            renderPagination(0);
            return;
        }

        let html = '<ul>';
        pageFiles.forEach((file, index) => {
            const globalIndex = startIndex + index;
            let statusHtml = '';
            let primaryDownloadUrl = file.download_url_1;
            let syncedLinksHtml = '';

            if (file.storage_status === 'synced') {
                statusHtml = ' <span class="status-synced">(已同步)</span>';
                primaryDownloadUrl = file.download_url_2;
                syncedLinksHtml = `<div class="synced-links">` +
                                  `<a href="${escapeHtml(file.download_url_1)}" target="_blank" class="download-link">本地链接</a>` +
                                  `<a href="${escapeHtml(file.download_url_2)}" target="_blank" class="download-link">OSS链接</a>` +
                                  `</div>`;
            } else if (file.storage_status === 'local_only') {
                statusHtml = ' <span class="status-local-only">(仅本地)</span>';
            } else if (file.storage_status === 'oss_only') {
                statusHtml = ' <span class="status-oss-only">(仅OSS)</span>';
                primaryDownloadUrl = file.download_url_2;
                syncedLinksHtml = `<div class="synced-links">` +
                                  `<a href="${escapeHtml(file.download_url_2)}" target="_blank" class="download-link">OSS链接</a>` +
                                  `</div>`;
            }

            // --- 修复：移除按钮禁用逻辑，对所有状态启用 ---
            // let multiDownloadBtnClass = 'action-btn multi-download-btn';
            // let multiDownloadBtnDisabled = '';
            // if (file.storage_status === 'local_only') {
            //     multiDownloadBtnClass += ' disabled'; // 使用 CSS 禁用样式
            //     multiDownloadBtnDisabled = 'disabled'; // 使用 HTML disabled 属性
            // }

            html += `<li data-index="${globalIndex}">
                        <div class="file-info-container">
                            <div class="file-main-info">
                                <strong>${escapeHtml(file.name)}</strong>${statusHtml}
                            </div>
                            <div class="file-meta-info">
                                <span class="file-size">${escapeHtml(file.size_formatted)}</span>
                                <span class="file-time">${escapeHtml(file.time_format1)}</span>
                            </div>
                            ${syncedLinksHtml}
                        </div>
                        <div class="file-actions">
                            <button class="action-btn play-btn" data-url="${escapeHtml(primaryDownloadUrl)}" data-name="${escapeHtml(file.name)}">播放</button>
                            <button class="action-btn download-btn" data-url="${escapeHtml(primaryDownloadUrl)}" data-name="${escapeHtml(file.name)}">下载</button>
                            <!-- 修复：移除禁用相关属性，添加 data-url 和 data-status -->
                            <button class="action-btn multi-download-btn" data-url-oss="${escapeHtml(file.download_url_2 || '')}" data-url-local="${escapeHtml(file.download_url_1 || '')}" data-name="${escapeHtml(file.name)}" data-status="${file.storage_status}">多线程下载</button>
                            <form class="delete-form delete-form-inline" data-filename="${escapeHtml(file.name)}" >
                                <input type="password" name="delete_password" placeholder="删除密码" required class="delete-password-input">
                                <button type="submit" class="action-btn delete-btn">删除</button>
                            </form>
                        </div>
                     </li>`;
        });
        html += '</ul>';
        fileList.innerHTML = html;

        setTimeout(() => {
            document.querySelectorAll('#fileList li').forEach(li => li.classList.add('visible'));
        }, 10);

        renderPagination(totalPages);
        bindPlayEvents();
        bindDownloadEvents();
        bindMultiDownloadEvents(); // 重新绑定事件
        bindDeleteEvents();
    }

    function renderPagination(totalPages) {
        const pagination = document.getElementById('pagination');
        if (totalPages <= 1) {
            pagination.innerHTML = '';
            return;
        }
        let html = '';
        // 添加上一页按钮
        html += `<button id="prevPageButton" ${currentPage === 1 ? 'disabled' : ''}>上一页</button>`;
        const delta = 2;
        for (let i = Math.max(1, currentPage - delta); i <= Math.min(totalPages, currentPage + delta); i++) {
            // 为每个页码按钮添加 data-page 属性
            html += `<button class="page-button ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
        }
        // 添加下一页按钮
        html += `<button id="nextPageButton" ${currentPage === totalPages ? 'disabled' : ''}>下一页</button>`;
        pagination.innerHTML = html;

        // 绑定分页按钮事件
        document.getElementById('prevPageButton')?.addEventListener('click', () => {
            if (currentPage > 1) changePage(currentPage - 1);
        });
        document.getElementById('nextPageButton')?.addEventListener('click', () => {
            if (currentPage < totalPages) changePage(currentPage + 1);
        });
        document.querySelectorAll('.page-button').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const page = parseInt(e.target.getAttribute('data-page'));
                if (!isNaN(page)) changePage(page);
            });
        });
    }

    function changePage(page) {
        const totalPages = Math.ceil(filteredFiles.length / itemsPerPage);
        if (page >= 1 && page <= totalPages) {
            currentPage = page;
            renderFileList();
        }
    }
    // 使 changePage 在全局可访问，以便分页按钮调用 (虽然现在是通过事件监听器)
    window.changePage = changePage;

    // --- 上传相关 ---
    function updateUploadProgress(percent, filename = '') {
        const progressBarFill = document.getElementById('progressBarFill');
        const uploadMessage = document.getElementById('uploadMessage');
        if (progressBarFill && uploadMessage) {
            progressBarFill.style.width = percent + '%';
            progressBarFill.textContent = Math.round(percent) + '%';
            if (filename) {
                uploadMessage.textContent = `正在上传 ${escapeHtml(filename)}...`;
            }
        }
    }

    function handleMultiThreadUpload(files) {
        const progressBarContainer = document.getElementById('progressContainer');
        const uploadCount = document.getElementById('uploadCount');
        progressBarContainer.style.display = 'block';
        updateUploadProgress(0);
        uploadCount.textContent = `0/${files.length}`;

        let completed = 0;
        const results = [];

        function uploadNext() {
            if (completed >= files.length) {
                progressBarContainer.style.display = 'none';
                let successCount = 0;
                let failCount = 0;
                results.forEach(r => {
                    if (r.success) successCount++;
                    else failCount++;
                });
                if (failCount === 0) {
                    showMessage(`多线程上传完成，共 ${successCount} 个文件。`, 'success');
                } else {
                    showMessage(`多线程上传完成，成功 ${successCount} 个，失败 ${failCount} 个。`, 'error');
                }
                loadFileList();
                return;
            }

            const file = files[completed];
            const formData = new FormData();
            formData.append('file', file);
            const customFilename = document.getElementById('customFilename').value.trim();
            if (customFilename) {
                formData.append('custom_filename', `${customFilename}_${completed + 1}`);
            }

            const xhr = new XMLHttpRequest();
            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    updateUploadProgress(percent, file.name);
                }
            });

            xhr.onload = function() {
                if (xhr.status >= 200 && xhr.status < 300) {
                    results.push({filename: escapeHtml(file.name), success: true});
                } else {
                    results.push({filename: escapeHtml(file.name), success: false, error: '上传失败'});
                }
                completed++;
                uploadCount.textContent = `${completed}/${files.length}`;
                uploadNext();
            };

            xhr.onerror = function() {
                results.push({filename: escapeHtml(file.name), success: false, error: '网络错误'});
                completed++;
                uploadCount.textContent = `${completed}/${files.length}`;
                uploadNext();
            };

            xhr.open('POST', '/upload', true);
            xhr.setRequestHeader('X-CSRFToken', GLOBAL_CSRF_TOKEN);
            xhr.send(formData);
        }

        uploadNext();
    }

    function handleAsyncUpload(files) {
        if (files.length !== 1) {
            showMessage('异步上传目前只支持单个文件。', 'error');
            return;
        }
        const file = files[0];
        const formData = new FormData();
        formData.append('file', file);
        const customFilename = document.getElementById('customFilename').value.trim();
        if (customFilename) {
            formData.append('custom_filename', customFilename);
        }

        const progressBarContainer = document.getElementById('progressContainer');
        const uploadMessage = document.getElementById('uploadMessage');
        progressBarContainer.style.display = 'block';
        updateUploadProgress(0);
        uploadMessage.textContent = '正在提交异步任务...';

        const xhr = new XMLHttpRequest();
        xhr.upload.addEventListener('progress', function(e) {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                updateUploadProgress(percent, file.name);
            }
        });

        xhr.onload = function() {
            progressBarContainer.style.display = 'none';
            if (xhr.status === 200) {
                const response = JSON.parse(xhr.responseText);
                if (response.success && response.task_id) {
                    showMessage(`文件已提交异步处理，任务ID: ${escapeHtml(response.task_id)}，请稍后查看结果。`, 'success');
                    pollTaskStatus(response.task_id);
                } else {
                    showMessage('上传失败：服务器处理文件时发生错误。', 'error');
                }
            } else {
                let errorMsg = '上传失败';
                try {
                    const errorResponse = JSON.parse(xhr.responseText);
                    errorMsg = errorResponse.message || errorMsg;
                } catch (e) {}
                showMessage('上传失败：' + escapeHtml(errorMsg), 'error');
            }
        };

        xhr.onerror = function() {
            progressBarContainer.style.display = 'none';
            showMessage('网络错误，文件上传失败。请检查网络连接。', 'error');
        };

        xhr.open('POST', '/upload_async', true);
        xhr.setRequestHeader('X-CSRFToken', GLOBAL_CSRF_TOKEN);
        xhr.send(formData);
    }

    function pollTaskStatus(taskId) {
        const pollInterval = setInterval(() => {
            fetch(`/api/task_status/${encodeURIComponent(taskId)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.state === 'SUCCESS') {
                        clearInterval(pollInterval);
                        showMessage(`异步任务完成：${escapeHtml(data.result.message)}`, 'success');
                        loadFileList();
                    } else if (data.state === 'FAILURE') {
                        clearInterval(pollInterval);
                        showMessage(`异步任务失败：${escapeHtml(data.status)}`, 'error');
                    } else {
                        // console.log(`任务状态: ${escapeHtml(data.state)} - ${escapeHtml(data.status)}`);
                    }
                })
                .catch(error => {
                    clearInterval(pollInterval);
                    console.error('查询任务状态失败:', error);
                    showMessage('查询异步任务状态失败：' + escapeHtml(error.message), 'error');
                });
        }, 2000);
    }

    // --- 事件绑定 ---
    document.getElementById('uploadForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        const fileInput = document.getElementById('fileInput');
        const files = fileInput.files;
        if (files.length === 0) {
            showMessage('请选择至少一个文件。', 'error');
            return;
        }

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
            const allowedExtensions = ['.mp3'];
            if (!allowedExtensions.includes(fileExtension)) {
                showMessage(`文件 ${escapeHtml(file.name)} 不是允许的MP3文件。`, 'error');
                return;
            }
            if (file.size > MAX_FILE_SIZE_BYTES) {
                showMessage(`文件 ${escapeHtml(file.name)} 大小超过限制 (${MAX_FILE_SIZE_MB}MB)。`, 'error');
                return;
            }
        }

        const uploadType = document.querySelector('input[name="uploadType"]:checked').value;
        if (uploadType === 'multi') {
            handleMultiThreadUpload(files);
        } else if (uploadType === 'async') {
            handleAsyncUpload(files);
        } else {
            if (files.length !== 1) {
                showMessage('同步上传目前只支持单个文件。', 'error');
                return;
            }
            const file = files[0];
            const formData = new FormData();
            formData.append('file', file);
            const customFilename = document.getElementById('customFilename').value.trim();
            if (customFilename) {
                formData.append('custom_filename', customFilename);
            }

            const progressBarContainer = document.getElementById('progressContainer');
            const uploadMessage = document.getElementById('uploadMessage');
            progressBarContainer.style.display = 'block';
            updateUploadProgress(0);
            uploadMessage.textContent = '正在上传...';

            const xhr = new XMLHttpRequest();
            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    updateUploadProgress(percent, file.name);
                }
            });

            xhr.onload = function() {
                progressBarContainer.style.display = 'none';
                if (xhr.status === 200) {
                    const response = JSON.parse(xhr.responseText);
                    if (response.success) {
                        showMessage('文件上传成功！', 'success');
                        loadFileList();
                    } else {
                        showMessage('上传失败：服务器处理文件时发生错误。', 'error');
                    }
                } else {
                    let errorMsg = '上传失败';
                    try {
                        const errorResponse = JSON.parse(xhr.responseText);
                        errorMsg = errorResponse.message || errorMsg;
                    } catch (e) {}
                    showMessage('上传失败：' + escapeHtml(errorMsg), 'error');
                }
                fileInput.value = ''; // 清空文件输入框
            };

            xhr.onerror = function() {
                progressBarContainer.style.display = 'none';
                showMessage('网络错误，文件上传失败。请检查网络连接。', 'error');
            };

            xhr.open('POST', '/upload', true);
            xhr.setRequestHeader('X-CSRFToken', GLOBAL_CSRF_TOKEN);
            xhr.send(formData);
        }
    });

    function bindPlayEvents() {
        document.querySelectorAll('.play-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const audioUrl = this.getAttribute('data-url');
                const fileName = this.getAttribute('data-name');
                const audioPlayer = document.getElementById('audioPlayer');
                const playerSection = document.querySelector('.audio-player-section');

                if (audioUrl) {
                    audioPlayer.src = audioUrl;
                    audioPlayer.load();
                    audioPlayer.play().then(() => {
                        playerSection.scrollIntoView({ behavior: 'smooth' });
                        showMessage(`正在播放: ${escapeHtml(fileName)}`, 'success');
                    }).catch(error => {
                        console.error('播放音频失败:', error);
                        showMessage(`播放失败: ${escapeHtml(error.message)}`, 'error');
                    });
                } else {
                    showMessage('无法播放：找不到有效的音频链接。', 'error');
                }
            });
        });
    }

    function bindDownloadEvents() {
        document.querySelectorAll('.download-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const fileUrl = this.getAttribute('data-url');
                const fileName = this.getAttribute('data-name');
                if (fileUrl) {
                    showMessage(`正在下载 ${escapeHtml(fileName)}...`, 'success');
                    const link = document.createElement('a');
                    link.href = fileUrl;
                    link.download = fileName;
                    link.style.display = 'none';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                } else {
                    showMessage('无法下载：找不到有效的下载链接。', 'error');
                }
            });
        });
    }

    // --- 修复：更新后的 bindMultiDownloadEvents 函数 (根据状态选择下载源) ---
    function bindMultiDownloadEvents() {
        // 为所有 .multi-download-btn 元素绑定点击事件监听器
        // 注意：这里使用事件委托或确保每次只绑定一次可能更好，但当前逻辑是每次 renderFileList 后调用
        document.querySelectorAll('.multi-download-btn').forEach(btn => {
            // 移除可能已存在的旧监听器（防止重复绑定）
            btn.removeEventListener('click', handleMultiDownloadClick);
            // 绑定新的处理函数
            btn.addEventListener('click', handleMultiDownloadClick);
        });
    }

    // 定义处理多线程下载点击的函数
    function handleMultiDownloadClick(event) {
        // 阻止默认行为（如果有的话）
        event.preventDefault();

        const button = this; // 'this' 指向被点击的按钮
        const fileName = button.getAttribute('data-name');
        const storageStatus = button.getAttribute('data-status');
        const ossUrl = button.getAttribute('data-url-oss');
        const localUrl = button.getAttribute('data-url-local');

        if (!fileName || !storageStatus) {
            showMessage('文件信息不完整，无法下载。', 'error');
            return;
        }

        let downloadUrl = null;
        let downloadSource = '';
        let isMultiThread = false; // 标记是否使用多线程下载

        // --- 根据 storage_status 决定下载 URL、来源和下载方式 ---
        if (storageStatus === 'synced') {
            // synced: 优先使用 OSS 链接进行多线程下载
            downloadUrl = ossUrl;
            downloadSource = 'OSS (优先)';
            isMultiThread = true;
        } else if (storageStatus === 'oss_only') {
            // oss_only: 使用 OSS 链接进行多线程下载
            downloadUrl = ossUrl;
            downloadSource = 'OSS';
            isMultiThread = true;
        } else if (storageStatus === 'local_only') {
            // local_only: 回退到本地链接 (普通下载)
            downloadUrl = localUrl;
            downloadSource = '本地';
            isMultiThread = false; // 本地文件使用普通下载
        }

        if (!downloadUrl) {
            showMessage(`无法获取 ${storageStatus} 文件的下载链接。`, 'error');
            return;
        }

        // --- 执行下载 ---
        if (isMultiThread) {
            // 对于 synced 和 oss_only，调用多线程下载 API
            showMessage(`正在从 ${downloadSource} 多线程下载 ${escapeHtml(fileName)}...`, 'success');
            const downloadApiUrl = `/api/download_multi/${encodeURIComponent(fileName)}`;
            // 注意：window.open 可能被浏览器拦截。
            // 更好的方式是使用 fetch + Blob + a标签下载，但这需要后端API支持返回文件数据。
            window.open(downloadApiUrl, '_blank');
        } else {
            // 对于 local_only，执行普通下载
            showMessage(`正在从 ${downloadSource} 下载 ${escapeHtml(fileName)}...`, 'success');
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = fileName; // 尝试触发下载而非浏览器内打开
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    }


    function bindDeleteEvents() {
        document.querySelectorAll('.delete-form').forEach(form => {
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                const filename = this.getAttribute('data-filename');
                const password = this.querySelector('input[name="delete_password"]').value;
                if (!password) {
                    alert('请输入删除密码');
                    return;
                }
                if (!confirm(`确定要删除文件 ${escapeHtml(filename)} 吗？此操作不可撤销！`)) {
                    return;
                }
                fetch(`/api/delete/${encodeURIComponent(filename)}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': GLOBAL_CSRF_TOKEN
                    },
                    body: JSON.stringify({ delete_password: password })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showMessage(escapeHtml(data.message), 'success');
                        loadFileList();
                    } else {
                        showMessage(escapeHtml(data.message), 'error');
                    }
                })
                .catch(error => {
                    showMessage('删除失败：' + escapeHtml(error.message), 'error');
                });
            });
        });
    }

    // 绑定搜索按钮和输入框事件
    document.getElementById('searchButton')?.addEventListener('click', loadFileList);
    let searchTimeout;
    document.getElementById('searchInput')?.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            loadFileList();
        }, 300);
    });

    // 初始加载文件列表
    loadFileList();
});