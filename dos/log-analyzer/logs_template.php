<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Анализатор логов NGINX - инструмент для анализа и визуализации логов веб-сервера">
    <title>Анализатор логов NGINX</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
    <style>
        body {
            padding: 20px;
            background-color: #f8f9fa;
        }
        .filters {
            margin-bottom: 20px;
        }
        .nav-tabs {
            margin-bottom: 0;
        }
        .tab-content {
            padding: 15px;
            border: 1px solid #dee2e6;
            border-top: none;
            border-radius: 0 0 5px 5px;
            background-color: #fff;
        }
        #logsModal .modal-dialog {
            max-width: 90%;
        }
        #logsModal .modal-body {
            max-height: 70vh;
            overflow-y: auto;
        }
        .logs-pagination {
            margin-top: 15px;
        }
        .log-entry {
            padding: 10px;
            border-bottom: 1px solid #eee;
            word-wrap: break-word;
            background-color: rgba(0,0,0,0.01);
            border-radius: 4px;
            margin-bottom: 8px;
        }
        .log-entry:hover {
            background-color: rgba(0,0,0,0.03);
        }
        .loading-overlay {
            display: none;
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(255, 255, 255, 0.8);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .relative-position {
            position: relative;
        }
        /* Улучшенные стили для card и кнопок */
        .card {
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border: none;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .card-header {
            border-radius: 8px 8px 0 0 !important;
            font-weight: 500;
        }
        .btn-primary {
            background-color: #0d6efd;
            border-color: #0d6efd;
        }
        .btn-primary:hover {
            background-color: #0b5ed7;
            border-color: #0a58ca;
        }
        /* Анимации и эффекты */
        .animate-fade-in {
            animation: fadeIn 0.5s ease-in-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        /* Улучшения для фильтров */
        .filter-badge {
            display: inline-block;
            padding: 0.35em 0.65em;
            font-size: 0.75em;
            font-weight: 700;
            line-height: 1;
            text-align: center;
            white-space: nowrap;
            vertical-align: baseline;
            border-radius: 0.25rem;
            color: #fff;
            background-color: #6c757d;
            margin-right: 5px;
        }
        .filter-badge .close {
            margin-left: 5px;
            cursor: pointer;
        }
        /* Кнопка наверх */
        #backToTop {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 99;
            display: none;
            width: 40px;
            height: 40px;
            text-align: center;
            line-height: 40px;
            background: #0d6efd;
            color: white;
            cursor: pointer;
            border-radius: 50%;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }
        #backToTop:hover {
            background: #0b5ed7;
        }
        /* Улучшения для мобильных устройств */
        @media (max-width: 767.98px) {
            .table-responsive {
                font-size: 0.85rem;
            }
            .card-body {
                padding: 1rem 0.5rem;
            }
        }
        
        /* Добавляем стили для переноса длинных IP-адресов */
        table td {
            word-wrap: break-word;
            word-break: break-word;
            max-width: 300px; /* Ограничиваем максимальную ширину ячеек */
        }
        
        /* Стиль для IPv6 адресов */
        .ipua-row td:first-child {
            word-break: break-all;
            overflow-wrap: break-word;
            white-space: normal !important;
        }
        
        /* Также обеспечиваем перенос IP в модальном окне */
        .log-entry div strong + span, 
        .log-entry div strong + a {
            word-break: break-all;
            word-wrap: break-word;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="mb-4 border-bottom pb-3">
            <div class="d-flex justify-content-between align-items-center">
                <h1>Анализатор логов NGINX</h1>
                <?php if ($hasData): ?>
                <div>
                    <a href="?clear=1" class="btn btn-outline-danger btn-sm" title="Очистить все данные и фильтры">
                        Очистить
                    </a>
                </div>
                <?php endif; ?>
            </div>
        </header>
        
        <?php
        // Отображаем сообщения об ошибках и успехе
        if (function_exists('displayErrors')) {
            displayErrors($errorMessages);
        } else if (!empty($errorMessages)) {
            echo '<div class="alert alert-danger">' . implode('<br>', $errorMessages) . '</div>';
        }
        
        if (function_exists('displaySuccessMessages')) {
            displaySuccessMessages($successMessages);
        } else if (!empty($successMessages)) {
            echo '<div class="alert alert-success">' . implode('<br>', $successMessages) . '</div>';
        }
        ?>
        
        <?php if (!empty($logSource)): ?>
        <div class="alert alert-success">
            <strong>Источник данных:</strong> <?php echo $logSource; ?>
            <form action="" method="post" class="mt-2">
                <input type="hidden" name="clear_data" value="1">
                <button type="submit" class="btn btn-sm btn-warning">
                    Очистить данные
                </button>
            </form>
        </div>
        <?php endif; ?>
        
        <?php if (!$hasData): ?>
        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5 class="card-title mb-0">Загрузить файл логов</h5>
            </div>
            <div class="card-body">
                <ul class="nav nav-tabs" id="uploadTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="file-tab" data-bs-toggle="tab" data-bs-target="#file-content" 
                            type="button" role="tab" aria-controls="file-content" aria-selected="true">
                            Загрузить файл
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="text-tab" data-bs-toggle="tab" data-bs-target="#text-content" 
                            type="button" role="tab" aria-controls="text-content" aria-selected="false">
                            Вставить текст
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="path-tab" data-bs-toggle="tab" data-bs-target="#path-content" 
                            type="button" role="tab" aria-controls="path-content" aria-selected="false">
                            Указать путь к файлу
                        </button>
                    </li>
                </ul>
                <div class="tab-content" id="uploadTabsContent">
                    <div class="tab-pane fade show active" id="file-content" role="tabpanel" aria-labelledby="file-tab">
                        <form action="" method="post" enctype="multipart/form-data" class="py-3">
                            <div class="mb-3">
                                <label for="log_file" class="form-label">Выберите файл с логами NGINX:</label>
                                <input type="file" class="form-control" id="log_file" name="log_file" required>
                                <div class="form-text">
                                    Поддерживаются текстовые файлы логов NGINX. Максимальный размер: 
                                    <?php echo number_format($maxFileUploadSize / (1024*1024), 2); ?> МБ.
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary">
                                Загрузить и проанализировать
                            </button>
                            
                            <!-- Отображаем состояние загрузки файла, если произошла ошибка -->
                            <?php if (isset($_FILES['log_file']) && $_FILES['log_file']['error'] != UPLOAD_ERR_OK && $_FILES['log_file']['error'] != UPLOAD_ERR_NO_FILE): ?>
                            <div class="alert alert-danger mt-3">
                                <?php 
                                $uploadErrors = array(
                                    UPLOAD_ERR_INI_SIZE => 'Размер файла превышает upload_max_filesize в php.ini',
                                    UPLOAD_ERR_FORM_SIZE => 'Размер файла превышает MAX_FILE_SIZE в HTML-форме',
                                    UPLOAD_ERR_PARTIAL => 'Файл был загружен только частично',
                                    UPLOAD_ERR_NO_TMP_DIR => 'Отсутствует временная директория',
                                    UPLOAD_ERR_CANT_WRITE => 'Не удалось записать файл на диск',
                                    UPLOAD_ERR_EXTENSION => 'Загрузка файла остановлена расширением PHP'
                                );
                                $errorCode = $_FILES['log_file']['error'];
                                echo 'Ошибка загрузки файла: ' . (isset($uploadErrors[$errorCode]) ? $uploadErrors[$errorCode] : 'Неизвестная ошибка');
                                ?>
                            </div>
                            <?php endif; ?>
                        </form>
                    </div>
                    <div class="tab-pane fade" id="text-content" role="tabpanel" aria-labelledby="text-tab">
                        <form action="" method="post" class="py-3">
                            <div class="mb-3">
                                <label for="log_content" class="form-label">Вставьте содержимое лог-файла NGINX:</label>
                                <textarea class="form-control" id="log_content" name="log_content" rows="10" required></textarea>
                                <div class="form-text">
                                    Вставьте строки логов NGINX в формате combined, main, custom или kinoprostor.
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary">
                                Проанализировать
                            </button>
                        </form>
                    </div>
                    <div class="tab-pane fade" id="path-content" role="tabpanel" aria-labelledby="path-tab">
                        <form action="" method="post" class="py-3">
                            <div class="mb-3">
                                <label for="log_path" class="form-label">Укажите путь к лог-файлу на сервере:</label>
                                <div class="input-group">
                                    <input type="text" class="form-control" id="log_path" name="log_path" 
                                           placeholder="/var/log/nginx/access.log" required>
                                </div>
                                <div class="form-text">
                                    Скрипт попытается прочитать файл напрямую с сервера. Укажите полный путь к файлу логов.
                                    Файл должен быть доступен для чтения PHP-процессу.
                                </div>
                            </div>
                            <div class="mb-3">
                                <label for="max_lines" class="form-label">Максимальное количество строк для анализа:</label>
                                <input type="number" class="form-control" id="max_lines" name="max_lines" 
                                       value="50000" min="1000" max="1000000">
                                <div class="form-text">
                                    Для очень больших файлов рекомендуется ограничить количество анализируемых строк.
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary">
                                Проанализировать
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>
        
        <?php if ($hasData): ?>
        <!-- Форма фильтров -->
        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5 class="card-title mb-0">Фильтры</h5>
            </div>
            <div class="card-body">
                <form action="" method="get" class="row g-3">
                    <div class="col-md-3">
                        <label for="ip" class="form-label">IP адрес:</label>
                        <div class="input-group">
                            <input type="text" class="form-control" id="ip" name="ip" 
                                value="<?php echo htmlspecialchars($ipFilter); ?>"
                                placeholder="Фильтр по IP">
                        </div>
                    </div>
                    <div class="col-md-3">
                        <label for="ua" class="form-label">User Agent:</label>
                        <div class="input-group">
                            <input type="text" class="form-control" id="ua" name="ua" 
                                value="<?php echo htmlspecialchars($uaFilter); ?>"
                                placeholder="Фильтр по User Agent">
                        </div>
                    </div>
                    <div class="col-md-3">
                        <label for="referer" class="form-label">Referer:</label>
                        <div class="input-group">
                            <input type="text" class="form-control" id="referer" name="referer" 
                                value="<?php echo htmlspecialchars($refererFilter); ?>"
                                placeholder="Фильтр по Referer">
                        </div>
                    </div>
                    <div class="col-md-3">
                        <label for="status" class="form-label">Код ответа:</label>
                        <div class="input-group">
                            <input type="text" class="form-control" id="status" name="status" 
                                value="<?php echo htmlspecialchars($statusFilter); ?>"
                                placeholder="Например: 200, 404, 500">
                        </div>
                    </div>
                    
                    <div class="col-md-12 mt-3">
                        <div class="row align-items-end">
                            <div class="col-md-2">
                                <label for="limit" class="form-label">Лимит результатов:</label>
                                <select class="form-select" id="limit" name="limit">
                                    <?php foreach([50, 100, 200, 500, 1000] as $limitValue): ?>
                                    <option value="<?php echo $limitValue; ?>" <?php echo $limit == $limitValue ? 'selected' : ''; ?>>
                                        <?php echo $limitValue; ?> записей
                                    </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-10 d-flex justify-content-end gap-2">
                                <?php if (!empty($ipFilter) || !empty($uaFilter) || !empty($refererFilter) || !empty($statusFilter)): ?>
                                <a href="<?php echo $_SERVER['PHP_SELF']; ?>" class="btn btn-outline-secondary">
                                    Сбросить фильтры
                                </a>
                                <?php endif; ?>
                                <button type="submit" class="btn btn-primary">
                                    Применить фильтры
                                </button>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Результаты -->
        <div class="card">
            <div class="card-header bg-primary text-white">
                <h5 class="card-title mb-0">Результаты анализа</h5>
            </div>
            <div class="card-body">
                <?php displayResults($logData, $limit, $ipFilter, $uaFilter, $refererFilter, $statusFilter); ?>
            </div>
        </div>
        <?php endif; ?>
        
        <!-- Модальное окно для отображения логов -->
        <div class="modal fade" id="logsModal" tabindex="-1" aria-labelledby="logsModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-xl">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="logsModalLabel">
                            Записи логов
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body relative-position">
                        <div class="loading-overlay" id="logsLoading">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">Загрузка...</span>
                            </div>
                        </div>
                        
                        <div id="logsList"></div>
                        <nav aria-label="Навигация по логам" class="logs-pagination">
                            <ul class="pagination justify-content-center" id="logsPagination"></ul>
                        </nav>
                    </div>
                    <div class="modal-footer">
                        <span class="text-muted me-auto" id="logsStatusInfo"></span>
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            Закрыть
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <footer class="mt-5 pt-4 text-center text-muted border-top">
            <div class="container">
                <div class="row">
                    <div class="col-md-6 offset-md-3">
                        <p><strong>Анализатор логов NGINX</strong></p>
                        <p>Инструмент для анализа и визуализации логов веб-сервера NGINX<br>
                        Совместим с PHP 5.6-8.3</p>
                        <p>&copy; <?php echo date('Y'); ?></p>
                    </div>
                </div>
            </div>
        </footer>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Модальное окно
        const logsModal = document.getElementById('logsModal');
        const logsModalTitle = document.getElementById('logsModalLabel');
        const logsList = document.getElementById('logsList');
        const logsPagination = document.getElementById('logsPagination');
        const logsLoading = document.getElementById('logsLoading');
        const logsStatusInfo = document.getElementById('logsStatusInfo');
        
        // Текущие параметры фильтрации
        let currentFilters = {
            ip: '',
            ua: '',
            status: '',
            referer: '',
            page: 1,
            per_page: 50
        };
        
        // Обработчик кнопок просмотра логов
        document.querySelectorAll('.view-logs').forEach(button => {
            button.addEventListener('click', function() {
                const ip = this.getAttribute('data-ip');
                const ua = this.getAttribute('data-ua');
                const status = this.getAttribute('data-status');
                
                // Устанавливаем заголовок модального окна
                let modalTitle = `Логи для IP: ${ip}`;
                if (ua) {
                    modalTitle += ` | User Agent: ${ua.substring(0, 50)}${ua.length > 50 ? '...' : ''}`;
                }
                if (status) {
                    modalTitle += ` | Статус: ${status}`;
                }
                logsModalTitle.textContent = modalTitle;
                
                // Устанавливаем текущие фильтры
                currentFilters.ip = ip;
                currentFilters.ua = ua;
                currentFilters.status = status || '';
                currentFilters.page = 1;
                
                // Открываем модальное окно
                const modal = new bootstrap.Modal(logsModal);
                modal.show();
                
                // Загружаем логи
                loadLogs();
            });
        });
        
        // Функция загрузки логов
        function loadLogs() {
            // Показываем индикатор загрузки
            logsLoading.style.display = 'flex';
            
            // Очищаем текущие логи
            logsList.innerHTML = '';
            logsPagination.innerHTML = '';
            
            // Формируем URL для запроса
            const url = `${window.location.pathname}?action=get_logs&ip=${encodeURIComponent(currentFilters.ip)}&ua=${encodeURIComponent(currentFilters.ua)}&status=${encodeURIComponent(currentFilters.status)}&referer=${encodeURIComponent(currentFilters.referer || '')}&page=${currentFilters.page}&per_page=${currentFilters.per_page}`;
            
            // Выполняем AJAX-запрос
            fetch(url)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Отображаем логи
                        displayLogs(data.logs);
                        
                        // Отображаем пагинацию
                        displayPagination(data.pagination);
                        
                        // Обновляем информацию о статусе
                        updateStatusInfo(data.pagination);
                    } else {
                        logsList.innerHTML = `<div class="alert alert-danger">${data.error || 'Ошибка при загрузке логов'}</div>`;
                    }
                })
                .catch(error => {
                    logsList.innerHTML = `<div class="alert alert-danger">Ошибка при выполнении запроса: ${error.message}</div>`;
                })
                .finally(() => {
                    logsLoading.style.display = 'none';
                });
        }
		
        // Обновление информации о статусе логов
        function updateStatusInfo(pagination) {
            if (logsStatusInfo && pagination) {
                let info = '';
                
                // Добавляем информацию о фильтрах
                const filters = [];
                if (currentFilters.ip) filters.push(`IP: ${currentFilters.ip}`);
                if (currentFilters.ua) filters.push(`UA: ${currentFilters.ua.substring(0, 30)}${currentFilters.ua.length > 30 ? '...' : ''}`);
                if (currentFilters.status) filters.push(`Статус: ${currentFilters.status}`);
                
                if (filters.length > 0) {
                    info = `Фильтры: ${filters.join(' | ')} | `;
                }
                
                // Добавляем информацию о пагинации
                info += `Показано ${(pagination.current - 1) * pagination.per_page + 1}-${Math.min(pagination.current * pagination.per_page, pagination.total_logs)} из ${pagination.total_logs} записей`;
                
                logsStatusInfo.textContent = info;
            }
        }
        
        // Функция отображения логов
        function displayLogs(logs) {
            if (logs.length === 0) {
                logsList.innerHTML = '<div class="alert alert-info">Логи не найдены для указанных параметров.</div>';
                return;
            }
            
            let html = '';
            logs.forEach(log => {
                // Определяем класс для статус-кода
                let statusClass = '';
                if (log.status) {
                    if (log.status.startsWith('2')) {
                        statusClass = 'text-success'; // 2xx - успешные ответы
                    } else if (log.status.startsWith('3')) {
                        statusClass = 'text-info'; // 3xx - перенаправления
                    } else if (log.status.startsWith('4')) {
                        statusClass = 'text-warning'; // 4xx - ошибки клиента
                    } else if (log.status.startsWith('5')) {
                        statusClass = 'text-danger'; // 5xx - ошибки сервера
                    }
                }
                
                html += `<div class="log-entry">
                    <div style="word-break: break-all;"><strong>IP:</strong> ${log.ip} ${log.remoteUser !== '-' ? '| <strong>Пользователь:</strong> ' + log.remoteUser : ''}</div>
                    <div><strong>Дата/время:</strong> ${log.datetime}</div>
                    <div><strong>Метод:</strong> ${log.method} | <strong>URL:</strong> ${log.url} | <strong>Протокол:</strong> ${log.protocol}</div>
                    <div><strong>Статус:</strong> <span class="${statusClass}">${log.status}</span> | <strong>Размер ответа:</strong> ${log.size} байт</div>
                    <div style="word-break: break-all;"><strong>Реферер:</strong> ${log.referer}</div>
                    <div style="word-break: break-all;"><strong>User Agent:</strong> ${log.userAgent}</div>
                    ${log.extraInfo ? '<div style="word-break: break-all;"><strong>Дополнительная информация:</strong> ' + log.extraInfo + '</div>' : ''}
                    <div><small class="text-secondary">Формат лога: ${log.format}</small></div>
                </div>`;
            });
            
            logsList.innerHTML = html;
            
            // Добавляем обработчики для статус-кодов, чтобы можно было фильтровать по клику
            logsList.querySelectorAll('.log-entry span[class^="text-"]').forEach(statusElement => {
                statusElement.style.cursor = 'pointer';
                statusElement.title = 'Нажмите для фильтрации по этому статус-коду';
                statusElement.addEventListener('click', function() {
                    currentFilters.status = this.textContent;
                    currentFilters.page = 1;
                    loadLogs();
                });
            });
        }
        
        // Функция отображения пагинации
        function displayPagination(pagination) {
            const currentPage = pagination.current;
            const totalPages = pagination.total_pages;
            
            if (totalPages <= 1) {
                return;
            }
            
            let html = '';
            
            // Кнопка "Предыдущая"
            html += `<li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${currentPage - 1}" aria-label="Предыдущая">
                    <span aria-hidden="true">&laquo;</span>
                </a>
            </li>`;
            
            // Определяем диапазон страниц для отображения
            let startPage = Math.max(1, currentPage - 2);
            let endPage = Math.min(totalPages, startPage + 4);
            
            if (endPage - startPage < 4) {
                startPage = Math.max(1, endPage - 4);
            }
            
            // Первая страница, если не попадает в диапазон
            if (startPage > 1) {
                html += `<li class="page-item"><a class="page-link" href="#" data-page="1">1</a></li>`;
                if (startPage > 2) {
                    html += `<li class="page-item disabled"><a class="page-link" href="#">...</a></li>`;
                }
            }
            
            // Страницы в диапазоне
            for (let i = startPage; i <= endPage; i++) {
                html += `<li class="page-item ${i === currentPage ? 'active' : ''}">
                    <a class="page-link" href="#" data-page="${i}">${i}</a>
                </li>`;
            }
            
            // Последняя страница, если не попадает в диапазон
            if (endPage < totalPages) {
                if (endPage < totalPages - 1) {
                    html += `<li class="page-item disabled"><a class="page-link" href="#">...</a></li>`;
                }
                html += `<li class="page-item"><a class="page-link" href="#" data-page="${totalPages}">${totalPages}</a></li>`;
            }
            
            // Кнопка "Следующая"
            html += `<li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${currentPage + 1}" aria-label="Следующая">
                    <span aria-hidden="true">&raquo;</span>
                </a>
            </li>`;
            
            logsPagination.innerHTML = html;
            
            // Обработчики событий для кнопок пагинации
            logsPagination.querySelectorAll('.page-link').forEach(link => {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    const page = parseInt(this.getAttribute('data-page'));
                    if (isNaN(page) || page < 1) {
                        return;
                    }
                    
                    currentFilters.page = page;
                    loadLogs();
                });
            });
        }
    });
    </script>
</body>
</html>