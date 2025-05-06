<?php
/**
 * Функции для отображения данных анализатора логов
 * Оптимизированная версия
 */

// Функция для отображения результатов с учетом фильтров и лимита
function displayResults($data, $limit, $ipFilter, $uaFilter, $refererFilter, $statusFilter) {
    // Если результат содержит ошибку, выводим её
    if (isset($data['error'])) {
        echo '<div class="alert alert-danger">' . htmlspecialchars($data['error']) . '</div>';
        return;
    }
    
    if (empty($data)) {
        echo '<div class="alert alert-info">Загрузите файл логов или вставьте содержимое для анализа.</div>';
        return;
    }
    
    $ipStats = isset($data['ipStats']) ? $data['ipStats'] : array();
    $uaStats = isset($data['uaStats']) ? $data['uaStats'] : array();
    $ipUaStats = isset($data['ipUaStats']) ? $data['ipUaStats'] : array();
    $ipUaStatusStats = isset($data['ipUaStatusStats']) ? $data['ipUaStatusStats'] : array();
    $statusStats = isset($data['statusStats']) ? $data['statusStats'] : array();
    $totalLines = isset($data['totalLines']) ? $data['totalLines'] : 0;
    $parsedLines = isset($data['parsedLines']) ? $data['parsedLines'] : 0;
    
    // Информация о файле
    echo '<div class="alert alert-info">';
    echo '<div class="row">';
    echo '<div class="col-md-6">';
    echo '<h5>Общая статистика</h5>';
    echo 'Всего строк в файле: ' . number_format($totalLines, 0, '.', ' ') . '<br>';
    echo 'Успешно обработано: ' . number_format($parsedLines, 0, '.', ' ') . ' (' . 
          ($totalLines > 0 ? round($parsedLines / $totalLines * 100, 2) : 0) . '%)<br>';
    
    // Если есть информация о полном количестве строк в файле
    if (isset($data['total_lines_in_file']) && isset($data['processed_lines'])) {
        echo '<div class="alert alert-warning mt-2 mb-0 p-2">';
        echo '<strong>Примечание:</strong> Файл содержит ' . number_format($data['total_lines_in_file'], 0, '.', ' ') . 
              ' строк, но проанализировано только ' . number_format($data['processed_lines'], 0, '.', ' ') . 
              ' строк из-за ограничений обработки.';
        echo '</div>';
    }
    echo '</div>';
    
    echo '<div class="col-md-6">';
    echo '<h5>Уникальные значения</h5>';
    echo 'IP адресов: ' . number_format(count($ipStats), 0, '.', ' ') . '<br>';
    echo 'User Agent: ' . number_format(count($uaStats), 0, '.', ' ') . '<br>';
    echo 'Комбинаций IP + User Agent: ' . number_format(count($ipUaStats), 0, '.', ' ') . '<br>';
    echo '</div>';
    echo '</div>';
    
    // Статистика по статус-кодам
    if (!empty($statusStats)) {
        echo '<hr><h5>Статистика по кодам ответа</h5>';
        echo '<div class="row">';
        
        // Сортировка статус-кодов для более логичного отображения
        ksort($statusStats);
        
        $counter = 0;
        foreach ($statusStats as $status => $count) {
            if ($count > 0) {
                $statusClass = getStatusClass($status);
                $percentage = ($parsedLines > 0) ? round($count / $parsedLines * 100, 2) : 0;
                
                echo '<div class="col-md-2 mb-2">';
                echo '<a href="?status=' . urlencode($status) . '" class="d-block p-2 ' . $statusClass . '" style="text-decoration:none;">';
                echo '<div class="fs-5">Код ' . htmlspecialchars($status) . '</div>';
                echo '<div>' . number_format($count, 0, '.', ' ') . ' строк</div>';
                echo '<div class="small">(' . $percentage . '%)</div>';
                echo '</a>';
                echo '</div>';
                
                $counter++;
                if ($counter % 6 === 0) {
                    echo '</div><div class="row">';
                }
            }
        }
        echo '</div>';
    }
    
    // Информация о количестве сохраненных логов
    if (isset($data['logEntriesLimited']) && $data['logEntriesLimited']) {
        echo '<div class="alert alert-warning mt-2">';
        echo 'Внимание! Из-за большого размера лога сохранено только ограниченное количество записей для детального просмотра.';
        echo '</div>';
    }
    
    // Информация о форматах логов
    if (isset($data['formatStats']) && !empty(array_filter($data['formatStats']))) {
        echo '<hr><h5>Распределение по форматам логов</h5>';
        echo '<div class="row">';
        
        $formatLabels = array(
            'combined' => 'Combined формат (стандартный)',
            'main' => 'Main формат (без реферера и User Agent)',
            'custom' => 'Расширенный формат',
            'kinoprostor' => 'Кинопростор формат',
            'unknown' => 'Неизвестный формат'
        );
        
        foreach ($data['formatStats'] as $format => $count) {
            if ($count > 0) {
                $percentage = ($parsedLines > 0) ? round($count / $parsedLines * 100, 2) : 0;
                $label = isset($formatLabels[$format]) ? $formatLabels[$format] : ucfirst($format);
                
                echo '<div class="col-md-4 mb-3">';
                echo '<div class="card">';
                echo '<div class="card-body p-3">';
                echo '<h6 class="card-title">' . $label . '</h6>';
                echo '<div class="progress">';
                echo '<div class="progress-bar" role="progressbar" style="width: ' . $percentage . '%;" ';
                echo 'aria-valuenow="' . $percentage . '" aria-valuemin="0" aria-valuemax="100">' . $percentage . '%</div>';
                echo '</div>';
                echo '<p class="card-text mt-2">' . number_format($count, 0, '.', ' ') . ' строк</p>';
                echo '</div>';
                echo '</div>';
                echo '</div>';
            }
        }
        
        echo '</div>';
    }
    
    echo '</div>';
    
    // Добавляем переключатель режима отображения с иконками
    echo '<div class="form-check form-switch mb-3 d-flex align-items-center">';
    echo '<input class="form-check-input me-2" type="checkbox" id="groupByStatusSwitch">';
    echo '<label class="form-check-label" for="groupByStatusSwitch">';
    echo 'Группировать по статус-кодам';
    echo '</label>';
    echo '</div>';
    
    // Отображение статистики по IP и User Agent
    echo '<div class="card mb-4">';
    echo '<div class="card-header bg-primary text-white">';
    echo '<h5 class="card-title mb-0">Статистика по IP + User Agent</h5>';
    echo '</div>';
    echo '<div class="card-body">';
    
    echo '<div class="table-responsive" id="ipUaTable">';
    echo '<table class="table table-striped table-bordered table-hover">';
    echo '<thead class="table-light"><tr>';
    echo '<th style="width: 20%;">IP</th>'; // Добавляем фиксированную ширину для столбца IP
    echo '<th style="width: 40%;">User Agent</th>';
    echo '<th style="width: 15%;">Статус</th>';
    echo '<th style="width: 15%;">Количество</th>';
    echo '<th style="width: 10%;">Действия</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    
    $count = 0;
    foreach ($ipUaStats as $item) {
        // Применяем фильтры
        if (
            (!empty($ipFilter) && stripos($item['ip'], $ipFilter) === false) ||
            (!empty($uaFilter) && stripos($item['userAgent'], $uaFilter) === false) ||
            (!empty($refererFilter) && stripos(isset($item['referer']) ? $item['referer'] : '', $refererFilter) === false) ||
            (!empty($statusFilter) && !isset($item['status_counts'][$statusFilter])) // Проверяем наличие статус-кода в счетчиках
        ) {
            continue;
        }
        
        if ($count >= $limit) {
            break;
        }
        
        $count++;
        
        echo '<tr class="ipua-row">';
        echo '<td style="word-break: break-all; word-wrap: break-word;">' . htmlspecialchars($item['ip']) . '</td>'; // Добавляем стили для переноса IP
        echo '<td>';
        // Обрезаем слишком длинный User Agent и добавляем всплывающую подсказку
        $userAgent = htmlspecialchars($item['userAgent']);
        if (mb_strlen($userAgent) > 100) {
            echo '<span title="' . $userAgent . '">' . mb_substr($userAgent, 0, 97) . '...</span>';
        } else {
            echo $userAgent;
        }
        echo '</td>';
        echo '<td>';
        
        // Вывод статус-кодов с цветовой индикацией
        if (isset($item['status_counts']) && !empty($item['status_counts'])) {
            echo getStatusBreakdownHTML($item['status_counts']);
        } else {
            echo '<span class="text-muted">н/д</span>';
        }
        
        echo '</td>';
        echo '<td>';
        // Общее количество
        echo '<strong>' . number_format($item['count'], 0, '.', ' ') . '</strong> запросов';
        echo '</td>';
        echo '<td>';
        echo '<button type="button" class="btn btn-sm btn-primary view-logs" ';
        echo 'data-ip="' . htmlspecialchars($item['ip']) . '" ';
        echo 'data-ua="' . htmlspecialchars(addslashes($item['userAgent'])) . '">';
        echo 'Показать логи</button>';
        echo '</td>';
        echo '</tr>';
    }
    
    echo '</tbody></table></div>';
    
    // Отображение статистики по IP + User Agent + Status
    echo '<div class="table-responsive" id="ipUaStatusTable" style="display:none;">';
    echo '<table class="table table-striped table-bordered table-hover">';
    echo '<thead class="table-light"><tr>';
    echo '<th style="width: 20%;">IP</th>'; // Добавляем фиксированную ширину
    echo '<th style="width: 40%;">User Agent</th>';
    echo '<th style="width: 10%;">Статус</th>';
    echo '<th style="width: 15%;">Количество</th>';
    echo '<th style="width: 15%;">Действия</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    
    $count = 0;
    if (!empty($ipUaStatusStats)) {
        foreach ($ipUaStatusStats as $item) {
            // Применяем фильтры
            if (
                (!empty($ipFilter) && stripos($item['ip'], $ipFilter) === false) ||
                (!empty($uaFilter) && stripos($item['userAgent'], $uaFilter) === false) ||
                (!empty($refererFilter) && stripos(isset($item['referer']) ? $item['referer'] : '', $refererFilter) === false) ||
                (!empty($statusFilter) && $item['status'] != $statusFilter) // Проверяем соответствие статус-кода фильтру
            ) {
                continue;
            }
            
            if ($count >= $limit) {
                break;
            }
            
            $count++;
            
            // Определяем класс для статус-кода
            $statusClass = getStatusClass($item['status']);
            
            echo '<tr>';
            echo '<td style="word-break: break-all; word-wrap: break-word;">' . htmlspecialchars($item['ip']) . '</td>'; // Добавляем стили для переноса IP
            echo '<td>';
            // Обрезаем слишком длинный User Agent
            $userAgent = htmlspecialchars($item['userAgent']);
            if (mb_strlen($userAgent) > 100) {
                echo '<span title="' . $userAgent . '">' . mb_substr($userAgent, 0, 97) . '...</span>';
            } else {
                echo $userAgent;
            }
            echo '</td>';
            echo '<td class="' . $statusClass . '">' . $item['status'] . '</td>';
            echo '<td>' . number_format($item['count'], 0, '.', ' ') . '</td>';
            echo '<td>';
            echo '<button type="button" class="btn btn-sm btn-primary view-logs" ';
            echo 'data-ip="' . htmlspecialchars($item['ip']) . '" ';
            echo 'data-ua="' . htmlspecialchars(addslashes($item['userAgent'])) . '" ';
            echo 'data-status="' . htmlspecialchars($item['status']) . '">';
            echo 'Показать логи</button>';
            echo '</td>';
            echo '</tr>';
        }
    }
    
    echo '</tbody></table></div>';
    
    echo '</div>';
    echo '</div>';
    
    // Если не найдено результатов после фильтрации
    if ($count == 0) {
        echo '<div class="alert alert-warning">';
        echo 'Результаты не найдены с указанными фильтрами. ';
        echo '<a href="' . $_SERVER['PHP_SELF'] . '" class="alert-link">Сбросить фильтры</a>';
        echo '</div>';
    }
    
    // JavaScript для переключения между режимами отображения
    echo '<script>
    document.addEventListener("DOMContentLoaded", function() {
        const groupByStatusSwitch = document.getElementById("groupByStatusSwitch");
        const ipUaTable = document.getElementById("ipUaTable");
        const ipUaStatusTable = document.getElementById("ipUaStatusTable");
        
        // Проверяем, был ли выбран режим группировки по статус-кодам ранее
        const savedMode = localStorage.getItem("logAnalyzerGroupByStatus");
        if (savedMode === "true") {
            groupByStatusSwitch.checked = true;
            ipUaTable.style.display = "none";
            ipUaStatusTable.style.display = "block";
        }
        
        groupByStatusSwitch.addEventListener("change", function() {
            if (this.checked) {
                ipUaTable.style.display = "none";
                ipUaStatusTable.style.display = "block";
                localStorage.setItem("logAnalyzerGroupByStatus", "true");
            } else {
                ipUaTable.style.display = "block";
                ipUaStatusTable.style.display = "none";
                localStorage.setItem("logAnalyzerGroupByStatus", "false");
            }
        });
    });
    </script>';
}

// Функция для определения класса по статус-коду
function getStatusClass($status) {
    $statusClass = '';
    if (substr($status, 0, 1) === '2') {
        $statusClass = 'text-success'; // 2xx - успешные ответы
    } elseif (substr($status, 0, 1) === '3') {
        $statusClass = 'text-info'; // 3xx - перенаправления
    } elseif (substr($status, 0, 1) === '4') {
        $statusClass = 'text-warning'; // 4xx - ошибки клиента
    } elseif (substr($status, 0, 1) === '5') {
        $statusClass = 'text-danger'; // 5xx - ошибки сервера
    }
    return $statusClass;
}

// Функция для отображения разбивки по статус-кодам
function getStatusBreakdownHTML($statusCounts) {
    $html = '';
    
    if (empty($statusCounts)) {
        return $html;
    }
    
    // Сортируем статус-коды
    ksort($statusCounts);
    
    $html .= '<div class="d-flex flex-wrap gap-1">';
    foreach ($statusCounts as $status => $count) {
        $badgeClass = 'bg-secondary';
        if (substr($status, 0, 1) === '2') {
            $badgeClass = 'bg-success';
        } elseif (substr($status, 0, 1) === '3') {
            $badgeClass = 'bg-info';
        } elseif (substr($status, 0, 1) === '4') {
            $badgeClass = 'bg-warning text-dark';
        } elseif (substr($status, 0, 1) === '5') {
            $badgeClass = 'bg-danger';
        }
        
        $html .= '<a href="?status=' . urlencode($status) . '" class="badge ' . $badgeClass . '" title="Фильтр по коду ' . $status . '">' 
              . $status . ': ' . number_format($count, 0, '.', ' ') . '</a>';
    }
    $html .= '</div>';
    
    return $html;
}

// Функция для отображения ошибок
function displayErrors($errors) {
    if (empty($errors)) {
        return;
    }
    
    echo '<div class="alert alert-danger alert-dismissible fade show" role="alert">';
    
    if (count($errors) === 1) {
        echo $errors[0];
    } else {
        echo '<ul class="mb-0 ps-3">';
        foreach ($errors as $error) {
            echo '<li>' . $error . '</li>';
        }
        echo '</ul>';
    }
    
    echo '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>';
    echo '</div>';
}

// Функция для отображения сообщений об успехе
function displaySuccessMessages($messages) {
    if (empty($messages)) {
        return;
    }
    
    echo '<div class="alert alert-success alert-dismissible fade show" role="alert">';
    
    if (count($messages) === 1) {
        echo $messages[0];
    } else {
        echo '<ul class="mb-0 ps-3">';
        foreach ($messages as $message) {
            echo '<li>' . $message . '</li>';
        }
        echo '</ul>';
    }
    
    echo '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>';
    echo '</div>';
}
?>