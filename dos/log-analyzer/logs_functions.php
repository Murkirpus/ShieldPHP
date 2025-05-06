<?php
/**
 * Файл с функциями для анализатора логов NGINX
 * Оптимизированная версия
 */

// Функция для чтения файла напрямую с сервера
function readLogFileFromServer($filePath, $maxLines = 50000) {
	error_log("Начало readLogFileFromServer, путь: " . $filePath . ", максимум строк: " . $maxLines);
    // Валидация входных данных
    $filePath = htmlspecialchars($filePath);
    
    // Проверка ограничений open_basedir
    $openBasedir = ini_get('open_basedir');
    if ($openBasedir) {
        $allowed_paths = explode(':', $openBasedir);
        $allowed = false;
        
        foreach ($allowed_paths as $path) {
            if (strpos($filePath, $path) === 0) {
                $allowed = true;
                break;
            }
        }
        
        if (!$allowed) {
        error_log("Ограничение open_basedir не позволяет доступ к файлу: " . $filePath);
        return array(
            'error' => 'Ограничение open_basedir не позволяет доступ к файлу: ' . htmlspecialchars($filePath) . 
                       '<br>Разрешены только пути: ' . htmlspecialchars($openBasedir) . 
                       '<br>Рекомендуем использовать путь в одной из разрешенных директорий.'
        );
    } else {
        error_log("Проверка open_basedir пройдена для файла: " . $filePath);
    }
    }
    
    // Проверяем существование файла и права на чтение
    if (!file_exists($filePath)) {
        return array('error' => 'Файл логов не найден: ' . htmlspecialchars($filePath));
    }
    
    if (!is_readable($filePath)) {
        return array('error' => 'Нет прав на чтение файла: ' . htmlspecialchars($filePath));
    }
    
    // Получаем размер файла
    $fileSize = filesize($filePath);
    if ($fileSize === false) {
        return array('error' => 'Не удалось определить размер файла: ' . htmlspecialchars($filePath));
    }
    
    // Вызываем потоковую обработку файла
    return processLogFile($filePath, $maxLines);
}

// Новая функция для потоковой обработки файла
function processLogFile($filePath, $maxLines = 50000, $isUploadedFile = false) {
    $handle = @fopen($filePath, 'r');
    if (!$handle) {
        return array('error' => 'Не удалось открыть файл для чтения: ' . htmlspecialchars($filePath));
    }
    
    // Инициализируем массивы для статистики
    $ipStats = array();
    $uaStats = array();
    $ipUaStats = array();
    $ipUaStatusStats = array();
    $statusStats = array();
    $formatStats = array(
        'combined' => 0,
        'main' => 0,
        'custom' => 0,
        'kinoprostor' => 0,
        'unknown' => 0
    );
    
    // Массив с обработанными записями логов, ограниченный по размеру
    $parsedLogs = array();
    $maxLogEntries = 10000;
    $logEntriesCounter = 0;
    
    // Счетчики строк
    $totalLines = 0;
    $parsedLines = 0;
    
    // Паттерны для разбора строк логов nginx
    $patterns = getLogPatterns();
    
    // Читаем файл построчно для экономии памяти
    while (($line = fgets($handle)) !== false && $totalLines < $maxLines) {
        $totalLines++;
        
        // Удаляем лишние пробелы и переносы строк
        $line = trim($line);
        
        // Пропускаем пустые строки
        if (empty($line)) {
            continue;
        }
        
        // Анализируем строку лога
        $logEntry = parseLogLine($line, $patterns, $formatStats);
        
        if ($logEntry !== false) {
            $parsedLines++;
            
            // Собираем статистику
            collectStatistics(
                $logEntry,
                $ipStats,
                $uaStats,
                $ipUaStats,
                $ipUaStatusStats,
                $statusStats
            );
            
            // Сохраняем детальные данные лога с ограничением количества
            if ($logEntriesCounter < $maxLogEntries) {
                $parsedLogs[] = $logEntry;
                $logEntriesCounter++;
            }
        }
        
        // Периодически освобождаем память
        if ($totalLines % 1000 === 0) {
            gc_collect_cycles();
        }
    }
    
    // Получаем общее количество строк в файле (если это возможно)
    $totalLinesInFile = 0;
    if (!$isUploadedFile) {
        // Подсчитываем общее количество строк только для файлов на сервере
        rewind($handle);
        $totalLinesInFile = count_file_lines($handle);
    }
    
    fclose($handle);
    
    // Сортируем результаты по убыванию количества запросов
    arsort($ipStats);
    arsort($uaStats);
    arsort($statusStats);
    
    // Сортировка массива IP+UA
    uasort($ipUaStats, function($a, $b) {
        return $b['count'] - $a['count'];
    });
    
    // Сортировка массива IP+UA+Status
    uasort($ipUaStatusStats, function($a, $b) {
        return $b['count'] - $a['count'];
    });
    
    // Формируем результат
    $result = array(
        'ipStats' => $ipStats,
        'uaStats' => $uaStats,
        'ipUaStats' => $ipUaStats,
        'ipUaStatusStats' => $ipUaStatusStats,
        'statusStats' => $statusStats,
        'parsedLogs' => $parsedLogs,
        'totalLines' => $totalLines,
        'parsedLines' => $parsedLines,
        'formatStats' => $formatStats,
        'logEntriesLimited' => ($logEntriesCounter >= $maxLogEntries)
    );
    
    // Если мы прочитали не весь файл или обработали только часть строк
    if ($totalLinesInFile > 0 && $totalLinesInFile > $totalLines) {
        $result['warning'] = "Файл очень большой (всего строк: {$totalLinesInFile}). " .
                           "Проанализированы только первые {$totalLines} строк.";
        $result['total_lines_in_file'] = $totalLinesInFile;
        $result['processed_lines'] = $totalLines;
    }
    
    return $result;
}

// Функция подсчета строк в файле (эффективный способ)
function count_file_lines($handle) {
    $lineCount = 0;
    $pos = ftell($handle);
    rewind($handle);
    
    // Для больших файлов используем другой метод подсчета
    $fileSize = fstat($handle)['size'];
    if ($fileSize > 50 * 1024 * 1024) { // Если файл больше 50MB
        // Для очень больших файлов оцениваем количество строк по выборке
        $sampleSize = 1024 * 1024; // 1MB
        $data = fread($handle, $sampleSize);
        $lines = substr_count($data, "\n");
        $lineCount = (int)($fileSize / $sampleSize * $lines);
    } else {
        // Для файлов среднего размера считаем точно
        while(!feof($handle)) {
            $line = fgets($handle);
            $lineCount++;
        }
    }
    
    // Возвращаем указатель на исходную позицию
    fseek($handle, $pos);
    return $lineCount;
}

// Функция для получения шаблонов разбора логов
function getLogPatterns() {
    return array(
        // 1. Стандартный формат combined
        'combined' => '/^(\S+) - (\S+) \[(.*?)\] "(\S+) (.*?) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"$/',
        
        // 2. Формат main (без реферера и User Agent)
        'main' => '/^(\S+) - (\S+) \[(.*?)\] "(\S+) (.*?) (\S+)" (\d+) (\d+)$/',
        
        // 3. Расширенный формат (custom) с дополнительными полями
        'custom' => '/^(\S+) - (\S+) \[(.*?)\] "(\S+) (.*?) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)" (.*)$/',
        
        // 4. Формат kinoprostor
        'kinoprostor' => '/^(\S+) - - \[(.*?)\].* "(\S+) (.*?) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)".*$/'
    );
}

// Функция для разбора одной строки лога
function parseLogLine($line, $patterns, &$formatStats) {
    // Проверяем каждый формат
    foreach ($patterns as $formatName => $pattern) {
        $matches = array();
        if (preg_match($pattern, $line, $matches)) {
            $formatStats[$formatName]++;
            
            // Инициализируем переменные с дефолтными значениями
            $ip = $matches[1];
            $remoteUser = isset($matches[2]) ? $matches[2] : '-';
            $datetime = isset($matches[3]) ? $matches[3] : '';
            $method = isset($matches[4]) ? $matches[4] : '';
            $url = isset($matches[5]) ? $matches[5] : '';
            $protocol = isset($matches[6]) ? $matches[6] : '';
            $statusCode = isset($matches[7]) ? $matches[7] : '';
            $responseSize = isset($matches[8]) ? $matches[8] : '0';
            $referer = isset($matches[9]) ? $matches[9] : '-';
            $userAgent = isset($matches[10]) ? $matches[10] : '-';
            $extraInfo = isset($matches[11]) ? $matches[11] : '';
            
            // Специальная обработка для формата kinoprostor
            if ($formatName === 'kinoprostor') {
                $datetime = $matches[2];
                $method = $matches[3];
                $url = $matches[4];
                $protocol = $matches[5];
                $statusCode = $matches[6];
                $responseSize = $matches[7];
                $referer = $matches[8];
                $userAgent = $matches[9];
            }
            
            // Если в формате main нет User Agent, устанавливаем дефолтное значение
            if ($formatName === 'main') {
                $referer = '-';
                $userAgent = 'Unknown';
            }
            
            return array(
                'ip' => $ip,
                'remoteUser' => $remoteUser,
                'datetime' => $datetime,
                'method' => $method,
                'url' => $url,
                'protocol' => $protocol,
                'status' => $statusCode,
                'size' => $responseSize,
                'referer' => $referer,
                'userAgent' => $userAgent,
                'extraInfo' => $extraInfo,
                'format' => $formatName,
                'raw' => $line
            );
        }
    }
    
    $formatStats['unknown']++;
    return false;
}

// Функция для сбора статистики по логам
function collectStatistics($logEntry, &$ipStats, &$uaStats, &$ipUaStats, &$ipUaStatusStats, &$statusStats) {
    $ip = $logEntry['ip'];
    $userAgent = $logEntry['userAgent'];
    $statusCode = $logEntry['status'];
    $referer = $logEntry['referer'];
    
    // Группировка по IP
    if (!isset($ipStats[$ip])) {
        $ipStats[$ip] = 0;
    }
    $ipStats[$ip]++;
    
    // Группировка по статус-коду
    if (!isset($statusStats[$statusCode])) {
        $statusStats[$statusCode] = 0;
    }
    $statusStats[$statusCode]++;
    
    // Группировка по User Agent, только если он есть
    if ($userAgent !== '-' && $userAgent !== 'Unknown') {
        if (!isset($uaStats[$userAgent])) {
            $uaStats[$userAgent] = 0;
        }
        $uaStats[$userAgent]++;
        
        // Группировка по IP и User Agent
        $key = $ip . ' - ' . $userAgent;
        if (!isset($ipUaStats[$key])) {
            $ipUaStats[$key] = array(
                'ip' => $ip,
                'userAgent' => $userAgent,
                'referer' => $referer,
                'count' => 0,
                'status_counts' => array()
            );
        }
        $ipUaStats[$key]['count']++;
        
        // Группировка по статус-кодам для каждой комбинации IP+UA
        if (!isset($ipUaStats[$key]['status_counts'][$statusCode])) {
            $ipUaStats[$key]['status_counts'][$statusCode] = 0;
        }
        $ipUaStats[$key]['status_counts'][$statusCode]++;
        
        // Добавляем детальную группировку по IP+UA+Status
        $statusKey = $key . ' - ' . $statusCode;
        if (!isset($ipUaStatusStats[$statusKey])) {
            $ipUaStatusStats[$statusKey] = array(
                'ip' => $ip,
                'userAgent' => $userAgent,
                'referer' => $referer,
                'status' => $statusCode,
                'count' => 0
            );
        }
        $ipUaStatusStats[$statusKey]['count']++;
    }
}

// Функция для сохранения загруженного файла с проверками безопасности
function saveUploadedFile($uploadedFile) {
    // Директория для временных файлов
    $uploadDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR;
    
    // Генерируем безопасное имя файла
    $filename = 'log_' . md5(uniqid() . time()) . '.txt';
    $targetPath = $uploadDir . $filename;
    
    // Проверка типа файла (разрешаем только текстовые файлы)
    $allowedTypes = array('text/plain', 'text/csv', 'application/octet-stream');
    if (!in_array($uploadedFile['type'], $allowedTypes) && !empty($uploadedFile['type'])) {
        // Дополнительно проверяем расширение
        $extension = pathinfo($uploadedFile['name'], PATHINFO_EXTENSION);
        $allowedExtensions = array('log', 'txt', 'csv');
        if (!in_array(strtolower($extension), $allowedExtensions)) {
            error_log("Недопустимый тип файла: {$uploadedFile['type']}, расширение: {$extension}");
            return false;
        }
    }
    
    // Проверяем, можем ли мы писать в директорию
    if (!is_writable($uploadDir)) {
        error_log("Директория недоступна для записи: $uploadDir");
        return false;
    }
    
    // Перемещаем загруженный файл
    if (move_uploaded_file($uploadedFile['tmp_name'], $targetPath)) {
        error_log("Файл успешно загружен: $targetPath");
        
        // Проверка на наличие вредоносного кода в файле (простая проверка)
        $firstBytes = file_get_contents($targetPath, false, null, 0, 256);
        if (preg_match('/<\?php|<script|<%|eval\(/', $firstBytes)) {
            unlink($targetPath);
            error_log("Обнаружен потенциально опасный контент в файле");
            return false;
        }
        
        return $targetPath;
    } else {
        error_log("Ошибка при перемещении загруженного файла: " . 
                 "from={$uploadedFile['tmp_name']}, to={$targetPath}, " .
                 "size={$uploadedFile['size']}, error={$uploadedFile['error']}");
        return false;
    }
}

// Функция для обработки загруженного файла
function processUploadedFile($tempFilePath) {
    return processLogFile($tempFilePath, 50000, true);
}

// Функция для парсинга текстового содержимого лога
function parseLogContent($logContent) {
    // Создаем временный файл
    $tempFile = tempnam(sys_get_temp_dir(), 'log_');
    file_put_contents($tempFile, $logContent);
    
    // Обрабатываем как файл
    $result = processLogFile($tempFile, 50000, true);
    
    // Удаляем временный файл
    @unlink($tempFile);
    
    return $result;
}

// Обработка AJAX запросов
// Обработка AJAX запросов
function handleAjaxRequest() {
    // Отключаем вывод ошибок, чтобы не испортить JSON
    ini_set('display_errors', 0);
    
    // Запускаем сессию
    if (!isset($_SESSION)) {
        session_start();
    }
    
    $response = array(
        'success' => false,
        'logs' => array(),
        'error' => ''
    );
    
    // Начинаем буферизацию вывода, чтобы перехватить любые ошибки PHP
    ob_start();
    
    // Проверяем наличие данных
    if (!isset($_SESSION['parsed_logs']) || empty($_SESSION['parsed_logs'])) {
        $response['error'] = 'Данные логов не найдены';
        // Очищаем вывод буфера
        ob_end_clean();
        // Устанавливаем правильные заголовки
        header('Content-Type: application/json');
        echo json_encode($response);
        return;
    }
    
    try {
        // Получаем параметры фильтрации
        $ip = isset($_GET['ip']) ? htmlspecialchars($_GET['ip']) : '';
        $ua = isset($_GET['ua']) ? htmlspecialchars($_GET['ua']) : '';
        $referer = isset($_GET['referer']) ? htmlspecialchars($_GET['referer']) : '';
        $status = isset($_GET['status']) ? htmlspecialchars($_GET['status']) : '';
        
        // Проверяем, что значения page и per_page являются числами
        $page = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
        $perPage = isset($_GET['per_page']) && is_numeric($_GET['per_page']) ? (int)$_GET['per_page'] : 50;
        
        if ($page < 1) $page = 1;
        if ($perPage < 10) $perPage = 10;
        if ($perPage > 200) $perPage = 200;
        
        $offset = ($page - 1) * $perPage;
        
        // Фильтруем логи
        $filteredLogs = array();
        foreach ($_SESSION['parsed_logs'] as $log) {
            $ipMatch = empty($ip) || stripos($log['ip'], $ip) !== false;
            $uaMatch = empty($ua) || stripos($log['userAgent'], $ua) !== false;
            $refererMatch = empty($referer) || stripos(isset($log['referer']) ? $log['referer'] : '', $referer) !== false;
            $statusMatch = empty($status) || $log['status'] == $status;
            
            if ($ipMatch && $uaMatch && $refererMatch && $statusMatch) {
                $filteredLogs[] = $log;
            }
        }
        
        // Пагинация
        $totalLogs = count($filteredLogs);
        $totalPages = ceil($totalLogs / $perPage);
        
        $logs = array_slice($filteredLogs, $offset, $perPage);
        
        $response = array(
            'success' => true,
            'logs' => $logs,
            'pagination' => array(
                'current' => $page,
                'total_pages' => $totalPages,
                'total_logs' => $totalLogs,
                'per_page' => $perPage
            )
        );
    } catch (Exception $e) {
        $response['error'] = 'Ошибка обработки: ' . $e->getMessage();
    }
    
    // Очищаем вывод буфера
    ob_end_clean();
    
    // Установка правильных заголовков для JSON
    header('Content-Type: application/json');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    
    echo json_encode($response);
    exit;
}

// Генерация CSRF-токена
function generateCSRFToken() {
    if (!isset($_SESSION)) {
        session_start();
    }
    
    if (!isset($_SESSION['csrf_token'])) {
        // Совместимость с PHP 5.6
        $bytes = '';
        for ($i = 0; $i < 32; $i++) {
            $bytes .= chr(mt_rand(0, 255));
        }
        $_SESSION['csrf_token'] = bin2hex($bytes);
    }
    return $_SESSION['csrf_token'];
}

// Проверка CSRF-токена
function validateCSRFToken($token) {
    if (!isset($_SESSION['csrf_token']) || $_SESSION['csrf_token'] !== $token) {
        return false;
    }
    return true;
}

// Функция для преобразования строк с размерами в байты
function convertToBytes($val) {
    $val = trim($val);
    $last = strtolower($val[strlen($val)-1]);
    $val = (int)$val;
    
    switch($last) {
        case 'g': $val *= 1024 * 1024 * 1024; break;
        case 'm': $val *= 1024 * 1024; break;
        case 'k': $val *= 1024; break;
    }
    
    return $val;
}
?>