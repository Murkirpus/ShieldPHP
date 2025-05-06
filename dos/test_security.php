<?php
/*
 * Скрипт для тестирования различных типов блокировок в security_monitor.php
 * Совместимость: PHP 5.6 - 8.3
 */

// Отключаем лимит выполнения, так как тесты могут занять время
@set_time_limit(300);

// Запускаем сессию для отслеживания блокировок
if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}

// Настройка обработки ошибок - показываем только в случае серьезных проблем
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', 0);

// Настройки
$site_url = "https://kinoprostor.tv"; // Замените на URL вашего сайта
//$site_url = "http" . (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "s" : "") . "://" . $_SERVER['HTTP_HOST']; // URL сайта автоматически
$dos_path = dirname(__FILE__); // Путь к текущей директории dos

// Функция для выполнения HTTP запросов - поддержка cURL и file_get_contents
function make_request($url, $user_agent = null, $headers = array()) {
    // Проверка доступности cURL
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        
        // Установка User-Agent если задан
        if ($user_agent !== null) {
            curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
        }
        
        // Дополнительные заголовки
        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }
        
        $response = curl_exec($ch);
        $info = curl_getinfo($ch);
        $error = curl_error($ch);
        curl_close($ch);
        
        return array(
            'response' => $response,
            'info' => $info,
            'error' => $error
        );
    } else {
        // Запасной вариант через file_get_contents
        $options = array(
            'http' => array(
                'method' => 'GET',
                'timeout' => 10
            )
        );
        
        if ($user_agent !== null) {
            $options['http']['header'] = "User-Agent: $user_agent\r\n";
        }
        
        if (!empty($headers)) {
            if (isset($options['http']['header'])) {
                foreach ($headers as $header) {
                    $options['http']['header'] .= "$header\r\n";
                }
            } else {
                $header_string = '';
                foreach ($headers as $header) {
                    $header_string .= "$header\r\n";
                }
                $options['http']['header'] = $header_string;
            }
        }
        
        $context = stream_context_create($options);
        $result = @file_get_contents($url, false, $context);
        $redirect = false;
        
        // Проверяем редирект на страницу разблокировки
        if (!empty($http_response_header)) {
            foreach ($http_response_header as $header) {
                if (strpos($header, 'Location:') !== false && strpos($header, 'recaptcha_unlock.php') !== false) {
                    $redirect = true;
                    break;
                }
            }
        }
        
        return array(
            'response' => $result,
            'info' => array(
                'url' => $redirect ? 'recaptcha_unlock.php' : $url,
                'http_code' => isset($http_response_header[0]) ? substr($http_response_header[0], 9, 3) : 0
            ),
            'error' => false
        );
    }
}

// Функция для выполнения мульти-запроса с параллельной отправкой
function make_parallel_requests($url_base, $count, $parallel, $user_agent = null) {
    $results = array();
    $blocked = false;
    
    // Проверка доступности cURL мульти
    if (function_exists('curl_multi_init')) {
        // Выполняем параллельные запросы пакетами
        $batches = ceil($count / $parallel);
        
        for ($b = 0; $b < $batches; $b++) {
            $mh = curl_multi_init();
            $handles = array();
            
            $batch_size = min($parallel, $count - $b * $parallel);
            for ($i = 0; $i < $batch_size; $i++) {
                $req_num = $b * $parallel + $i;
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url_base . "/?test=page_rate&i=$req_num");
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                
                if ($user_agent !== null) {
                    curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
                }
                
                curl_multi_add_handle($mh, $ch);
                $handles[] = $ch;
            }
            
            $running = null;
            do {
                $mrc = curl_multi_exec($mh, $running);
            } while ($running > 0);
            
            foreach ($handles as $ch) {
                $info = curl_getinfo($ch);
                $results[] = $info;
                
                if (strpos($info['url'], 'recaptcha_unlock.php') !== false) {
                    $blocked = true;
                }
                
                curl_multi_remove_handle($mh, $ch);
            }
            
            curl_multi_close($mh);
            
            // Если заблокированы, прерываем выполнение
            if ($blocked) {
                break;
            }
            
            // Короткая пауза между пакетами
            usleep(200000); // 0.2 секунды
        }
    } else {
        // Запасной вариант - последовательные запросы
        for ($i = 0; $i < $count; $i++) {
            $response = make_request($url_base . "/?test=page_rate&i=$i", $user_agent);
            $results[] = $response['info'];
            
            if (strpos($response['info']['url'], 'recaptcha_unlock.php') !== false) {
                $blocked = true;
                break;
            }
            
            // Минимальная задержка
            usleep(100000); // 0.1 секунды
        }
    }
    
    return array(
        'results' => $results,
        'blocked' => $blocked
    );
}

// Проверка статуса блокировки
function check_ip_blocked($ip) {
    global $dos_path;
    
    $results = array(
        'redis' => false,
        'file_cache' => false,
        'htaccess' => false,
        'nginx' => false,
        'iptables' => false,
        'api' => false,
        'block_count' => 0
    );
    
    // Проверка блокировки в файловом кеше
    $cache_file = $dos_path . '/blocked_ips.php';
    if (file_exists($cache_file)) {
        include $cache_file;
        if (isset($blocked_ips) && isset($blocked_ips[$ip]) && $blocked_ips[$ip] > time()) {
            $results['file_cache'] = true;
            $results['file_cache_until'] = date('Y-m-d H:i:s', $blocked_ips[$ip]);
        }
    }
    
    // Проверка информации о блокировке
    $info_file = $dos_path . '/blocked_info.php';
    if (file_exists($info_file)) {
        include $info_file;
        if (isset($blocked_info) && isset($blocked_info[$ip])) {
            $results['block_count'] = isset($blocked_info[$ip]['count']) ? $blocked_info[$ip]['count'] : 1;
        }
    }
    
    // Проверка блокировки в .htaccess
    $htaccess_file = dirname($dos_path) . '/.htaccess';
    if (file_exists($htaccess_file)) {
        $htaccess_content = file_get_contents($htaccess_file);
        if (strpos($htaccess_content, "Deny from $ip") !== false) {
            $results['htaccess'] = true;
        }
    }
    
    // Проверка блокировки в nginx
    $nginx_file = $dos_path . '/ip.conf';
    if (file_exists($nginx_file)) {
        $nginx_content = file_get_contents($nginx_file);
        if (strpos($nginx_content, "$ip 1;") !== false) {
            $results['nginx'] = true;
        }
    }
    
    // Проверка блокировки в iptables (через лог)
    $iptables_log = $dos_path . '/hard_blocked_ips.log';
    if (file_exists($iptables_log)) {
        $log_content = file_get_contents($iptables_log);
        if (strpos($log_content, $ip) !== false) {
            $results['iptables'] = true;
        }
    }
    
    return $results;
}

// Получение последних строк из лог-файла
function get_log_tail($log_file, $lines = 20) {
    if (!file_exists($log_file)) {
        return "Лог-файл не найден";
    }
    
    // Проверяем, доступна ли функция shell_exec
    if (function_exists('shell_exec') && !in_array('shell_exec', explode(',', ini_get('disable_functions')))) {
        $output = @shell_exec("tail -n " . intval($lines) . " " . escapeshellarg($log_file));
        if ($output) {
            return $output;
        }
    }
    
    // Альтернативный метод - чтение файла через PHP
    $file = @file($log_file);
    if ($file === false) {
        return "Ошибка чтения лог-файла";
    }
    
    $count = count($file);
    $start = max(0, $count - $lines);
    $output = array_slice($file, $start);
    
    return implode("", $output);
}

// Проверка Redis соединения и статуса блокировки
function check_redis_blocking($ip) {
    global $dos_path;
    
    $results = array(
        'available' => false,
        'blocked' => false,
        'block_until' => null,
        'block_count' => null,
        'reason' => null
    );
    
    // Проверка доступности класса Redis
    if (!class_exists('Redis')) {
        return $results;
    }
    
    // Подключаем settings.php для получения настроек Redis
    $settings_file = $dos_path . '/settings.php';
    if (!file_exists($settings_file)) {
        return $results;
    }
    
    // Включаем settings.php
    require_once $settings_file;
    
    try {
        // Проверка, определены ли константы
        $redis_host = defined('REDIS_HOST') ? REDIS_HOST : '127.0.0.1';
        $redis_port = defined('REDIS_PORT') ? REDIS_PORT : 6379;
        $redis_password = defined('REDIS_PASSWORD') ? REDIS_PASSWORD : '';
        $redis_database = defined('REDIS_DATABASE') ? REDIS_DATABASE : 0;
        $redis_prefix = defined('REDIS_PREFIX') ? REDIS_PREFIX : 'dos:';
        
        // Соединение с Redis
        $redis = new Redis();
        if (!$redis->connect($redis_host, $redis_port, 2.0)) {
            return $results;
        }
        
        // Аутентификация, если настроен пароль
        if ($redis_password) {
            if (!$redis->auth($redis_password)) {
                return $results;
            }
        }
        
        // Выбор базы данных
        $redis->select($redis_database);
        
        // Проверка доступности Redis
        $ping = $redis->ping();
        if ($ping !== true && $ping !== "+PONG") {
            return $results;
        }
        
        $results['available'] = true;
        
        // Проверка блокировки IP
        $blockedIpsKey = $redis_prefix . 'blocked_ips';
        $blockUntil = $redis->zScore($blockedIpsKey, $ip);
        
        if ($blockUntil !== false && $blockUntil > time()) {
            $results['blocked'] = true;
            $results['block_until'] = date('Y-m-d H:i:s', $blockUntil);
            
            // Получение дополнительной информации
            $blockKey = $redis_prefix . "blocked_ip:$ip";
            if ($redis->exists($blockKey)) {
                $results['block_count'] = $redis->hGet($blockKey, 'block_count');
                $results['reason'] = $redis->hGet($blockKey, 'reason');
            }
        }
        
        return $results;
    } catch (Exception $e) {
        return $results;
    }
}

// Функция для ручной блокировки IP
function manual_block_ip($ip, $reason, $seconds = 3600) {
    global $dos_path;
    $result = "";
    
    // Записываем в лог
    $log_message = date('Y-m-d H:i:s') . " - " . $ip . " заблокирован на " . format_time_period($seconds) . ": " . 
                  $reason . " (тестовая блокировка)\n";
    $result .= "Запись в лог блокировки: " . htmlspecialchars($log_message);
    @file_put_contents($dos_path . '/blocked_ips.log', $log_message, FILE_APPEND);
    
    // Создаем блокировку в кеше
    $block_time = time() + $seconds;
    $blocked_ips = array();
    
    // Чтение существующего кеша
    $cache_file = $dos_path . '/blocked_ips.php';
    if (file_exists($cache_file)) {
        include($cache_file);
    }
    
    if (!isset($blocked_ips) || !is_array($blocked_ips)) {
        $blocked_ips = array();
    }
    
    // Добавляем IP в кеш
    $blocked_ips[$ip] = $block_time;
    
    // Записываем обновленный кеш
    $tmp_file = $cache_file . '.tmp';
    $cache_content = "<?php\n\$blocked_ips = " . var_export($blocked_ips, true) . ";\n";
    
    if (@file_put_contents($tmp_file, $cache_content) !== false) {
        @rename($tmp_file, $cache_file);
        $result .= "<br>IP успешно добавлен в кеш блокировок на " . format_time_period($seconds) . ".<br>";
    } else {
        $result .= "<br>Ошибка при записи в кеш блокировок.<br>";
    }
    
    // Обновляем информацию о блокировке
    $blocked_info = array();
    $info_file = $dos_path . '/blocked_info.php';
    
    if (file_exists($info_file)) {
        include($info_file);
    }
    
    if (!isset($blocked_info) || !is_array($blocked_info)) {
        $blocked_info = array();
    }
    
    // Устанавливаем или обновляем счетчик блокировок
    $block_count = 1;
    if (isset($blocked_info[$ip])) {
        $block_count = isset($blocked_info[$ip]['count']) ? $blocked_info[$ip]['count'] + 1 : 2;
    }
    
    $blocked_info[$ip] = array(
        'until' => $block_time,
        'count' => $block_count
    );
    
    // Записываем обновленную информацию
    $tmp_file = $info_file . '.tmp';
    $info_content = "<?php\n\$blocked_info = " . var_export($blocked_info, true) . ";\n";
    
    if (@file_put_contents($tmp_file, $info_content) !== false) {
        @rename($tmp_file, $info_file);
        $result .= "Информация о блокировке обновлена (блокировка #$block_count).<br>";
    }
    
    return $result;
}

// Получение настроек блокировки из settings.php
function get_security_settings() {
    global $dos_path;
    
    $settings = array(
        'htaccess_enabled' => false,
        'nginx_enabled' => false,
        'firewall_enabled' => false,
        'api_enabled' => false,
        'redis_enabled' => false
    );
    
    // Проверяем настройки блокировки
    $settings_file = $dos_path . '/settings.php';
    if (file_exists($settings_file)) {
        $settings_content = file_get_contents($settings_file);
        
        // Проверяем значения констант
        $settings['htaccess_enabled'] = preg_match('/ENABLE_HTACCESS_BLOCKING[\'"]?\s*,\s*true/i', $settings_content);
        $settings['nginx_enabled'] = preg_match('/ENABLE_NGINX_BLOCKING[\'"]?\s*,\s*true/i', $settings_content);
        $settings['firewall_enabled'] = preg_match('/ENABLE_FIREWALL_BLOCKING[\'"]?\s*,\s*true/i', $settings_content);
        $settings['api_enabled'] = preg_match('/ENABLE_API_BLOCKING[\'"]?\s*,\s*true/i', $settings_content);
        $settings['redis_enabled'] = preg_match('/USE_REDIS[\'"]?\s*,\s*true/i', $settings_content);
    }
    
    return $settings;
}

// Форматирование времени
function format_time_period($seconds) {
    if ($seconds < 60) {
        return "$seconds секунд";
    } elseif ($seconds < 3600) {
        return floor($seconds / 60) . " минут";
    } elseif ($seconds < 86400) {
        return floor($seconds / 3600) . " часов";
    } else {
        return floor($seconds / 86400) . " дней";
    }
}

// Функция для форматирования состояния (вкл/выкл)
function format_state($enabled) {
    return $enabled ? '<span style="color: green; font-weight: bold;">Включено</span>' : '<span style="color: red;">Выключено</span>';
}

// Обработка тестов
$result = '';
$log_output = '';
$block_status = array();
$redis_status = array();
$client_ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';
$settings = get_security_settings();

if (isset($_POST['action'])) {
    $action = $_POST['action'];
    
    switch ($action) {
        case 'test_rate_limit':
            $result .= "<h3>Тест превышения лимита запросов</h3>";
            $count = isset($_POST['request_count']) ? intval($_POST['request_count']) : 30;
            $delay = isset($_POST['delay']) ? floatval($_POST['delay']) : 0.1;
            $user_agent = isset($_POST['use_empty_ua']) && $_POST['use_empty_ua'] == 1 ? "" : null;
            
            $result .= "Выполняем $count запросов с задержкой $delay сек...<br>";
            if ($user_agent === "") {
                $result .= "Используем пустой User-Agent<br>";
            }
            
            $blocked = false;
            for ($i = 0; $i < $count; $i++) {
                $response = make_request($site_url . "/?test=rate_limit&i=$i", $user_agent);
                if ($i % 5 == 0 || $i == $count - 1) {
                    $result .= "Выполнено запросов: " . ($i + 1) . "<br>";
                    // Сбрасываем буфер, чтобы видеть прогресс
                    if (function_exists('ob_flush')) {
                        @ob_flush();
                        @flush();
                    }
                }
                
                // Задержка между запросами
                if ($delay > 0) {
                    usleep($delay * 1000000);
                }
                
                // Если получили редирект на страницу разблокировки, останавливаемся
                if (strpos($response['info']['url'], 'recaptcha_unlock.php') !== false) {
                    $result .= "<strong>IP заблокирован после " . ($i + 1) . " запросов!</strong><br>";
                    $blocked = true;
                    break;
                }
            }
            
            if (!$blocked) {
                $result .= "Тест завершен без блокировки.<br>";
            }
            
            $block_status = check_ip_blocked($client_ip);
            $redis_status = check_redis_blocking($client_ip);
            $log_output = get_log_tail($dos_path . '/blocked_ips.log');
            break;
            
        case 'test_suspicious':
            $result .= "<h3>Тест подозрительных запросов</h3>";
            $count = isset($_POST['request_count']) ? intval($_POST['request_count']) : 15;
            $user_agent = isset($_POST['user_agent']) ? $_POST['user_agent'] : '';
            
            $result .= "Выполняем $count запросов с User-Agent: " . ($user_agent ?: '[пусто]') . "<br>";
            
            $blocked = false;
            for ($i = 0; $i < $count; $i++) {
                $response = make_request(
                    $site_url . "/?test=suspicious&i=$i", 
                    $user_agent
                );
                
                if ($i % 5 == 0 || $i == $count - 1) {
                    $result .= "Выполнено запросов: " . ($i + 1) . "<br>";
                    if (function_exists('ob_flush')) {
                        @ob_flush();
                        @flush();
                    }
                }
                
                // Минимальная задержка для стабильности
                usleep(100000); // 0.1 секунды
                
                // Если получили редирект на страницу разблокировки, останавливаемся
                if (strpos($response['info']['url'], 'recaptcha_unlock.php') !== false) {
                    $result .= "<strong>IP заблокирован после " . ($i + 1) . " запросов!</strong><br>";
                    $blocked = true;
                    break;
                }
            }
            
            if (!$blocked) {
                $result .= "Тест завершен без блокировки.<br>";
            }
            
            $block_status = check_ip_blocked($client_ip);
            $redis_status = check_redis_blocking($client_ip);
            $log_output = get_log_tail($dos_path . '/blocked_ips.log');
            break;
            
        case 'test_page_rate':
            $result .= "<h3>Тест превышения лимита запросов страниц</h3>";
            $count = isset($_POST['request_count']) ? intval($_POST['request_count']) : 20;
            $parallel = isset($_POST['parallel']) ? intval($_POST['parallel']) : 5;
            $aggressive = isset($_POST['aggressive']) && $_POST['aggressive'] == 1 ? true : false;
            
            $result .= "Выполняем $count запросов (по $parallel параллельно)" . 
                      ($aggressive ? " в агрессивном режиме" : "") . "...<br>";
            
            // Выполняем параллельные запросы
            $test_results = make_parallel_requests($site_url, $count, $parallel);
            
            if ($test_results['blocked']) {
                $result .= "<strong>IP заблокирован!</strong><br>";
                
                // В агрессивном режиме отправляем дополнительные запросы для повышения уровня блокировки
                if ($aggressive) {
                    $result .= "Отправка дополнительных запросов в агрессивном режиме...<br>";
                    
                    // Пауза для обработки первой блокировки
                    sleep(1);
                    
                    // Отправляем еще один пакет запросов
                    $extra_results = make_parallel_requests($site_url, $parallel, $parallel);
                    
                    $result .= "Дополнительные запросы отправлены.<br>";
                    
                    // Пауза для обработки запросов
                    sleep(1);
                }
            } else {
                $result .= "Тест завершен без блокировки.<br>";
            }
            
            $block_status = check_ip_blocked($client_ip);
            $redis_status = check_redis_blocking($client_ip);
            $log_output = get_log_tail($dos_path . '/blocked_ips.log');
            break;
            
        case 'test_manual_block':
            $result .= "<h3>Тест ручной блокировки</h3>";
            $ip = isset($_POST['block_ip']) ? $_POST['block_ip'] : $client_ip;
            $reason = isset($_POST['block_reason']) ? $_POST['block_reason'] : 'Тестовая блокировка';
            $level = isset($_POST['block_level']) ? intval($_POST['block_level']) : 1;
            
            // Блокировка на разное время в зависимости от уровня
            $block_time = 3600; // 1 час по умолчанию
            
            if ($level == 2) {
                $block_time = 10800; // 3 часа
                $reason .= " (блокировка #2)";
            } else if ($level == 3) {
                $block_time = 21600; // 6 часов
                $reason .= " (блокировка #3)";
            }
            
            $result .= manual_block_ip($ip, $reason, $block_time);
            
            $block_status = check_ip_blocked($client_ip);
            $redis_status = check_redis_blocking($client_ip);
            $log_output = get_log_tail($dos_path . '/blocked_ips.log');
            break;
            
        case 'check_status':
            $result .= "<h3>Проверка статуса блокировки</h3>";
            $ip = isset($_POST['ip']) ? $_POST['ip'] : $client_ip;
            
            $block_status = check_ip_blocked($ip);
            $redis_status = check_redis_blocking($ip);
            
            $result .= "Проверка блокировки для IP: $ip<br>";
            $log_output = get_log_tail($dos_path . '/blocked_ips.log');
            break;
            
        case 'view_logs':
            $result .= "<h3>Просмотр логов</h3>";
            $log_file = isset($_POST['log_file']) ? $_POST['log_file'] : 'blocked_ips.log';
            $lines = isset($_POST['lines']) ? intval($_POST['lines']) : 50;
            
            // Безопасная проверка имени файла
            if (!preg_match('/^[a-zA-Z0-9_.]+$/', $log_file)) {
                $result .= "Некорректное имя файла";
                break;
            }
            
            $log_path = $dos_path . '/' . $log_file;
            $log_output = get_log_tail($log_path, $lines);
            break;
            
        case 'check_redis':
            $result .= "<h3>Проверка настроек Redis</h3>";
            $redis_status = check_redis_blocking($client_ip);
            
            if ($redis_status['available']) {
                $result .= "Redis доступен и правильно настроен.<br>";
                if ($redis_status['blocked']) {
                    $result .= "Текущий IP заблокирован в Redis до: " . $redis_status['block_until'] . "<br>";
                    $result .= "Причина: " . htmlspecialchars($redis_status['reason']) . "<br>";
                    $result .= "Счетчик блокировок: " . $redis_status['block_count'] . "<br>";
                } else {
                    $result .= "Текущий IP не заблокирован в Redis.<br>";
                }
            } else {
                $result .= "Redis не доступен или не настроен.<br>";
                $result .= "Проверьте, что:<br>";
                $result .= "1. Установлено расширение Redis для PHP<br>";
                $result .= "2. Redis сервер запущен<br>";
                $result .= "3. Правильно настроены параметры подключения в settings.php<br>";
                $result .= "4. USE_REDIS установлено в true в settings.php<br>";
            }
            break;
    }
}

// Текущий статус блокировки для отображения
if (empty($block_status)) {
    $block_status = check_ip_blocked($client_ip);
}

// HTML интерфейс
?>
<!DOCTYPE html>
<html>
<head>
    <title>Тестирование security_monitor.php</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #333;
        }
        .test-section {
            margin-bottom: 20px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background-color: #f9f9f9;
        }
        form {
            margin-bottom: 10px;
        }
        label {
            display: inline-block;
            width: 250px;
            margin-bottom: 5px;
        }
        input[type="text"],
        input[type="number"] {
            padding: 5px;
            width: 100px;
        }
        input[type="checkbox"] {
            margin-right: 5px;
        }
        input[type="submit"] {
            padding: 8px 15px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #45a049;
        }
        .result {
            margin-top: 20px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background-color: #fff;
        }
        .log {
            margin-top: 20px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background-color: #f5f5f5;
            font-family: monospace;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .blocked {
            background-color: #ffdddd;
            color: #ff0000;
            font-weight: bold;
        }
        .not-blocked {
            background-color: #e6ffe6;
            color: #006600;
        }
        .info-box {
            background-color: #e7f3fe;
            border-left: 5px solid #2196F3;
            padding: 10px;
            margin: 20px 0;
        }
        .warning-box {
            background-color: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 10px;
            margin: 20px 0;
        }
        .test-description {
            background-color: #f8f9fa;
            border: 1px dashed #ddd;
            padding: 10px;
            margin-bottom: 10px;
            font-style: italic;
        }
        .status-box {
            margin-top: 20px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Тестирование security_monitor.php</h1>
        <p>IP адрес клиента: <?php echo htmlspecialchars($client_ip); ?></p>
        
        <div class="status-box <?php echo $block_status['file_cache'] ? 'blocked' : 'not-blocked'; ?>">
            <h3>Текущий статус</h3>
            <?php if ($block_status['file_cache']): ?>
                <p><strong>Ваш IP заблокирован до:</strong> <?php echo htmlspecialchars($block_status['file_cache_until']); ?></p>
                <p><strong>Уровень блокировки:</strong> <?php echo htmlspecialchars($block_status['block_count']); ?></p>
            <?php else: ?>
                <p>Ваш IP не заблокирован.</p>
            <?php endif; ?>
        </div>
        
        <div class="info-box">
            <h3>Текущие настройки в settings.php</h3>
            <table>
                <tr>
                    <td>Блокировка через .htaccess:</td>
                    <td><?php echo format_state($settings['htaccess_enabled']); ?></td>
                </tr>
                <tr>
                    <td>Блокировка через Nginx (ip.conf):</td>
                    <td><?php echo format_state($settings['nginx_enabled']); ?></td>
                </tr>
                <tr>
                    <td>Блокировка через брандмауэр (iptables):</td>
                    <td><?php echo format_state($settings['firewall_enabled']); ?></td>
                </tr>
                <tr>
                    <td>Блокировка через API:</td>
                    <td><?php echo format_state($settings['api_enabled']); ?></td>
                </tr>
                <tr>
                    <td>Использование Redis:</td>
                    <td><?php echo format_state($settings['redis_enabled']); ?></td>
                </tr>
            </table>
        </div>
        
        <div class="warning-box">
            <p><strong>Внимание:</strong> Запуск тестов может привести к блокировке вашего IP-адреса. Используйте этот скрипт только для тестирования и не запускайте его на производственном сервере.</p>
        </div>
        
        <div class="test-section">
            <h2>Тест 1: Превышение лимита запросов</h2>
            <div class="test-description">
                Этот тест имитирует много последовательных запросов для проверки блокировки по превышению лимита запросов.
            </div>
            <form method="post">
                <input type="hidden" name="action" value="test_rate_limit">
                <label for="request_count">Количество запросов:</label>
                <input type="number" id="request_count" name="request_count" value="30" min="1" max="100"><br>
                <label for="delay">Задержка между запросами (сек):</label>
                <input type="text" id="delay" name="delay" value="0.1"><br>
                <label for="use_empty_ua">Использовать пустой User-Agent:</label>
                <input type="checkbox" id="use_empty_ua" name="use_empty_ua" value="1" checked><br>
                <input type="submit" value="Запустить тест">
            </form>
        </div>
        
        <div class="test-section">
            <h2>Тест 2: Подозрительные запросы</h2>
            <div class="test-description">
                Этот тест отправляет запросы с пустым или подозрительным User-Agent для проверки блокировки "Слишком много подозрительных запросов".
            </div>
            <form method="post">
                <input type="hidden" name="action" value="test_suspicious">
                <label for="request_count">Количество запросов:</label>
                <input type="number" id="request_count" name="request_count" value="15" min="1" max="100"><br>
                <label for="user_agent">User-Agent (пусто или "bot"):</label>
                <input type="text" id="user_agent" name="user_agent" value=""><br>
                <input type="submit" value="Запустить тест">
            </form>
        </div>
        
        <div class="test-section">
            <h2>Тест 3: Превышение лимита запросов страниц</h2>
            <div class="test-description">
                Этот тест отправляет параллельные запросы для проверки блокировки по превышению лимита запросов страниц. 
                Агрессивный режим отправляет дополнительные запросы для повышения уровня блокировки.
            </div>
            <form method="post">
                <input type="hidden" name="action" value="test_page_rate">
                <label for="request_count">Общее количество запросов:</label>
                <input type="number" id="request_count" name="request_count" value="20" min="1" max="100"><br>
                <label for="parallel">Параллельных запросов:</label>
                <input type="number" id="parallel" name="parallel" value="5" min="1" max="20"><br>
                <label for="aggressive">Агрессивный режим (для блокировки #2):</label>
                <input type="checkbox" id="aggressive" name="aggressive" value="1" checked><br>
                <input type="submit" value="Запустить тест">
            </form>
        </div>
        
        <div class="test-section">
            <h2>Тест 4: Ручная блокировка</h2>
            <div class="test-description">
                Принудительная блокировка с указанием причины и уровня. Позволяет проверить работу блокировки на разных уровнях.
            </div>
            <form method="post">
                <input type="hidden" name="action" value="test_manual_block">
                <label for="block_ip">IP адрес:</label>
                <input type="text" id="block_ip" name="block_ip" value="<?php echo htmlspecialchars($client_ip); ?>"><br>
                <label for="block_reason">Причина блокировки:</label>
                <input type="text" id="block_reason" name="block_reason" value="Слишком много подозрительных запросов" style="width: 300px;"><br>
                <label for="block_level">Уровень блокировки:</label>
                <select id="block_level" name="block_level">
                    <option value="1">Блокировка #1 (1 час)</option>
                    <option value="2">Блокировка #2 (3 часа)</option>
                    <option value="3">Блокировка #3 (6 часов)</option>
                </select><br>
                <input type="submit" value="Выполнить блокировку">
            </form>
        </div>
        
        <div class="test-section">
            <h2>Проверка статуса блокировки</h2>
            <form method="post">
                <input type="hidden" name="action" value="check_status">
                <label for="ip">IP адрес (по умолчанию ваш):</label>
                <input type="text" id="ip" name="ip" value="<?php echo htmlspecialchars($client_ip); ?>"><br>
                <input type="submit" value="Проверить статус">
            </form>
        </div>
        
        <div class="test-section">
            <h2>Проверка настроек Redis</h2>
            <form method="post">
                <input type="hidden" name="action" value="check_redis">
                <input type="submit" value="Проверить Redis">
            </form>
        </div>
        
        <div class="test-section">
            <h2>Просмотр логов</h2>
            <form method="post">
                <input type="hidden" name="action" value="view_logs">
                <label for="log_file">Файл лога:</label>
                <select id="log_file" name="log_file">
                    <option value="blocked_ips.log">blocked_ips.log</option>
                    <option value="cleanup.log">cleanup.log</option>
                    <option value="hard_blocked_ips.log">hard_blocked_ips.log</option>
                    <option value="recaptcha_unlock.log">recaptcha_unlock.log</option>
                    <option value="unlock_attempts.log">unlock_attempts.log</option>
                </select><br>
                <label for="lines">Количество строк:</label>
                <input type="number" id="lines" name="lines" value="50" min="10" max="500"><br>
                <input type="submit" value="Просмотреть лог">
            </form>
        </div>
        
        <?php if (!empty($result)): ?>
        <div class="result">
            <h2>Результаты теста</h2>
            <?php echo $result; ?>
            
            <?php if (!empty($block_status)): ?>
            <h3>Статус блокировки IP <?php echo htmlspecialchars($client_ip); ?></h3>
            <table>
                <tr>
                    <th>Метод блокировки</th>
                    <th>Статус</th>
                    <th>Детали</th>
                </tr>
                <tr class="<?php echo $block_status['file_cache'] ? 'blocked' : 'not-blocked'; ?>">
                    <td>Файловый кеш</td>
                    <td><?php echo $block_status['file_cache'] ? 'ЗАБЛОКИРОВАН' : 'Не блокирован'; ?></td>
                    <td>
                        <?php 
                            if (isset($block_status['file_cache_until'])) {
                                echo 'До: ' . htmlspecialchars($block_status['file_cache_until']);
                            }
                            if (isset($block_status['block_count']) && $block_status['block_count'] > 0) {
                                echo ' (блок #' . $block_status['block_count'] . ')'; 
                            }
                        ?>
                    </td>
                </tr>
                <tr class="<?php echo $block_status['htaccess'] ? 'blocked' : 'not-blocked'; ?>">
                    <td>Apache (.htaccess)</td>
                    <td><?php echo $block_status['htaccess'] ? 'ЗАБЛОКИРОВАН' : 'Не блокирован'; ?></td>
                    <td><?php echo $settings['htaccess_enabled'] ? '' : 'Блокировка выключена в настройках'; ?></td>
                </tr>
                <tr class="<?php echo $block_status['nginx'] ? 'blocked' : 'not-blocked'; ?>">
                    <td>Nginx (ip.conf)</td>
                    <td><?php echo $block_status['nginx'] ? 'ЗАБЛОКИРОВАН' : 'Не блокирован'; ?></td>
                    <td><?php echo $settings['nginx_enabled'] ? '' : 'Блокировка выключена в настройках'; ?></td>
                </tr>
                <tr class="<?php echo $block_status['iptables'] ? 'blocked' : 'not-blocked'; ?>">
                    <td>Брандмауэр (iptables)</td>
                    <td><?php echo $block_status['iptables'] ? 'ЗАБЛОКИРОВАН' : 'Не блокирован'; ?></td>
                    <td><?php echo $settings['firewall_enabled'] ? 'Проверка через лог hard_blocked_ips.log' : 'Блокировка выключена в настройках'; ?></td>
                </tr>
            </table>
            <?php endif; ?>
            
            <?php if (!empty($redis_status) && $redis_status['available']): ?>
            <h3>Статус блокировки в Redis</h3>
            <table>
                <tr>
                    <th>Параметр</th>
                    <th>Значение</th>
                </tr>
                <tr class="<?php echo $redis_status['blocked'] ? 'blocked' : 'not-blocked'; ?>">
                    <td>Статус блокировки</td>
                    <td><?php echo $redis_status['blocked'] ? 'ЗАБЛОКИРОВАН' : 'Не блокирован'; ?></td>
                </tr>
                <?php if ($redis_status['blocked']): ?>
                <tr>
                    <td>Блокировка до</td>
                    <td><?php echo htmlspecialchars($redis_status['block_until']); ?></td>
                </tr>
                <tr>
                    <td>Счетчик блокировок</td>
                    <td><?php echo htmlspecialchars($redis_status['block_count']); ?></td>
                </tr>
                <tr>
                    <td>Причина</td>
                    <td><?php echo htmlspecialchars($redis_status['reason']); ?></td>
                </tr>
                <?php endif; ?>
            </table>
            <?php endif; ?>
        </div>
        <?php endif; ?>
        
        <?php if (!empty($log_output)): ?>
        <div class="log">
            <h2>Лог-файл</h2>
            <?php echo htmlspecialchars($log_output); ?>
        </div>
        <?php endif; ?>
    </div>
    
    <!-- Совместимый с PHP 5.6 JavaScript -->
    <script type="text/javascript">
    (function() {
        // Проверка наличия куки
        function checkCookies() {
            var cookiesEnabled = navigator.cookieEnabled;
            if (!cookiesEnabled) {
                var warningBox = document.createElement("div");
                warningBox.className = "warning-box";
                warningBox.innerHTML = "<p><strong>Внимание:</strong> Cookies отключены в вашем браузере. Для правильной работы скрипта тестирования требуются cookies.</p>";
                
                var container = document.querySelector(".container");
                container.insertBefore(warningBox, container.firstChild);
            }
        }
        
        // Запуск проверки при загрузке страницы
        if (window.addEventListener) {
            window.addEventListener("load", checkCookies, false);
        } else if (window.attachEvent) {
            window.attachEvent("onload", checkCookies);
        }
    })();
    </script>
</body>
</html>