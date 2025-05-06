<?php
// /dos/block_escalation.php
// Модуль для повышения уровня блокировки при повторных запросах

require_once 'settings.php';

/**
 * Функция повышения уровня блокировки для IP
 * 
 * @param string $ip IP-адрес
 * @return bool Результат операции
 */
function escalateBlockLevel($ip) {
    // Проверяем, включена ли эта функция
    if (!defined('ESCALATE_BLOCK_ON_REPEAT_ATTEMPTS') || !ESCALATE_BLOCK_ON_REPEAT_ATTEMPTS) {
        return false;
    }
    
    // Путь к файлу с данными о попытках
    $attempts_file = dirname(__FILE__) . '/block_escalation_attempts.php';
    $dos_dir = dirname(__FILE__) . '/';
    $now = time();
    
    // Загружаем текущие данные о попытках
    $attempts = array();
    if (file_exists($attempts_file)) {
        include $attempts_file;
    }
    
    // Инициализируем запись для текущего IP, если её нет
    if (!isset($attempts[$ip])) {
        $attempts[$ip] = array(
            'count' => 1,
            'last_attempt' => $now,
            'last_escalation' => 0
        );
    } else {
        // Увеличиваем счетчик попыток
        $attempts[$ip]['count']++;
        $attempts[$ip]['last_attempt'] = $now;
    }
    
    // Проверяем, нужно ли повысить уровень блокировки
    $min_attempts = defined('ATTEMPTS_BEFORE_ESCALATION') ? ATTEMPTS_BEFORE_ESCALATION : 3;
    $cooldown = defined('BLOCK_ESCALATION_COOLDOWN') ? BLOCK_ESCALATION_COOLDOWN : 300;
    
    if ($attempts[$ip]['count'] >= $min_attempts && 
        ($now - $attempts[$ip]['last_escalation']) > $cooldown) {
        
        // Время повышать уровень блокировки
        $result = escalateBlockLevelInStorage($ip);
        
        if ($result) {
            // Сбрасываем счетчик попыток и обновляем время последнего повышения
            $attempts[$ip]['count'] = 0;
            $attempts[$ip]['last_escalation'] = $now;
            
            // Логируем действие
            $log_message = date('Y-m-d H:i:s') . " - Повышен уровень блокировки для IP: " . $ip . "\n";
            @file_put_contents($dos_dir . 'block_escalation.log', $log_message, FILE_APPEND);
        }
    }
    
    // Сохраняем обновленные данные о попытках
    $content = "<?php\n\$attempts = " . var_export($attempts, true) . ";\n";
    @file_put_contents($attempts_file, $content);
    
    // Очищаем старые записи (старше 24 часов)
    cleanupOldAttempts($attempts, $attempts_file);
    
    return true;
}

/**
 * Повышение уровня блокировки в хранилище (Redis или MySQL)
 * 
 * @param string $ip IP-адрес
 * @return bool Результат операции
 */
function escalateBlockLevelInStorage($ip) {
    $useRedis = defined('USE_REDIS') ? USE_REDIS : false;
    $prefix = defined('REDIS_PREFIX') ? REDIS_PREFIX : 'dos:';
    $success = false;
    
    // Пытаемся повысить уровень в Redis
    if ($useRedis) {
        try {
            $redis = new Redis();
            $host = defined('REDIS_HOST') ? REDIS_HOST : '127.0.0.1';
            $port = defined('REDIS_PORT') ? REDIS_PORT : 6379;
            
            if ($redis->connect($host, $port, 2.0)) {
                // Аутентификация, если настроен пароль
                if (defined('REDIS_PASSWORD') && REDIS_PASSWORD) {
                    $redis->auth(REDIS_PASSWORD);
                }
                
                // Выбор базы данных
                $database = defined('REDIS_DATABASE') ? REDIS_DATABASE : 0;
                $redis->select($database);
                
                // Получаем информацию о блокировке
                $blockKey = $prefix . "blocked_ip:$ip";
                
                if ($redis->exists($blockKey)) {
                    // Увеличиваем счетчик блокировок
                    $block_count = $redis->hIncrBy($blockKey, 'block_count', 1);
                    
                    // Определяем новое время блокировки
                    $now = time();
                    $current_block_until = (int)$redis->hGet($blockKey, 'block_until');
                    
                    // Рассчитываем новое время блокировки
                    $new_seconds = getBlockTimeForCount($block_count);
                    $new_block_until = max($current_block_until, $now + $new_seconds);
                    
                    // Обновляем данные блокировки
                    $redis->hMSet($blockKey, array(
                        'block_until' => $new_block_until,
                        'reason' => "Повышение уровня блокировки (уровень #$block_count)"
                    ));
                    
                    // Обновляем сортированное множество
                    $redis->zAdd($prefix . "blocked_ips", $new_block_until, $ip);
                    
                    // Добавляем в лог блокировок
                    $redis->lPush($prefix . "block_log", json_encode(array(
                        'ip' => $ip,
                        'reason' => "Повышение уровня блокировки",
                        'block_until' => $new_block_until,
                        'block_count' => $block_count,
                        'time' => $now
                    )));
                    $redis->ltrim($prefix . "block_log", 0, 999);
                    
                    $success = true;
                    
                    // Применить внешние блокировки
                    applyExternalBlockingsSimple($ip);
                    
                    // Обновить файловый кеш блокировок
                    updateBlockedIPsCache();
                }
            }
        } catch (Exception $e) {
            error_log("Error escalating block in Redis: " . $e->getMessage());
        }
    }
    
    // Если Redis не сработал или не используется, пробуем через MariaDB
    if (!$success) {
        try {
            $db = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
            if (defined('PDO::ATTR_ERRMODE')) {
                $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            }
            
            // Получаем текущую информацию о блокировке
            $stmt = $db->prepare("
                SELECT block_count, block_until
                FROM blocked_ips 
                WHERE ip = ? AND block_until > NOW()
            ");
            $stmt->execute(array($ip));
            $current_block = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($current_block) {
                // Увеличиваем счетчик блокировок
                $block_count = $current_block['block_count'] + 1;
                
                // Определяем новое время блокировки
                $new_seconds = getBlockTimeForCount($block_count);
                
                // Обновляем запись блокировки
                $stmt = $db->prepare("
                    UPDATE blocked_ips
                    SET block_count = ?,
                        block_until = GREATEST(block_until, DATE_ADD(NOW(), INTERVAL ? SECOND)),
                        reason = ?
                    WHERE ip = ?
                ");
                $stmt->execute(array(
                    $block_count,
                    $new_seconds,
                    "Повышение уровня блокировки (уровень #$block_count)",
                    $ip
                ));
                
                $success = true;
                
                // Применить внешние блокировки
                applyExternalBlockingsSimple($ip);
                
                // Обновить файловый кеш блокировок
                updateBlockedIPsCache();
            }
        } catch(PDOException $e) {
            error_log("Error escalating block in DB: " . $e->getMessage());
        }
    }
    
    return $success;
}

/**
 * Получение времени блокировки в зависимости от счетчика
 * 
 * @param int $count Счетчик блокировок
 * @return int Время блокировки в секундах
 */
function getBlockTimeForCount($count) {
    switch ($count) {
        case 2:
            return defined('BLOCK_TIME_SECOND') ? BLOCK_TIME_SECOND : 10800; // 3 часа
        case 3:
            return defined('BLOCK_TIME_THIRD') ? BLOCK_TIME_THIRD : 21600; // 6 часов
        case 4:
            return defined('BLOCK_TIME_FOURTH') ? BLOCK_TIME_FOURTH : 43200; // 12 часов
        case 5:
            return defined('BLOCK_TIME_FIFTH') ? BLOCK_TIME_FIFTH : 86400; // 24 часа
        case 6:
            return defined('BLOCK_TIME_SIXTH') ? BLOCK_TIME_SIXTH : 259200; // 3 дня
        default:
            if ($count > 6) {
                return defined('BLOCK_TIME_SEVENTH_PLUS') ? BLOCK_TIME_SEVENTH_PLUS : 604800; // 7 дней
            }
            return defined('BLOCK_TIME_FIRST') ? BLOCK_TIME_FIRST : 3600; // 1 час
    }
}

/**
 * Очистка старых записей о попытках
 * 
 * @param array $attempts Массив попыток
 * @param string $file Путь к файлу
 * @return bool Результат операции
 */
function cleanupOldAttempts($attempts, $file) {
    $now = time();
    $max_age = 86400; // 24 часа
    $updated = false;
    
    foreach ($attempts as $ip => $data) {
        if (($now - $data['last_attempt']) > $max_age) {
            unset($attempts[$ip]);
            $updated = true;
        }
    }
    
    if ($updated) {
        $content = "<?php\n\$attempts = " . var_export($attempts, true) . ";\n";
        @file_put_contents($file, $content);
    }
    
    return true;
}

/**
 * Применение всех доступных методов блокировки
 * 
 * @param string $ip IP-адрес
 * @return bool Результат операции
 */
function applyExternalBlockingsSimple($ip) {
    // Блокировка через .htaccess
    if (defined('ENABLE_HTACCESS_BLOCKING') && ENABLE_HTACCESS_BLOCKING) {
        blockIPInHtaccessSimple($ip);
    }
    
    // Блокировка через Nginx (ip.conf)
    if (defined('ENABLE_NGINX_BLOCKING') && ENABLE_NGINX_BLOCKING) {
        logIPToConfSimple($ip);
    }
    
    // Блокировка через брандмауэр (iptables)
    if (defined('ENABLE_FIREWALL_BLOCKING') && ENABLE_FIREWALL_BLOCKING) {
        blockIPWithIptablesSimple($ip);
    }
    
    // Блокировка через API
    if (defined('ENABLE_API_BLOCKING') && ENABLE_API_BLOCKING) {
        blockIPWithAPISimple($ip);
    }
    
    return true;
}

/**
 * Блокировка IP через .htaccess
 * 
 * @param string $ip IP-адрес
 * @return bool Результат операции
 */
function blockIPInHtaccessSimple($ip) {
    $htaccessPath = dirname(dirname(__FILE__)) . '/.htaccess';
    
    // Проверка существования файла
    if (!file_exists($htaccessPath)) {
        file_put_contents($htaccessPath, "");
    }
    
    // Проверяем, что IP еще не заблокирован
    $htaccessContent = file_get_contents($htaccessPath);
    if (strpos($htaccessContent, "Deny from $ip") !== false) {
        return true; // Уже заблокирован
    }
    
    // Добавляем правило блокировки
    $rule = "Deny from $ip\n";
    return file_put_contents($htaccessPath, $rule, FILE_APPEND) !== false;
}

/**
 * Добавление IP в Nginx conf
 * 
 * @param string $ip IP-адрес
 * @return bool Результат операции
 */
function logIPToConfSimple($ip) {
    $ipConfFile = dirname(__FILE__) . '/ip.conf';
    
    // Если файл не существует, создаем новый
    if (!file_exists($ipConfFile)) {
        file_put_contents($ipConfFile, "# IP Blocklist\n");
    }
    
    // Читаем файл
    $lines = file($ipConfFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $blockedIPs = array();
    
    // Собираем существующие IP
    foreach ($lines as $line) {
        if (strpos($line, '#') === 0) continue;
        
        $parts = explode(' ', trim($line));
        $blockedIPs[] = $parts[0];
    }
    
    // Если IP уже заблокирован, ничего не делаем
    if (in_array($ip, $blockedIPs)) {
        return true;
    }
    
    // Добавляем IP
    $blockedIPs[] = $ip;
    
    // Формируем новое содержимое файла
    $content = "# Обновлено " . date('Y-m-d H:i:s') . "\n";
    foreach ($blockedIPs as $blockedIP) {
        $content .= "$blockedIP 1;\n";
    }
    
    // Записываем файл
    if (file_put_contents($ipConfFile, $content) === false) {
        return false;
    }
    
    // Перезагружаем Nginx
    reloadNginxSimple();
    
    return true;
}

/**
 * Перезагрузка Nginx
 * 
 * @return bool Результат операции
 */
function reloadNginxSimple() {
    // Создаем файл-флаг для перезагрузки
    $flag_file = dirname(__FILE__) . '/nginx_reload_needed';
    file_put_contents($flag_file, date('Y-m-d H:i:s'));
    
    // Пытаемся перезагрузить
    if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))))) {
        exec('sudo /usr/sbin/nginx -s reload 2>&1');
    }
    
    return true;
}

/**
 * Блокировка IP через iptables
 * 
 * @param string $ip IP-адрес
 * @return bool Результат операции
 */
function blockIPWithIptablesSimple($ip) {
    // Определяем версию IP
    $isIPv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    
    // Блокируем порты 80 и 443
    $ports = array(80, 443);
    
    foreach ($ports as $port) {
        // Формируем команду
        if ($isIPv6) {
            $command = "sudo ip6tables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
        } else {
            $command = "sudo iptables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
        }
        
        // Выполняем команду
        if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))))) {
            exec($command);
        }
    }
    
    // Сохраняем правила
    saveIptablesRulesSimple($isIPv6);
    
    return true;
}

/**
 * Сохранение правил iptables
 * 
 * @param bool $isIPv6 Использовать IPv6
 * @return bool Результат операции
 */
function saveIptablesRulesSimple($isIPv6) {
    if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))))) {
        if ($isIPv6) {
            exec("sudo sh -c 'ip6tables-save > /etc/iptables/rules.v6'");
        } else {
            exec("sudo sh -c 'iptables-save > /etc/iptables/rules.v4'");
        }
    }
    
    return true;
}

/**
 * Блокировка IP через API
 * 
 * @param string $ip IP-адрес
 * @return bool Результат операции
 */
function blockIPWithAPISimple($ip) {
    // Проверяем наличие настроек API
    if (!defined('API_BLOCK_URL') || !defined('API_BLOCK_KEY')) {
        return false;
    }
    
    $url = API_BLOCK_URL;
    $api_key = API_BLOCK_KEY;
    $userAgent = defined('API_USER_AGENT') ? API_USER_AGENT : 'PHP/' . PHP_VERSION;
    
    // Формируем параметры
    $params = array(
        'action' => 'block',
        'ip' => $ip,
        'api_key' => $api_key,
        'api' => 1
    );
    
    // Формируем URL
    $requestUrl = $url . '?' . http_build_query($params);
    
    // Используем cURL
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $requestUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_USERAGENT, $userAgent);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        
        $response = curl_exec($ch);
        curl_close($ch);
        
        return $response !== false;
    }
    
    // Если cURL недоступен, используем file_get_contents
    $opts = array(
        'http' => array(
            'method' => 'GET',
            'timeout' => 10,
            'header' => "User-Agent: $userAgent\r\n"
        )
    );
    
    $context = stream_context_create($opts);
    return file_get_contents($requestUrl, false, $context) !== false;
}

/**
 * Обновление файлового кеша блокировок
 * 
 * @return bool Результат операции
 */
function updateBlockedIPsCache() {
    $dos_dir = dirname(__FILE__) . '/';
    $cache_file = $dos_dir . 'blocked_ips.php';
    $info_file = $dos_dir . 'blocked_info.php';
    
    $blocked_ips = array();
    $blocked_info = array();
    
    // Пытаемся получить данные из Redis
    $useRedis = defined('USE_REDIS') ? USE_REDIS : false;
    $prefix = defined('REDIS_PREFIX') ? REDIS_PREFIX : 'dos:';
    
    if ($useRedis) {
        try {
            $redis = new Redis();
            $host = defined('REDIS_HOST') ? REDIS_HOST : '127.0.0.1';
            $port = defined('REDIS_PORT') ? REDIS_PORT : 6379;
            
            if ($redis->connect($host, $port, 2.0)) {
                // Аутентификация, если настроен пароль
                if (defined('REDIS_PASSWORD') && REDIS_PASSWORD) {
                    $redis->auth(REDIS_PASSWORD);
                }
                
                // Выбор базы данных
                $database = defined('REDIS_DATABASE') ? REDIS_DATABASE : 0;
                $redis->select($database);
                
                // Получаем все активные блокировки
                $now = time();
                $blocked_list = $redis->zRangeByScore($prefix . "blocked_ips", $now, '+inf', array('WITHSCORES' => true));
                
                foreach ($blocked_list as $ip => $block_until) {
                    $blocked_ips[$ip] = (int)$block_until;
                    
                    // Получаем дополнительную информацию
                    $blockKey = $prefix . "blocked_ip:$ip";
                    if ($redis->exists($blockKey)) {
                        $block_count = (int)$redis->hGet($blockKey, 'block_count');
                        $blocked_info[$ip] = array(
                            'until' => (int)$block_until,
                            'count' => $block_count
                        );
                    } else {
                        $blocked_info[$ip] = array(
                            'until' => (int)$block_until,
                            'count' => 1
                        );
                    }
                }
            }
        } catch (Exception $e) {
            error_log("Error updating cache from Redis: " . $e->getMessage());
        }
    }
    
    // Если Redis не сработал или данные не получены, пробуем через БД
    if (empty($blocked_ips)) {
        try {
            $db = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
            
            $stmt = $db->query("
                SELECT ip, UNIX_TIMESTAMP(block_until) as block_until, block_count 
                FROM blocked_ips 
                WHERE block_until > NOW()
            ");
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $blocked_ips[$row['ip']] = (int)$row['block_until'];
                $blocked_info[$row['ip']] = array(
                    'until' => (int)$row['block_until'],
                    'count' => (int)$row['block_count']
                );
            }
        } catch(PDOException $e) {
            error_log("Error updating cache from DB: " . $e->getMessage());
        }
    }
    
    // Записываем данные в кеш
    $content = "<?php\n\$blocked_ips = " . var_export($blocked_ips, true) . ";\n";
    $info_content = "<?php\n\$blocked_info = " . var_export($blocked_info, true) . ";\n";
    
    // Используем атомарную запись
    $tmp_file = $cache_file . '.tmp';
    if (file_put_contents($tmp_file, $content) !== false) {
        rename($tmp_file, $cache_file);
    }
    
    $tmp_info_file = $info_file . '.tmp';
    if (file_put_contents($tmp_info_file, $info_content) !== false) {
        rename($tmp_info_file, $info_file);
    }
    
    return true;
}
?>