<?php
/**
 * iptables.php - Скрипт для блокировки IP-адресов через iptables (IPv4) и ip6tables (IPv6)
 * Скрипт работает без прав root, используя sudo для выполнения команд iptables
 * 
 * Совместим с PHP версий 5.6 - 8.3
 * Добавлена защита API ключом
 * Добавлено распределение нагрузки API запросов
 * 
 * Для работы необходимо настроить sudoers, добавив примерно следующее:
 * www-data ALL=(ALL) NOPASSWD: /sbin/iptables, /sbin/ip6tables, /sbin/iptables-save, /sbin/ip6tables-save
 */
 
 /**
 * Поддерживаемые URL API для iptables.php
 * 
 * Все запросы должны содержать параметр api=1 и действительный api_key
 * 
 * 1. Блокировка IP-адреса
 *    URL: iptables.php?action=block&ip={IP_ADDRESS}&api=1&api_key={YOUR_API_KEY}
 *    Метод: GET/POST
 *    Параметры: action=block, ip (обязателен)
 *    Пример: iptables.php?action=block&ip=192.168.1.10&api=1&api_key=ваш_ключ
 * 
 * 2. Разблокировка IP-адреса
 *    URL: iptables.php?action=unblock&ip={IP_ADDRESS}&api=1&api_key={YOUR_API_KEY}
 *    Метод: GET/POST
 *    Параметры: action=unblock, ip (обязателен)
 *    Пример: iptables.php?action=unblock&ip=192.168.1.10&api=1&api_key=ваш_ключ
 * 
 * 3. Получение списка заблокированных IPv4-адресов
 *    URL: iptables.php?action=list&api=1&api_key={YOUR_API_KEY}
 *    Метод: GET
 *    Пример: iptables.php?action=list&api=1&api_key=ваш_ключ
 * 
 * 4. Получение списка заблокированных IPv6-адресов
 *    URL: iptables.php?action=list6&api=1&api_key={YOUR_API_KEY}
 *    Метод: GET
 *    Пример: iptables.php?action=list6&api=1&api_key=ваш_ключ
 * 
 * 5. Удаление всех правил блокировки
 *    URL: iptables.php?action=clear&api=1&api_key={YOUR_API_KEY}
 *    Метод: GET
 *    Пример: iptables.php?action=clear&api=1&api_key=ваш_ключ
 * 
 * 6. Режим отладки (получение всех правил iptables)
 *    URL: iptables.php?action=debug&api=1&api_key={YOUR_API_KEY}
 *    Метод: GET
 *    Пример: iptables.php?action=debug&api=1&api_key=ваш_ключ
 * 
 * Все API-вызовы возвращают результат в формате JSON
 */

// Отключаем уведомления для совместимости со старыми версиями PHP
error_reporting(E_ALL & ~E_NOTICE);

// Подключаем файл настроек для получения API ключа
require_once 'settings.php';

// =====================================================================
// НАСТРОЙКА РАСПРЕДЕЛЕНИЯ НАГРУЗКИ ДЛЯ API
// =====================================================================

// Настройки распределения нагрузки - используем значения из settings.php, если они определены
$load_balancing_enabled = defined('LOAD_BALANCING_ENABLED') ? LOAD_BALANCING_ENABLED : true;
$max_concurrent_requests = defined('MAX_CONCURRENT_REQUESTS') ? MAX_CONCURRENT_REQUESTS : 20;
$request_processing_delay = defined('REQUEST_PROCESSING_DELAY') ? REQUEST_PROCESSING_DELAY : 0;
$dynamic_delay_enabled = defined('DYNAMIC_DELAY_ENABLED') ? DYNAMIC_DELAY_ENABLED : true;
$load_threshold = defined('LOAD_THRESHOLD') ? LOAD_THRESHOLD : 4.0; // порог загрузки CPU
$max_dynamic_delay = defined('MAX_DYNAMIC_DELAY') ? MAX_DYNAMIC_DELAY : 100000; // 0.1 секунды в микросекундах
$sem_key_path = defined('SEM_KEY_PATH') ? SEM_KEY_PATH : __FILE__;
$load_tracking_file = defined('LOAD_TRACKING_FILE') ? LOAD_TRACKING_FILE : '/tmp/iptables_load_tracking';

/**
 * Получает текущую нагрузку на сервер
 * @return float Текущая загрузка CPU (среднее за 1 минуту)
 */
function getServerLoad() {
    if (function_exists('sys_getloadavg')) {
        $load = sys_getloadavg();
        return $load[0]; // значение за 1 минуту
    }
    return 0; // если функция недоступна
}

/**
 * Определяет задержку обработки в зависимости от нагрузки
 * @return int Задержка в микросекундах
 */
function calculateDynamicDelay($threshold, $max_delay) {
    $load = getServerLoad();
    
    if ($load <= $threshold) {
        return 0; // нет задержки при низкой нагрузке
    }
    
    // Рассчитываем задержку пропорционально превышению порога
    // Чем выше нагрузка, тем больше задержка, но не более max_delay
    $factor = ($load - $threshold) / $threshold;
    $delay = (int)($factor * $max_delay);
    
    return min($delay, $max_delay);
}

/**
 * Управляет количеством одновременных запросов с помощью семафоров
 * @param bool $acquire true для получения доступа, false для освобождения
 * @return bool Успешность операции
 */
function manageConcurrentRequests($acquire, $max_requests, $sem_key_path) {
    static $semaphore = null;
    
    // Проверяем поддержку семафоров
    if (!extension_loaded('sysvsem')) {
        return true; // если расширение не доступно, пропускаем контроль
    }
    
    // Создаем семафор при первом вызове
    if ($semaphore === null) {
        $sem_key = ftok($sem_key_path, 'i');
        $semaphore = sem_get($sem_key, $max_requests);
        
        if (!$semaphore) {
            error_log("Не удалось создать семафор");
            return true; // продолжаем без контроля, если не удалось создать семафор
        }
    }
    
    // Управляем доступом
    if ($acquire) {
        return sem_acquire($semaphore, true); // неблокирующий режим
    } else {
        return sem_release($semaphore);
    }
}

/**
 * Отслеживает и регулирует скорость обработки запросов
 * @return void
 */
function trackRequestRate() {
    global $load_tracking_file;
    
    // Создаем или обновляем файл отслеживания
    $now = microtime(true);
    $tracking_data = array(
        'timestamp' => $now,
        'request_count' => 1,
        'load' => getServerLoad()
    );
    
    // Пытаемся получить предыдущие данные
    if (file_exists($load_tracking_file)) {
        $content = @file_get_contents($load_tracking_file);
        if ($content) {
            $previous_data = json_decode($content, true);
            if (is_array($previous_data)) {
                // Если прошло менее 1 секунды, увеличиваем счетчик
                if (($now - $previous_data['timestamp']) < 1.0) {
                    $tracking_data['request_count'] = $previous_data['request_count'] + 1;
                }
            }
        }
    }
    
    // Сохраняем обновленные данные
    @file_put_contents($load_tracking_file, json_encode($tracking_data));
    
    // Логируем статистику каждые 100 запросов
    if ($tracking_data['request_count'] % 100 === 0) {
        error_log("API статистика: {$tracking_data['request_count']} запросов/сек, нагрузка: {$tracking_data['load']}");
    }
}

/**
 * Применяет стратегию распределения нагрузки
 * @return bool true если запрос может быть обработан немедленно, false если нужно поставить в очередь
 */
function applyLoadBalancing() {
    global $load_balancing_enabled, $max_concurrent_requests, $request_processing_delay, 
           $dynamic_delay_enabled, $load_threshold, $max_dynamic_delay, $sem_key_path;
    
    if (!$load_balancing_enabled) {
        return true;
    }
    
    // Отслеживаем статистику запросов
    trackRequestRate();
    
    // Пытаемся получить доступ через семафор
    if (!manageConcurrentRequests(true, $max_concurrent_requests, $sem_key_path)) {
        // Задержка, если превышен лимит одновременных запросов
        usleep(10000); // 10 мс
    }
    
    // Применяем базовую задержку для всех запросов, если указана
    if ($request_processing_delay > 0) {
        usleep($request_processing_delay);
    }
    
    // Применяем динамическую задержку в зависимости от нагрузки
    if ($dynamic_delay_enabled) {
        $dynamic_delay = calculateDynamicDelay($load_threshold, $max_dynamic_delay);
        if ($dynamic_delay > 0) {
            usleep($dynamic_delay);
        }
    }
    
    return true;
}

// =====================================================================
// НАСТРОЙКА БЕЗОПАСНОСТИ - ИСПОЛЬЗУЕМ НАСТРОЙКИ ИЗ settings.php
// =====================================================================

// Используем ключ API из settings.php
$valid_api_key = defined('API_BLOCK_KEY') ? API_BLOCK_KEY : 'api-key';

// Список разрешенных IP-адресов (необязательно, если используется API ключ)
$allowed_ips = array(
    // '192.168.1.100',  // Разрешенный IP 1
    // '10.0.0.5',       // Разрешенный IP 2
    '127.0.0.1'          // Локальный доступ (можно удалить, если не нужен)
);

// Параметр для включения/отключения защиты по IP (true - включено, false - отключено)
$enable_ip_restriction = true;

// =====================================================================
// ФУНКЦИИ БЕЗОПАСНОСТИ
// =====================================================================

// Функция для безопасного получения значения из массива
function safe_get($array, $key, $default = '') {
    return isset($array[$key]) ? $array[$key] : $default;
}

// Получение IP-адреса пользователя
function getUserIP() {
    // Проверяем наличие прокси
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        // Если несколько IP через запятую, берем первый
        if (strpos($ip, ',') !== false) {
            $ip = trim(explode(',', $ip)[0]);
        }
    } elseif (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return $ip;
}

// Проверка API ключа и/или IP-адреса
function checkAccess($valid_api_key, $allowed_ips, $enable_ip_restriction) {
    // Получаем API ключ из GET или POST параметров
    $api_key = safe_get($_REQUEST, 'api_key', '');
    
    // Проверяем API ключ
    $api_key_valid = ($api_key === $valid_api_key);
    
    // Если API ключ валидный, разрешаем доступ без дальнейших проверок
    if ($api_key_valid) {
        return true;
    }
    
    // Если включена проверка по IP, проверяем IP-адрес
    if ($enable_ip_restriction) {
        $user_ip = getUserIP();
        if (in_array($user_ip, $allowed_ips)) {
            return true;
        }
    }
    
    // Если ни API ключ, ни IP не подошли, запрещаем доступ
    return false;
}

// Выполняем проверку доступа
if (!checkAccess($valid_api_key, $allowed_ips, $enable_ip_restriction)) {
    header("HTTP/1.1 403 Forbidden");
    echo "Доступ запрещен. Требуется авторизация.";
    exit;
}

// =====================================================================
// ПРОВЕРКА РЕЖИМА API
// =====================================================================

// Проверяем, нужно ли вернуть JSON (для API)
$api_mode = isset($_GET['api']) && $_GET['api'] == 1;

// Устанавливаем заголовок в зависимости от режима
if ($api_mode) {
    header('Content-Type: application/json');
    
    // Применяем стратегию распределения нагрузки для API запросов
    applyLoadBalancing();
    
    // Регистрируем функцию освобождения семафора при завершении запроса
    register_shutdown_function(function() use ($max_concurrent_requests, $sem_key_path) {
        manageConcurrentRequests(false, $max_concurrent_requests, $sem_key_path);
    });
}

// =====================================================================
// ОСНОВНЫЕ ФУНКЦИИ IPTABLES
// =====================================================================

// Функция для блокировки IP-адреса
function blockIP($ip) {
    // Проверяем валидность IP-адреса
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return array('status' => 'error', 'message' => "Неверный формат IP-адреса: $ip");
    }
    
    // Защита от инъекций - проверяем, что IP содержит только допустимые символы
    if (!preg_match('/^[0-9a-fA-F:\.]+$/', $ip)) {
        return array('status' => 'error', 'message' => "Недопустимые символы в IP-адресе");
    }
    
    // Определяем версию IP
    $isIPv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    
    // Массив для хранения результатов
    $results = array();
    $success = true;
    
    // Блокируем порты 80 и 443
    $ports = array(80, 443);
    
    // Записываем в лог исходный IP для отладки
    error_log("Блокирую IP: $ip, IPv6: " . ($isIPv6 ? "да" : "нет"));
    
    foreach ($ports as $port) {
        // Формируем команду в зависимости от версии IP
        if ($isIPv6) {
            $commandCheck = "sudo ip6tables -C INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
            $command = "sudo ip6tables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
        } else {
            $commandCheck = "sudo iptables -C INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
            $command = "sudo iptables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
        }
        
        // Записываем команды в лог для отладки
        error_log("Команда проверки: $commandCheck");
        error_log("Команда блокировки: $command");
        
        // Проверяем, не блокирован ли уже IP для этого порта
        $returnVar = 0;
        $output = array();
        exec($commandCheck, $output, $returnVar);
        
        // Если команда проверки вернула 0, значит правило уже существует
        if ($returnVar === 0) {
            $results[] = "Порт $port: IP уже заблокирован";
            continue;
        }
        
        // Выполняем команду блокировки
        $output = array();
        $returnVar = 0;
        exec($command, $output, $returnVar);
        
        // Записываем результат в лог
        error_log("Результат блокировки порта $port: " . $returnVar . ", вывод: " . implode(", ", $output));
        
        // Проверяем результат выполнения
        if ($returnVar !== 0) {
            $results[] = "Порт $port: Ошибка блокировки";
            $success = false;
        } else {
            $results[] = "Порт $port: Блокировка успешна";
        }
    }
    
    // Сохраняем правила для сохранения после перезагрузки
    if ($success) {
        saveRules($isIPv6);
    }
    
    // Формируем сообщение в зависимости от успешности операций
    if ($success) {
        return array(
            'status' => 'success', 
            'message' => "IP-адрес $ip успешно заблокирован для портов 80 и 443",
            'details' => implode(", ", $results)
        );
    } else {
        return array(
            'status' => 'error', 
            'message' => "Ошибка при блокировке IP-адреса: $ip", 
            'details' => implode(", ", $results)
        );
    }
}

// Функция для разблокировки IP-адреса
function unblockIP($ip) {
    // Проверяем валидность IP-адреса и учитываем возможность CIDR-нотации
    $is_cidr = strpos($ip, '/') !== false;
    $ip_for_validation = $is_cidr ? substr($ip, 0, strpos($ip, '/')) : $ip;
    
    if (!$is_cidr && !filter_var($ip_for_validation, FILTER_VALIDATE_IP)) {
        return array('status' => 'error', 'message' => "Неверный формат IP-адреса: $ip");
    }
    
    // Защита от инъекций - проверяем, что IP содержит только допустимые символы
    if (!preg_match('/^[0-9a-fA-F:\.\/]+$/', $ip)) {
        return array('status' => 'error', 'message' => "Недопустимые символы в IP-адресе");
    }
    
    // Определяем версию IP
    $isIPv6 = strpos($ip, ':') !== false || 
              (!$is_cidr && filter_var($ip_for_validation, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6));
    
    // Массив для хранения результатов
    $results = array();
    $allSuccess = true;
    
    // Проверка для ::/0 (что означает все IPv6 адреса)
    if ($ip === "::/0" && $isIPv6) {
        // Попробуем использовать конкретный IPv6 адрес вместо ::/0
        $test_ip = "2a00:1e20:11:fcea:1a09:ee3a:6bcb:5f6f";
        $output = array();
        exec("sudo ip6tables -L INPUT -n -v | grep -i '$test_ip'", $output);
        
        if (!empty($output)) {
            // Используем найденный IPv6 вместо ::/0
            $ip = $test_ip;
            $results[] = "Разблокировка переключена с ::/0 на $test_ip";
        }
    }
    
    // Логируем действие разблокировки
    error_log("Разблокирую IP: $ip, IPv6: " . ($isIPv6 ? "да" : "нет"));
    
    // Порты для разблокировки
    $ports = array(80, 443);
    
    foreach ($ports as $port) {
        // Формируем команду в зависимости от версии IP
        if ($isIPv6) {
            $command = "sudo ip6tables -D INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
        } else {
            $command = "sudo iptables -D INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
        }
        
        // Логируем команду
        error_log("Команда разблокировки: $command");
        
        // Выполняем команду
        $output = array();
        $returnVar = 0;
        exec($command, $output, $returnVar);
        
        // Логируем результат
        error_log("Результат разблокировки порта $port: " . $returnVar . ", вывод: " . implode(", ", $output));
        
        // Проверяем результат выполнения
        if ($returnVar !== 0) {
            $results[] = "Порт $port: Ошибка разблокировки";
            $allSuccess = false;
        } else {
            $results[] = "Порт $port: Разблокировка успешна";
        }
    }
    
    // Пытаемся разблокировать также общее правило (для совместимости со старыми версиями)
    if ($isIPv6) {
        $command = "sudo ip6tables -D INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null";
    } else {
        $command = "sudo iptables -D INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null";
    }
    
    // Выполняем команду не проверяя результат (это только для совместимости)
    exec($command);
    
    // Сохраняем правила для сохранения после перезагрузки
    saveRules($isIPv6);
    
    // Формируем сообщение в зависимости от успешности операций
    if ($allSuccess) {
        return array(
            'status' => 'success', 
            'message' => "IP-адрес $ip успешно разблокирован для портов 80 и 443",
            'details' => implode(", ", $results)
        );
    } else {
        return array(
            'status' => 'warning', 
            'message' => "Частичная разблокировка IP-адреса: $ip", 
            'details' => implode(", ", $results)
        );
    }
}

// Функция для удаления всех правил блокировки
function clearAllRules() {
    $results = array();
    $success = true;
    
    // Массив для хранения всех найденных IP-адресов
    $ipv4Addresses = array();
    $ipv6Addresses = array();
    
    // Получаем список заблокированных IPv4
    $ipv4List = listBlockedIPs(4);
    if ($ipv4List['status'] === 'success' && isset($ipv4List['blocked_ips'])) {
        $ipv4Addresses = $ipv4List['blocked_ips'];
    }
    
    // Получаем список заблокированных IPv6
    $ipv6List = listBlockedIPs(6);
    if ($ipv6List['status'] === 'success' && isset($ipv6List['blocked_ips'])) {
        $ipv6Addresses = $ipv6List['blocked_ips'];
    }
    
    // Разблокируем каждый IPv4 адрес
    foreach ($ipv4Addresses as $ip) {
        $result = unblockIP($ip);
        if ($result['status'] !== 'success') {
            $success = false;
            $results[] = "Ошибка при разблокировке IPv4: $ip";
        } else {
            $results[] = "IPv4 $ip успешно разблокирован";
        }
    }
    
    // Разблокируем каждый IPv6 адрес
    foreach ($ipv6Addresses as $ip) {
        $result = unblockIP($ip);
        if ($result['status'] !== 'success') {
            $success = false;
            $results[] = "Ошибка при разблокировке IPv6: $ip";
        } else {
            $results[] = "IPv6 $ip успешно разблокирован";
        }
    }
    
    // Для случая, если есть правила, которые не были захвачены в списках
    // Выполняем дополнительную очистку
    
    // Очистка IPv4 правил для портов 80 и 443
    $portsToClean = array(80, 443);
    
    foreach ($portsToClean as $port) {
        // Пока есть правила, продолжаем удалять
        $continueDeleting = true;
        $maxIterations = 50; // Предотвращаем бесконечный цикл
        $iterations = 0;
        
        while ($continueDeleting && $iterations < $maxIterations) {
            $iterations++;
            
            // Пытаемся найти первое правило для порта
            $output = array();
            exec("sudo iptables -L INPUT -n --line-numbers | grep 'tcp dpt:$port' | head -n 1", $output);
            
            if (!empty($output) && preg_match('/^(\d+).*DROP.*tcp dpt:' . $port . '/', $output[0], $matches)) {
                $ruleNum = $matches[1];
                exec("sudo iptables -D INPUT $ruleNum", $outputCmd, $returnVar);
                if ($returnVar !== 0) {
                    $success = false;
                    $results[] = "Ошибка удаления правила для IPv4 порт $port (#$ruleNum)";
                    $continueDeleting = false;
                }
            } else {
                $continueDeleting = false;
            }
        }
        
        // То же самое для IPv6
        $continueDeleting = true;
        $iterations = 0;
        
        while ($continueDeleting && $iterations < $maxIterations) {
            $iterations++;
            
            // Пытаемся найти первое правило для порта
            $output = array();
            exec("sudo ip6tables -L INPUT -n --line-numbers | grep 'tcp dpt:$port' | head -n 1", $output);
            
            if (!empty($output) && preg_match('/^(\d+).*DROP.*tcp dpt:' . $port . '/', $output[0], $matches)) {
                $ruleNum = $matches[1];
                exec("sudo ip6tables -D INPUT $ruleNum", $outputCmd, $returnVar);
                if ($returnVar !== 0) {
                    $success = false;
                    $results[] = "Ошибка удаления правила для IPv6 порт $port (#$ruleNum)";
                    $continueDeleting = false;
                }
            } else {
                $continueDeleting = false;
            }
        }
    }
    
    // Сохраняем правила
    saveRules(false); // IPv4
    saveRules(true);  // IPv6
    
    // Если не было найдено IP-адресов и все дополнительные очистки прошли успешно
    if (empty($ipv4Addresses) && empty($ipv6Addresses) && $success) {
        $results[] = "Не найдено заблокированных IP-адресов, но все правила очищены";
    }
    
    // Формируем сообщение
    if ($success) {
        return array(
            'status' => 'success', 
            'message' => "Все правила блокировки успешно удалены",
            'details' => implode(", ", $results)
        );
    } else {
        return array(
            'status' => 'warning', 
            'message' => "Некоторые правила не удалось удалить", 
            'details' => implode(", ", $results)
        );
    }
}

// Функция для отображения списка заблокированных IP-адресов
function listBlockedIPs($version) {
    // Массив для хранения заблокированных IP-адресов и портов
    $blockedIPs = array();
    $blockedIPsDetails = array(); // Для хранения деталей блокировки
    
    // Добавим дополнительное логирование для отладки
    $debug_output = array();
    
    // Получаем прямой список IP с конкретными правилами блокировки
    if ($version === 6) {
        // Для IPv6 пробуем получить конкретные блокировки
        $command = "sudo ip6tables -S INPUT | grep '\-A INPUT \-s' | grep '\-j DROP'";
    } else {
        // Для IPv4 пробуем получить конкретные блокировки
        $command = "sudo iptables -S INPUT | grep '\-A INPUT \-s' | grep '\-j DROP'";
    }
    
    $output = array();
    $returnVar = 0;
    exec($command, $output, $returnVar);
    $debug_output[] = "Команда списка правил: $command";
    $debug_output[] = "Вывод: " . implode("\n", $output);
    
    // Обрабатываем вывод
    foreach ($output as $line) {
        // Игнорируем 0.0.0.0/0 и ::/0 (все адреса)
        if (strpos($line, " -s 0.0.0.0/0 ") !== false || strpos($line, " -s ::/0 ") !== false) {
            continue;
        }
        
        // Пытаемся извлечь IP-адрес и порт
        if (preg_match('/\-s\s+([0-9a-fA-F:\.\/]+)\s+.*\-p\s+tcp\s+.*\-\-dport\s+(\d+)/', $line, $matches)) {
            $ip = $matches[1];
            $port = $matches[2];
            
            // Игнорируем 0.0.0.0/0 и ::/0 (проверка после извлечения)
            if ($ip === "0.0.0.0/0" || $ip === "::/0") {
                continue;
            }
            
            if (!isset($blockedIPsDetails[$ip])) {
                $blockedIPsDetails[$ip] = array(
                    'ip' => $ip,
                    'ports' => array()
                );
                $blockedIPs[] = $ip;
            }
            
            if (!in_array($port, $blockedIPsDetails[$ip]['ports'])) {
                $blockedIPsDetails[$ip]['ports'][] = $port;
            }
        }
    }
    
    // Если блокировок не найдено, пробуем специальную команду для поиска
    if (empty($blockedIPs)) {
        // Пробуем получить список через прямой вывод правил
        $command = ($version === 6) ? 
            "sudo ip6tables -L INPUT -n -v" : 
            "sudo iptables -L INPUT -n -v";
        
        $output = array();
        $returnVar = 0;
        exec($command, $output, $returnVar);
        
        $debug_output[] = "Команда вывода правил: $command";
        $debug_output[] = "Вывод: " . implode("\n", $output);
        
        // Анализируем каждую строку
        foreach ($output as $line) {
            // Игнорируем строки с 0.0.0.0/0 или ::/0
            if (strpos($line, "0.0.0.0/0") !== false || strpos($line, "::/0") !== false) {
                continue;
            }
            
            // Для IPv4
            if ($version !== 6 && preg_match('/DROP\s+.*tcp\s+.*dpt:(\d+).*?(\d+\.\d+\.\d+\.\d+(?:\/\d+)?)/', $line, $matches)) {
                $port = $matches[1];
                $ip = $matches[2];
                
                // Дополнительная проверка IP
                if ($ip === "0.0.0.0/0") continue;
                
                if (!isset($blockedIPsDetails[$ip])) {
                    $blockedIPsDetails[$ip] = array(
                        'ip' => $ip,
                        'ports' => array()
                    );
                    $blockedIPs[] = $ip;
                }
                
                if (!in_array($port, $blockedIPsDetails[$ip]['ports'])) {
                    $blockedIPsDetails[$ip]['ports'][] = $port;
                }
            }
            // Для IPv6
            else if ($version === 6 && preg_match('/DROP\s+.*tcp\s+.*dpt:(\d+).*?([0-9a-fA-F:]+(?:\/\d+)?)/', $line, $matches)) {
                $port = $matches[1];
                $ip = $matches[2];
                
                // Дополнительная проверка IP
                if ($ip === "::/0") continue;
                
                if (!isset($blockedIPsDetails[$ip])) {
                    $blockedIPsDetails[$ip] = array(
                        'ip' => $ip,
                        'ports' => array()
                    );
                    $blockedIPs[] = $ip;
                }
                
                if (!in_array($port, $blockedIPsDetails[$ip]['ports'])) {
                    $blockedIPsDetails[$ip]['ports'][] = $port;
                }
            }
        }
    }
    
    // Если все ещё пусто, и это IPv6, проверяем целевой IP
    if (empty($blockedIPs) && $version === 6) {
        // Проверяем конкретный IP адрес
        $testIPs = array("2a00:1e20:11:fcea:1a09:ee3a:6bcb:5f6f", "2a00:1e20:11:fcea:d0b3:86ef:ec7a:5fb7");
        
        foreach ($testIPs as $testIP) {
            $command = "sudo ip6tables-save | grep -i '$testIP'";
            $output = array();
            exec($command, $output, $returnVar);
            
            $debug_output[] = "Тестирование IP $testIP: " . implode("\n", $output);
            
            foreach ($output as $line) {
                if (preg_match('/\-A INPUT \-s (' . preg_quote($testIP, '/') . '(?:\/\d+)?)\s+.*\-p tcp \-\-dport (\d+)/', $line, $matches)) {
                    $ip = $matches[1];
                    $port = $matches[2];
                    
                    if (!isset($blockedIPsDetails[$ip])) {
                        $blockedIPsDetails[$ip] = array(
                            'ip' => $ip,
                            'ports' => array()
                        );
                        $blockedIPs[] = $ip;
                    }
                    
                    if (!in_array($port, $blockedIPsDetails[$ip]['ports'])) {
                        $blockedIPsDetails[$ip]['ports'][] = $port;
                    }
                }
            }
        }
    }
    
    // Преобразуем ассоциативный массив в обычный
    $detailsList = array_values($blockedIPsDetails);
    
    error_log("DEBUG ListBlockedIPs v$version: " . implode("\n", $debug_output));
    
    // Возвращаем результат
    return array(
        'status' => 'success',
        'version' => "IPv$version", 
        'count' => count($blockedIPs),
        'blocked_ips' => $blockedIPs,
        'blocked_details' => $detailsList,
        'debug' => implode("<br>", $debug_output)
    );
}

// Функция для сохранения правил iptables
function saveRules($isIPv6) {
    $distro = getLinuxDistribution();
    
    // На основе дистрибутива выбираем метод сохранения правил
    switch ($distro) {
        case 'ubuntu':
        case 'debian':
            // Для Ubuntu/Debian используем iptables-save
            $command = $isIPv6 ? 
                "sudo sh -c 'ip6tables-save > /etc/iptables/rules.v6'" : 
                "sudo sh -c 'iptables-save > /etc/iptables/rules.v4'";
            break;
            
        case 'centos':
        case 'fedora':
        case 'rhel':
            // Для CentOS/RHEL/Fedora используем service iptables save
            $command = $isIPv6 ? 
                "sudo service ip6tables save" : 
                "sudo service iptables save";
            break;
            
        default:
            // Для других дистрибутивов используем iptables-save
            $command = $isIPv6 ? 
                "sudo sh -c 'ip6tables-save > /etc/iptables/rules.v6'" : 
                "sudo sh -c 'iptables-save > /etc/iptables/rules.v4'";
    }
    
    // Пытаемся создать директорию, если она не существует
    if (in_array($distro, array('ubuntu', 'debian')) || $distro === 'default') {
        exec('sudo mkdir -p /etc/iptables 2>/dev/null');
    }
    
    $output = array();
    $returnVar = 0;
    exec($command, $output, $returnVar);
    
    // Проверяем результат выполнения, но не возвращаем ошибку, так как блокировка уже прошла успешно
    if ($returnVar !== 0) {
        error_log("Предупреждение: Не удалось сохранить правила iptables");
    }
    
    return true;
}

// Функция для определения дистрибутива Linux
function getLinuxDistribution() {
    // Пытаемся использовать lsb_release
    $output = array();
    exec('lsb_release -i 2>/dev/null', $output);
    
    if (!empty($output)) {
        $distro = strtolower(trim(str_replace('Distributor ID:', '', $output[0])));
        return $distro;
    }
    
    // Проверяем файлы release
    if (file_exists('/etc/debian_version')) return 'debian';
    if (file_exists('/etc/redhat-release')) return 'rhel';
    if (file_exists('/etc/fedora-release')) return 'fedora';
    if (file_exists('/etc/centos-release')) return 'centos';
    
    // Проверяем os-release
    if (file_exists('/etc/os-release')) {
        $content = file_get_contents('/etc/os-release');
        if (preg_match('/NAME="?([^"]+)"?/i', $content, $matches)) {
            $osName = strtolower($matches[1]);
            if (strpos($osName, 'ubuntu') !== false) return 'ubuntu';
            if (strpos($osName, 'debian') !== false) return 'debian';
            if (strpos($osName, 'centos') !== false) return 'centos';
            if (strpos($osName, 'fedora') !== false) return 'fedora';
            if (strpos($osName, 'red hat') !== false) return 'rhel';
        }
    }
    
    // По умолчанию предполагаем Ubuntu
    return 'ubuntu';
}

// Обработка действий, если они переданы
$result = null;
$action = safe_get($_REQUEST, 'action', '');
if ($action) {
    $action = strtolower($action);
    
    switch ($action) {
        case 'block':
            if (isset($_REQUEST['ip'])) {
                $ip = $_REQUEST['ip'];
                $result = blockIP($ip);
            } else {
                $result = array('status' => 'error', 'message' => 'Не указан IP-адрес для блокировки');
            }
            break;
            
        case 'unblock':
            if (isset($_REQUEST['ip'])) {
                $ip = $_REQUEST['ip'];
                $result = unblockIP($ip);
            } else {
                $result = array('status' => 'error', 'message' => 'Не указан IP-адрес для разблокировки');
            }
            break;
            
        case 'list':
            $result = listBlockedIPs(4);
            break;
            
        case 'list6':
            $result = listBlockedIPs(6);
            break;
            
        case 'clear':
            $result = clearAllRules();
            break;
            
        case 'debug':
            // Режим отладки - вывести текущие iptables правила
            $output = array();
            exec("sudo iptables -L INPUT -n -v", $output);
            $ipv4Rules = implode("<br>", $output);
            
            $output = array();
            exec("sudo ip6tables -L INPUT -n -v", $output);
            $ipv6Rules = implode("<br>", $output);
            
            // Дополнительно запрашиваем вывод через ip6tables-save
            $output = array();
            exec("sudo ip6tables-save | grep -i 'DROP'", $output);
            $ipv6SaveRules = implode("<br>", $output);
            
            // Проверяем конкретные правила для 2a00:1e20:11:fcea:1a09:ee3a:6bcb:5f6f
            $test_ip = "2a00:1e20:11:fcea:1a09:ee3a:6bcb:5f6f";
            $output = array();
            exec("sudo ip6tables -L INPUT -n -v | grep -i '$test_ip'", $output);
            $specificIpv6 = implode("<br>", $output);
            
            $result = array(
                'status' => 'success',
                'message' => 'Текущие правила iptables',
                'details' => "<h4>IPv4 правила:</h4>{$ipv4Rules}<br><br>" .
                             "<h4>IPv6 правила:</h4>{$ipv6Rules}<br><br>" .
                             "<h4>IPv6 (ip6tables-save):</h4>{$ipv6SaveRules}<br><br>" .
                             "<h4>Поиск IPv6 $test_ip:</h4>{$specificIpv6}<br><br>"
            );
            break;
            
        default:
            $result = array('status' => 'error', 'message' => 'Неизвестное действие');
    }
}

// Если в API режиме, сразу возвращаем результат
if ($api_mode && $result) {
    echo json_encode($result);
    exit;
}

// Загружаем списки IP-адресов при первой загрузке страницы
$ipv4List = listBlockedIPs(4);
$ipv6List = listBlockedIPs(6);

// Получаем IP-адрес пользователя - уже определена ранее

$userIP = getUserIP();

// В противном случае показываем HTML-интерфейс
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Управление блокировкой IP-адресов</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            overflow-x: hidden; /* Предотвращает горизонтальную прокрутку */
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"] {
            width: 300px;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .btn {
            padding: 8px 15px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 5px;
        }
        .btn-danger {
            background: #f44336;
        }
        .btn-info {
            background: #2196F3;
        }
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .alert-success {
            background-color: #dff0d8;
            border: 1px solid #d6e9c6;
            color: #3c763d;
        }
        .alert-warning {
            background-color: #fcf8e3;
            border: 1px solid #faebcc;
            color: #8a6d3b;
        }
        .alert-danger {
            background-color: #f2dede;
            border: 1px solid #ebccd1;
            color: #a94442;
        }
        .details-info {
            margin-top: 10px;
            font-size: 0.9em;
            padding: 5px;
            background-color: rgba(255, 255, 255, 0.3);
            border-radius: 3px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        table, th, td {
            border: 1px solid #ddd;
        }
        th, td {
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        .ip-list {
            margin-top: 30px;
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid #ddd;
        }
        .tab {
            padding: 10px 15px;
            cursor: pointer;
            background-color: #f1f1f1;
            margin-right: 2px;
            border-radius: 5px 5px 0 0;
        }
        @media (max-width: 768px) {
            .tabs {
                display: flex;
                width: 100%;
            }
            .tab {
                flex: 1;
                text-align: center;
                padding: 10px 5px;
                margin-right: 1px;
                white-space: nowrap;
            }
            input[type="text"] {
                width: 100%;
                box-sizing: border-box;
            }
            .btn {
                display: block;
                width: 100%;
                margin-bottom: 5px;
                box-sizing: border-box;
                text-align: center;
            }
        }
        .tab.active {
            background-color: #4CAF50;
            color: white;
        }
        .tab-content {
            display: none;
            padding: 15px;
            border: 1px solid #ddd;
            border-top: none;
        }
        .tab-content.active {
            display: block;
        }
        .ip-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px;
            border-bottom: 1px solid #eee;
            flex-wrap: wrap;
        }
        .ip-details {
            display: flex;
            flex-direction: column;
            word-break: break-all; /* Для корректного отображения длинных IPv6 */
            max-width: 70%;
        }
        @media (max-width: 768px) {
            .ip-item {
                flex-direction: column;
                align-items: flex-start;
            }
            .ip-details {
                max-width: 100%;
                margin-bottom: 10px;
            }
            .ip-actions {
                width: 100%;
            }
            .ip-actions button {
                width: 100%;
                margin-top: 5px;
            }
        }
        .ip-address {
            font-weight: bold;
        }
        .ip-ports {
            font-size: 0.9em;
            color: #666;
            margin-top: 4px;
        }
        .ip-item:last-child {
            border-bottom: none;
        }
        .ip-actions {
            display: flex;
        }
        .ip-actions button {
            margin-left: 5px;
        }
        .ip-list-container {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid #eee;
            margin-top: 10px;
        }
        .refresh-button {
            display: inline-block;
            margin-left: 10px;
            font-size: 18px;
            cursor: pointer;
        }
        .stats {
            margin-top: 20px;
            padding: 10px;
            background-color: #f9f9f9;
            border-radius: 4px;
            border: 1px solid #ddd;
        }
        .box-title {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        /* Стили для мобильных устройств */
        @media (max-width: 768px) {
            .box-title {
                flex-direction: column;
                align-items: flex-start;
            }
            .box-title div {
                margin-top: 10px;
                display: flex;
                flex-wrap: wrap;
                gap: 5px;
                width: 100%;
            }
            .box-title a.btn {
                flex: 1;
                text-align: center;
                margin-right: 0 !important;
            }
            .refresh-button {
                flex: 0 0 auto;
            }
        }
        .user-ip-box {
            background-color: #e8f5e9;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
            border: 1px solid #c8e6c9;
            overflow-wrap: break-word; /* Для переноса длинных строк */
        }
        .ip-info {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
        }
        /* Стили для мобильных устройств */
        @media (max-width: 768px) {
            .ip-info {
                flex-direction: column;
                align-items: flex-start;
            }
            .ip-info span {
                word-break: break-all; /* Разрешаем перенос длинных IP-адресов */
                max-width: 100%;
                margin-bottom: 10px;
            }
            .ip-info button {
                width: 100%;
            }
        }
        .api-alert {
            background-color: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
            padding: 10px 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Управление блокировкой IP-адресов</h1>
        
        <?php if ($valid_api_key === 'ваш_секретный_ключ_здесь'): ?>
        <div class="api-alert">
            <strong>Внимание!</strong> Для обеспечения безопасности необходимо изменить API ключ в файле settings.php.
        </div>
        <?php endif; ?>
        
        <div class="user-ip-box">
            <div class="ip-info">
                <strong>Ваш IP-адрес:</strong> <span id="userIP"><?php echo htmlspecialchars($userIP); ?></span>
                <button onclick="blockCurrentIP()" class="btn">Заблокировать мой IP</button>
            </div>
        </div>
        
        <?php if ($result): ?>
            <div class="alert alert-<?php echo $result['status'] === 'success' ? 'success' : ($result['status'] === 'warning' ? 'warning' : 'danger'); ?>">
                <?php echo htmlspecialchars($result['message']); ?>
                <?php if (isset($result['details'])): ?>
                    <div class="details-info">
                        <?php echo $result['details']; ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('block')">Блокировка IP</div>
            <div class="tab" onclick="switchTab('list')">Заблокированные IP</div>
        </div>
        
        <div id="block-tab" class="tab-content active">
            <h2>Блокировка/Разблокировка IP</h2>
            <form method="post" action="">
                <div class="form-group">
                    <label for="ip">IP-адрес:</label>
                    <input type="text" id="ip" name="ip" placeholder="Введите IPv4 или IPv6 адрес" required>
                    <!-- Скрытое поле для API ключа -->
                    <input type="hidden" name="api_key" value="<?php echo htmlspecialchars($valid_api_key); ?>">
                </div>
                <div class="form-group">
                    <button type="submit" name="action" value="block" class="btn">Заблокировать IP</button>
                    <button type="submit" name="action" value="unblock" class="btn btn-danger">Разблокировать IP</button>
                </div>
            </form>
        </div>
        
        <div id="list-tab" class="tab-content">
            <div class="box-title">
                <h2>Заблокированные IP-адреса</h2>
                <div>
                    <a href="?action=debug&api_key=<?php echo urlencode($valid_api_key); ?>" class="btn btn-info" style="margin-right: 10px;">Показать правила</a>
                    <a href="?action=clear&api_key=<?php echo urlencode($valid_api_key); ?>" class="btn btn-danger" style="margin-right: 10px;" onclick="return confirm('Вы уверены, что хотите удалить ВСЕ правила блокировки для портов 80 и 443?');">Удалить все правила</a>
                    <span class="refresh-button" title="Обновить списки" onclick="refreshLists()">🔄</span>
                </div>
            </div>
            
            <div class="stats">
                <strong>Статистика блокировок:</strong> 
                IPv4: <span id="ipv4-count"><?php echo $ipv4List['count']; ?></span> | 
                IPv6: <span id="ipv6-count"><?php echo $ipv6List['count']; ?></span>
            </div>
            
            <h3>IPv4 адреса</h3>
            <div id="ipv4-list" class="ip-list">
                <?php if ($ipv4List['count'] > 0): ?>
                    <div class="ip-list-container">
                        <?php foreach ($ipv4List['blocked_details'] as $ipInfo): ?>
                            <div class="ip-item">
                                <div class="ip-details">
                                    <span class="ip-address"><?php echo htmlspecialchars($ipInfo['ip']); ?></span>
                                    <span class="ip-ports">
                                        Порты: <?php 
                                        if (in_array('all', $ipInfo['ports'])) {
                                            echo 'Все порты';
                                        } else {
                                            echo implode(', ', $ipInfo['ports']); 
                                        }
                                        ?>
                                    </span>
                                </div>
                                <div class="ip-actions">
                                    <form method="post" action="" style="display: inline;">
                                        <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ipInfo['ip']); ?>">
                                        <input type="hidden" name="api_key" value="<?php echo htmlspecialchars($valid_api_key); ?>">
                                        <button type="submit" name="action" value="unblock" class="btn btn-danger" style="padding: 4px 8px; font-size: 12px;">Разблокировать</button>
                                    </form>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <p>Заблокированных IPv4 адресов не найдено.</p>
                <?php endif; ?>
            </div>
            
            <h3>IPv6 адреса</h3>
            <div id="ipv6-list" class="ip-list">
                <?php if ($ipv6List['count'] > 0): ?>
                    <div class="ip-list-container">
                        <?php foreach ($ipv6List['blocked_details'] as $ipInfo): ?>
                            <div class="ip-item">
                                <div class="ip-details">
                                    <span class="ip-address"><?php echo htmlspecialchars($ipInfo['ip']); ?></span>
                                    <span class="ip-ports">
                                        Порты: <?php 
                                        if (in_array('all', $ipInfo['ports'])) {
                                            echo 'Все порты';
                                        } else {
                                            echo implode(', ', $ipInfo['ports']); 
                                        }
                                        ?>
                                    </span>
                                </div>
                                <div class="ip-actions">
                                    <form method="post" action="" style="display: inline;">
                                        <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ipInfo['ip']); ?>">
                                        <input type="hidden" name="api_key" value="<?php echo htmlspecialchars($valid_api_key); ?>">
                                        <button type="submit" name="action" value="unblock" class="btn btn-danger" style="padding: 4px 8px; font-size: 12px;">Разблокировать</button>
                                    </form>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <p>Заблокированных IPv6 адресов не найдено.</p>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <script>
        // Добавляем API ключ ко всем запросам
        var apiKey = "<?php echo htmlspecialchars(addslashes($valid_api_key)); ?>";
        
        function switchTab(tabName) {
            try {
                // Скрываем все вкладки и убираем класс active
                var tabs = document.querySelectorAll('.tab');
                var tabContents = document.querySelectorAll('.tab-content');
                
                for (var i = 0; i < tabs.length; i++) {
                    tabs[i].classList.remove('active');
                }
                
                for (var i = 0; i < tabContents.length; i++) {
                    tabContents[i].classList.remove('active');
                }
                
                // Активируем нужную вкладку
                var tabSelector = document.querySelector('[onclick="switchTab(\'' + tabName + '\')"]');
                if (tabSelector) {
                    tabSelector.classList.add('active');
                }
                
                var tabContent = document.getElementById(tabName + '-tab');
                if (tabContent) {
                    tabContent.classList.add('active');
                }
            } catch (e) {
                console.error('Ошибка при переключении вкладки:', e);
            }
        }
        
        function loadIPs(version, callback) {
            try {
                // Определяем действие в зависимости от версии IP
                var action = version === 6 ? 'list6' : 'list';
                
                // Создаем Ajax запрос
                var xhr = new XMLHttpRequest();
                xhr.open('GET', '?action=' + action + '&api=1&api_key=' + encodeURIComponent(apiKey), true);
                
                xhr.onload = function() {
                    if (xhr.status === 200) {
                        try {
                            var response = JSON.parse(xhr.responseText);
                            if (callback && typeof callback === 'function') {
                                callback(response);
                            }
                        } catch (e) {
                            console.error('Ошибка при разборе JSON:', e, xhr.responseText);
                        }
                    }
                };
                
                xhr.onerror = function() {
                    console.error('Ошибка при отправке запроса');
                };
                
                xhr.send();
            } catch (e) {
                console.error('Ошибка при загрузке IP:', e);
            }
        }
        
        function refreshLists() {
            try {
                // Обновляем IPv4
                loadIPs(4, function(data) {
                    updateIPList('ipv4', data);
                });
                
                // Обновляем IPv6
                loadIPs(6, function(data) {
                    updateIPList('ipv6', data);
                });
            } catch (e) {
                console.error('Ошибка при обновлении списков:', e);
            }
        }
        
        function updateIPList(type, data) {
            var ipListElement = document.getElementById(type + '-list');
            var countElement = document.getElementById(type + '-count');
            
            // Обновляем счетчик
            if (countElement) {
                countElement.textContent = data.count;
            }
            
            if (data.status === 'success') {
                if (data.count === 0) {
                    ipListElement.innerHTML = '<p>Заблокированных ' + data.version + ' адресов не найдено.</p>';
                    return;
                }
                
                var html = '<div class="ip-list-container">';
                
                // Используем blocked_details если доступно, иначе используем blocked_ips
                if (data.blocked_details && data.blocked_details.length > 0) {
                    for (var i = 0; i < data.blocked_details.length; i++) {
                        var ipInfo = data.blocked_details[i];
                        var portsText = '';
                        
                        if (ipInfo.ports.includes('all')) {
                            portsText = 'Все порты';
                        } else {
                            portsText = ipInfo.ports.join(', ');
                        }
                        
                        html += '<div class="ip-item">' +
                            '<div class="ip-details">' +
                            '<span class="ip-address">' + ipInfo.ip + '</span>' +
                            '<span class="ip-ports">Порты: ' + portsText + '</span>' +
                            '</div>' +
                            '<div class="ip-actions">' +
                            '<form method="post" action="" style="display: inline;">' +
                            '<input type="hidden" name="ip" value="' + ipInfo.ip + '">' +
                            '<input type="hidden" name="api_key" value="' + apiKey + '">' +
                            '<button type="submit" name="action" value="unblock" class="btn btn-danger" style="padding: 4px 8px; font-size: 12px;">Разблокировать</button>' +
                            '</form>' +
                            '</div>' +
                            '</div>';
                    }
                } else {
                    // Для обратной совместимости
                    for (var i = 0; i < data.blocked_ips.length; i++) {
                        var ip = data.blocked_ips[i];
                        html += '<div class="ip-item">' +
                            '<div class="ip-details">' +
                            '<span class="ip-address">' + ip + '</span>' +
                            '</div>' +
                            '<div class="ip-actions">' +
                            '<form method="post" action="" style="display: inline;">' +
                            '<input type="hidden" name="ip" value="' + ip + '">' +
                            '<input type="hidden" name="api_key" value="' + apiKey + '">' +
                            '<button type="submit" name="action" value="unblock" class="btn btn-danger" style="padding: 4px 8px; font-size: 12px;">Разблокировать</button>' +
                            '</form>' +
                            '</div>' +
                            '</div>';
                    }
                }
                
                html += '</div>';
                ipListElement.innerHTML = html;
            } else {
                ipListElement.innerHTML = '<p>Ошибка: ' + data.message + '</p>';
            }
        }
        
        function blockCurrentIP() {
            try {
                var userIP = document.getElementById('userIP').textContent;
                if (confirm('Вы уверены, что хотите заблокировать свой IP-адрес (' + userIP + ')?\nЭто может привести к потере доступа к сайту!')) {
                    // Создаем и отправляем форму
                    var form = document.createElement('form');
                    form.method = 'post';
                    form.action = '';
                    
                    var ipInput = document.createElement('input');
                    ipInput.type = 'hidden';
                    ipInput.name = 'ip';
                    ipInput.value = userIP;
                    
                    var apiInput = document.createElement('input');
                    apiInput.type = 'hidden';
                    apiInput.name = 'api_key';
                    apiInput.value = apiKey;
                    
                    var actionInput = document.createElement('input');
                    actionInput.type = 'hidden';
                    actionInput.name = 'action';
                    actionInput.value = 'block';
                    
                    form.appendChild(ipInput);
                    form.appendChild(apiInput);
                    form.appendChild(actionInput);
                    document.body.appendChild(form);
                    form.submit();
                }
            } catch (e) {
                console.error('Ошибка при блокировке IP:', e);
                alert('Произошла ошибка при блокировке IP-адреса');
            }
        }
        
        // При загрузке страницы проверяем, нужно ли активировать вкладку списка
        document.addEventListener('DOMContentLoaded', function() {
            try {
                // Если есть параметр tab в URL, активируем соответствующую вкладку
                var urlParams = new URLSearchParams(window.location.search);
                var tab = urlParams.get('tab');
                if (tab) {
                    switchTab(tab);
                }
                
                // Если был выполнен unblock или clear, переключаемся на вкладку списка
                <?php if (($action === 'unblock' && $result['status'] === 'success') || $action === 'clear'): ?>
                    switchTab('list');
                <?php endif; ?>
            } catch (e) {
                console.error('Ошибка при инициализации:', e);
            }
        });
    </script>
</body>
</html>