<?php
require_once 'settings.php';
// /dos/admin.php
// Административный интерфейс для управления заблокированными IP-адресами с поддержкой Redis

// Отключаем мониторинг безопасности для админ-панели
define('DISABLE_SECURITY_MONITOR', true);

// Базовая аутентификация для защиты доступа
//define('ADMIN_USERNAME', 'murkir'); // Измените это на более надежное имя пользователя
//define('ADMIN_PASSWORD', 'murkir'); // Измените это на более надежный пароль

// Определение переменных для работы с Redis
$useRedis = defined('USE_REDIS') ? USE_REDIS : false;
$redis = null;
$redisPrefix = defined('REDIS_PREFIX') ? REDIS_PREFIX : 'dos:';

// Функция аутентификации - объявляем перед использованием
function checkAuth() {
    if (!isset($_SERVER['PHP_AUTH_USER']) || 
        !isset($_SERVER['PHP_AUTH_PW']) || 
        $_SERVER['PHP_AUTH_USER'] !== ADMIN_USERNAME || 
        $_SERVER['PHP_AUTH_PW'] !== ADMIN_PASSWORD) {
        
        header('WWW-Authenticate: Basic realm="Панель администратора безопасности"');
        header('HTTP/1.0 401 Unauthorized');
        echo '<h1>Доступ запрещен</h1>';
        exit;
    }
}

// Выполняем проверку аутентификации
checkAuth();

// Подключаем класс мониторинга безопасности
require_once 'security_monitor.php';

// Автоматическая разблокировка текущего IP после успешной аутентификации
function autoUnblockCurrentIP() {
    $admin = new SecurityAdmin();
    $current_ip = $admin->getClientIP();
    
    // Проверяем, заблокирован ли текущий IP
    if ($admin->isIPBlocked($current_ip)) {
        // Разблокируем IP (включая API разблокировку)
        $admin->unblockIP($current_ip);
        return true;
    }
    
    return false;
}

// Обработка переключения DNS-запросов
if (isset($_POST['toggle_rdns'])) {
    $new_value = isset($_POST['disable_rdns']) ? true : false;
    
    // Находим константу в settings.php и изменяем её значение
    $settings_file = dirname(__FILE__) . '/settings.php';
    $settings_content = file_get_contents($settings_file);
    
    // Заменяем значение константы
    $pattern = "/define\('DISABLE_RDNS_LOOKUP',\s*(true|false)\);/";
    $replacement = "define('DISABLE_RDNS_LOOKUP', " . ($new_value ? 'true' : 'false') . ");";
    $new_content = preg_replace($pattern, $replacement, $settings_content);
    
    if ($new_content !== $settings_content) {
        // Записываем изменения в файл
        if (file_put_contents($settings_file, $new_content)) {
            $successMessage = "Настройки DNS-запросов успешно обновлены";
            
            // Переопределяем константу для текущего запроса
            if (defined('DISABLE_RDNS_LOOKUP')) {
                // Так как константы напрямую переопределить нельзя, используем глобальную переменную
                $GLOBALS['DISABLE_RDNS_LOOKUP'] = $new_value;
            }
        } else {
            $errorMessage = "Не удалось обновить настройки DNS-запросов. Проверьте права доступа к файлу settings.php";
        }
    }
    
    // Перезагружаем страницу для обновления настроек
    header("Location: admin.php?page=" . $active_page);
    exit;
}

// Пытаемся разблокировать текущий IP
$auto_unblocked = autoUnblockCurrentIP();

// Класс для администрирования
class SecurityAdmin {
    private $db;
    private $dos_dir;
    private $whitelisted_ips = array();
    private $redis = null;
    private $useRedis = false;
    private $prefix = '';
    private $redisInfo = array();
    
    public function __construct() {
        $this->dos_dir = dirname(__FILE__) . '/';
        
        // Определяем, использовать ли Redis
        $this->useRedis = defined('USE_REDIS') ? USE_REDIS : false;
        $this->prefix = defined('REDIS_PREFIX') ? REDIS_PREFIX : 'dos:';
        
        // Инициализируем соединение с Redis, если используется
        if ($this->useRedis) {
            $this->connectRedis();
        }
        
        // Если Redis недоступен, используем MariaDB
        if (!$this->useRedis || !$this->redis) {
            $this->connectDB();
        }
        
        $this->loadWhitelist();
    }
    
    // Соединение с Redis
    private function connectRedis() {
        try {
            if (!class_exists('Redis')) {
                error_log("Redis PHP extension not available. Using MariaDB fallback.");
                $this->useRedis = false;
                return false;
            }
            
            $this->redis = new Redis();
            $host = defined('REDIS_HOST') ? REDIS_HOST : '127.0.0.1';
            $port = defined('REDIS_PORT') ? REDIS_PORT : 6379;
            
            if (!$this->redis->connect($host, $port, 2.0)) { // 2 секунды таймаут
                error_log("Failed to connect to Redis at $host:$port. Using MariaDB fallback.");
                $this->useRedis = false;
                return false;
            }
            
            // Аутентификация, если настроен пароль
            if (defined('REDIS_PASSWORD') && REDIS_PASSWORD) {
                if (!$this->redis->auth(REDIS_PASSWORD)) {
                    error_log("Redis authentication failed. Using MariaDB fallback.");
                    $this->useRedis = false;
                    return false;
                }
            }
            
            // Выбор базы данных
            $database = defined('REDIS_DATABASE') ? REDIS_DATABASE : 0;
            $this->redis->select($database);
            
            // Сохраняем базовую информацию о Redis
            $this->collectRedisInfo();
            
            return true;
        } catch (Exception $e) {
            error_log("Redis connection error: " . $e->getMessage());
            $this->useRedis = false;
            return false;
        }
    }
    
    // Проверка, заблокирован ли IP через Redis
    private function isIPBlockedRedis($ip) {
        if (!$this->redis) return false;
        
        try {
            // Проверяем наличие ключа блокировки
            $blockKey = $this->prefix . "blocked_ip:$ip";
            
            // Если ключ существует, проверяем, не истек ли срок блокировки
            if ($this->redis->exists($blockKey)) {
                // Получаем время блокировки
                $blockUntil = (int)$this->redis->hGet($blockKey, 'block_until');
                
                // Если блокировка еще активна
                if ($blockUntil > time()) {
                    return true;
                }
                
                // Если блокировка истекла, удаляем ключ для освобождения памяти
                $this->redis->del($blockKey);
                
                // Удаляем IP из отсортированного множества заблокированных IP
                $this->redis->zRem($this->prefix . "blocked_ips", $ip);
            }
            
            return false;
        } catch (Exception $e) {
            error_log("Error checking IP block in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    // Проверка, заблокирован ли IP
    public function isIPBlocked($ip) {
        // Сначала проверяем через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            return $this->isIPBlockedRedis($ip);
        }
        
        // Иначе через MariaDB
        try {
            if (!$this->db) {
                $this->connectDB();
                if (!$this->db) {
                    return false;
                }
            }
            
            $stmt = $this->db->prepare("SELECT 1 FROM blocked_ips WHERE ip = ? AND block_until > NOW()");
            $stmt->execute(array($ip));
            return $stmt->fetchColumn() ? true : false;
        } catch(PDOException $e) {
            error_log("Error checking if IP is blocked: " . $e->getMessage());
            return false;
        }
    }
	// Получение IP-адреса клиента с поддержкой IPv6
    public function getClientIP() {
        // Проверяем различные заголовки
        $ip_keys = array(
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );
        
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    
                    // Валидация IPv4
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                        return $ip;
                    }
                    
                    // Валидация IPv6
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                        return $ip;
                    }
                }
            }
        }
        
        // Если ничего не нашли, возвращаем REMOTE_ADDR
        return $_SERVER['REMOTE_ADDR'];
    }
    
    // Нормализация IP-адреса (для IPv6 приводим к полному формату)
    public function normalizeIP($ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // Преобразуем IPv6 в полную форму для точного сравнения
            $packed = inet_pton($ip);
            if ($packed !== false) {
                return inet_ntop($packed);
            }
        }
        return $ip;
    }
    
    // Загрузка белого списка IP-адресов
    private function loadWhitelist() {
        // Если используем Redis, сначала пытаемся загрузить из Redis
        if ($this->useRedis && $this->redis) {
            try {
                $whitelistKey = $this->prefix . "whitelist_ips";
                if ($this->redis->exists($whitelistKey)) {
                    $whitelist = $this->redis->sMembers($whitelistKey);
                    if (!empty($whitelist)) {
                        $this->whitelisted_ips = $whitelist;
                        return;
                    }
                }
            } catch (Exception $e) {
                error_log("Error loading whitelist from Redis: " . $e->getMessage());
                // Продолжаем и загружаем из файла
            }
        }
        
        // Фолбэк: загрузка из файла
        $whitelist_file = $this->dos_dir . 'whitelist_ips.php';
        
        if (file_exists($whitelist_file)) {
            @include $whitelist_file;
            if (isset($whitelist_ips) && is_array($whitelist_ips)) {
                $this->whitelisted_ips = $whitelist_ips;
                
                // Если используем Redis, синхронизируем с ним
                if ($this->useRedis && $this->redis) {
                    try {
                        $whitelistKey = $this->prefix . "whitelist_ips";
                        $this->redis->del($whitelistKey);
                        if (!empty($this->whitelisted_ips)) {
                            foreach ($this->whitelisted_ips as $ip) {
                                $this->redis->sAdd($whitelistKey, $ip);
                            }
                        }
                    } catch (Exception $e) {
                        error_log("Error syncing whitelist to Redis: " . $e->getMessage());
                    }
                }
            }
        }
    }
    
    // Подключение к БД
    private function connectDB() {
        // Настройки подключения
        //$host = 'localhost';
        //$dbname = 'murkir.pp.ua';
        //$username = 'murkir';
        //$password = 'iG2mX1qQ8m';
        
        try {
            $this->db = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
            if (defined('PDO::ATTR_ERRMODE')) {
                $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            }
            $this->db->exec("SET NAMES utf8mb4");
        } catch(PDOException $e) {
            die("Ошибка подключения к БД: " . $e->getMessage());
        }
    }
    
    // Получение списка всех заблокированных IP через Redis
    private function getBlockedIPsRedis($limit = null, $offset = null) {
    if (!$this->redis) return false;
    
    try {
        $now = time();
        $blockedIps = array();
        $blockedIpsKey = $this->prefix . "blocked_ips";
        
        // Получаем все IP с временем блокировки больше текущего времени
        $blockedList = $this->redis->zRangeByScore($blockedIpsKey, $now, '+inf', array('WITHSCORES' => true));
        
        // Получаем общее количество заблокированных IP
        $total = count($blockedList);
        
        // Реализуем пагинацию на уровне PHP, так как Redis не поддерживает OFFSET в zRangeByScore напрямую
        if ($limit !== null && $offset !== null) {
            $blockedList = array_slice($blockedList, $offset, $limit, true);
        }
        
        foreach ($blockedList as $ip => $blockUntil) {
            $blockKey = $this->prefix . "blocked_ip:$ip";
            if (!$this->redis->exists($blockKey)) {
                continue; // Пропускаем IP, для которых нет данных о блокировке
            }
            
            $blockInfo = $this->redis->hGetAll($blockKey);
            if (!$blockInfo) {
                continue;
            }
            
            // Преобразуем строковые значения в числовые
            $blockInfo['block_count'] = (int)$blockInfo['block_count'];
            $blockInfo['block_until'] = (int)$blockInfo['block_until'];
            $blockInfo['created_at'] = (int)$blockInfo['created_at'];
            $blockInfo['first_blocked_at'] = (int)$blockInfo['first_blocked_at'];
            
            // Преобразуем временные метки в MySQL datetime формат для единообразия с MariaDB
            $blockInfo['block_until'] = date('Y-m-d H:i:s', $blockInfo['block_until']);
            $blockInfo['created_at'] = date('Y-m-d H:i:s', $blockInfo['created_at']);
            $blockInfo['first_blocked_at'] = date('Y-m-d H:i:s', $blockInfo['first_blocked_at']);
            
            // Добавляем IP в blockInfo
            $blockInfo['ip'] = $ip;
            
            // Добавляем в результат
            $blockedIps[] = $blockInfo;
        }
        
        return [
            'data' => $blockedIps,
            'total' => $total
        ];
    } catch (Exception $e) {
        error_log("Error getting blocked IPs from Redis: " . $e->getMessage());
        return false;
    }
}
    
    // Получение списка всех заблокированных IP
    public function getBlockedIPs($limit = null, $offset = null) {
    // Сначала проверяем через Redis, если доступен
    if ($this->useRedis && $this->redis) {
        $redisBlockedIPs = $this->getBlockedIPsRedis($limit, $offset);
        if ($redisBlockedIPs !== false) {
            return $redisBlockedIPs;
        }
    }
    
    // Иначе через MariaDB
    try {
        if (!$this->db) {
            $this->connectDB();
            if (!$this->db) {
                return ['data' => array(), 'total' => 0];
            }
        }
        
        // Сначала узнаем общее количество записей для пагинации
        $countSql = "SELECT COUNT(*) FROM blocked_ips WHERE block_until > NOW()";
        $countStmt = $this->db->query($countSql);
        $total = $countStmt->fetchColumn();
        
        // Запрос с учетом пагинации
        $sql = "
            SELECT ip, block_until, reason, created_at, block_count, first_blocked_at 
            FROM blocked_ips 
            WHERE block_until > NOW()
            ORDER BY block_until DESC
        ";
        
        // Добавляем LIMIT только если указаны оба параметра
        if ($limit !== null && $offset !== null) {
            $sql .= " LIMIT ?, ?";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(1, $offset, PDO::PARAM_INT);
            $stmt->bindParam(2, $limit, PDO::PARAM_INT);
            $stmt->execute();
        } else {
            $stmt = $this->db->query($sql);
        }
        
        return [
            'data' => $stmt->fetchAll(PDO::FETCH_ASSOC),
            'total' => $total
        ];
    } catch(PDOException $e) {
        error_log("Ошибка при получении списка заблокированных IP: " . $e->getMessage());
        return ['data' => array(), 'total' => 0];
    }
}
    
    // Разблокировка IP через Redis
    private function unblockIPRedis($ip) {
    if (!$this->redis) return false;
    
    try {
        // Ключ блокировки
        $blockKey = $this->prefix . "blocked_ip:$ip";
        
        // Проверяем, существует ли блокировка
        if (!$this->redis->exists($blockKey)) {
            return true; // Нечего разблокировать
        }
        
        // Удаляем из Redis
        // 1. Удаляем ключ блокировки
        $this->redis->del($blockKey);
        
        // 2. Удаляем из отсортированного множества
        $this->redis->zRem($this->prefix . "blocked_ips", $ip);
        
        // НОВЫЙ КОД: Удаляем также из MariaDB
        // Подключаемся к БД, если еще не подключены
        if (!$this->db) {
            $this->connectDB();
        }
        
        // Если соединение с БД установлено, удаляем IP
        if ($this->db) {
            try {
                $stmt = $this->db->prepare("DELETE FROM blocked_ips WHERE ip = ?");
                $stmt->execute(array($ip));
                error_log("IP $ip успешно удален из базы данных MySQL");
            } catch(PDOException $e) {
                error_log("Ошибка при удалении IP из MariaDB: " . $e->getMessage());
                // Продолжаем выполнение даже в случае ошибки
            }
        }
        
        // Выполняем внешние разблокировки (существующий код)
        $this->removeIPFromConf($ip);
        $this->removeIPFromHtaccess($ip);
        $this->unblockIPFromIptables($ip);
        $this->unblockIPViaAPI($ip);
        
        // Сбрасываем счетчики запросов для IP
        $this->redis->del($this->prefix . "ip_request_rate:$ip");
        
        // Логируем разблокировку
        $this->redis->lPush($this->prefix . "unblock_log", json_encode([
            'ip' => $ip,
            'time' => time(),
            'method' => 'admin'
        ]));
        $this->redis->ltrim($this->prefix . "unblock_log", 0, 999);
        
        // Обновляем файловый кеш блокировок
        $this->updateBlockedIPsCache();
        
        return true;
    } catch (Exception $e) {
        error_log("Error unblocking IP in Redis: " . $e->getMessage());
        return false;
    }
}
// Разблокировка IP
    public function unblockIP($ip) {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            if ($this->unblockIPRedis($ip)) {
                return true;
            }
        }
        
        // Иначе через MariaDB
        try {
            if (!$this->db) {
                $this->connectDB();
                if (!$this->db) {
                    return false;
                }
            }
            
            // Удаляем IP из .htaccess
            $this->removeIPFromHtaccess($ip);
            
            // Удаляем IP из ip.conf
            $this->removeIPFromConf($ip);
            
            // Удаляем IP из iptables/ip6tables
            $this->unblockIPFromIptables($ip);
            
            // Удаляем IP через внешний API
            $this->unblockIPViaAPI($ip);
            
            // Удаляем из базы данных
            $stmt = $this->db->prepare("DELETE FROM blocked_ips WHERE ip = ?");
            $result = $stmt->execute(array($ip));
            
            if ($result) {
                // Обновляем кеш блокировок
                $this->updateBlockedIPsCache();
                return true;
            }
            
            return false;
        } catch(PDOException $e) {
            die("Ошибка при разблокировке IP: " . $e->getMessage());
        }
    }
	
	// Разблокировка всех IP
public function unblockAllIPs() {
    $count = 0;
    
    // Сначала через Redis, если доступен
    if ($this->useRedis && $this->redis) {
        $now = time();
        $blockedIpsKey = $this->prefix . "blocked_ips";
        
        // Получаем все заблокированные IP-адреса
        $blockedList = $this->redis->zRangeByScore($blockedIpsKey, $now, '+inf');
        
        foreach ($blockedList as $ip) {
            if ($this->unblockIPRedis($ip)) {
                $count++;
            }
        }
    }
    
    // Также разблокируем через MariaDB
    try {
        if (!$this->db) {
            $this->connectDB();
            if (!$this->db) {
                return $count;
            }
        }
        
        // Получаем список заблокированных IP
        $stmt = $this->db->query("SELECT ip FROM blocked_ips WHERE block_until > NOW()");
        $ips = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        foreach ($ips as $ip) {
            // Удаляем IP из .htaccess
            $this->removeIPFromHtaccess($ip);
            
            // Удаляем IP из ip.conf
            $this->removeIPFromConf($ip);
            
            // Удаляем IP из iptables/ip6tables
            $this->unblockIPFromIptables($ip);
            
            // Удаляем IP через внешний API
            $this->unblockIPViaAPI($ip);
        }
        
        // Удаляем все IP из базы данных одним запросом
        $stmt = $this->db->prepare("DELETE FROM blocked_ips WHERE block_until > NOW()");
        $stmt->execute();
        
        $count += count($ips);
        
        // Обновляем кеш блокировок
        $this->updateBlockedIPsCache();
        
        return $count;
    } catch(PDOException $e) {
        error_log("Ошибка при массовой разблокировке IP: " . $e->getMessage());
        return $count;
    }
}
    
    // Метод для разблокировки IP через внешний API
    private function unblockIPViaAPI($ip) {
        // Пропускаем, если API-блокировка отключена
        if (defined('ENABLE_API_BLOCKING') && !ENABLE_API_BLOCKING) {
            return true; // Возвращаем true, так как отключение - не ошибка
        }
        
        // Проверяем наличие необходимых настроек
        if (!defined('API_BLOCK_URL') || !defined('API_BLOCK_KEY')) {
            error_log("Ошибка: API_BLOCK_URL или API_BLOCK_KEY не определены в настройках");
            return false;
        }
        
        $url = API_BLOCK_URL;
        $api_key = API_BLOCK_KEY;
        $userAgent = defined('API_USER_AGENT') ? API_USER_AGENT : 'PHP/' . PHP_VERSION;
        
        // Подготавливаем параметры запроса
        $params = array(
            'action' => 'unblock',
            'ip' => $ip,
            'api_key' => $api_key,
            'api' => 1 // Включаем режим API для получения JSON-ответа
        );
        
        // Формируем URL запроса
        $requestUrl = $url . '?' . http_build_query($params);
        
        error_log("Выполняем разблокировку IP $ip через API: $requestUrl");
        
        // Инициализируем cURL
        $ch = curl_init();
        
        // Настраиваем cURL
        curl_setopt($ch, CURLOPT_URL, $requestUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10); // Таймаут 10 секунд
        curl_setopt($ch, CURLOPT_USERAGENT, $userAgent);
        
        // Для работы с HTTPS
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        
        // Выполняем запрос
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        
        // Закрываем cURL
        curl_close($ch);
        
        // Проверяем ошибки
        if ($error) {
            error_log("Ошибка API разблокировки для IP $ip: $error");
            return false;
        }
        
        // Если код ответа не 200 OK
        if ($httpCode !== 200) {
            error_log("Ошибка API разблокировки для IP $ip: HTTP код $httpCode");
            return false;
        }
        
        // Пытаемся разобрать JSON-ответ
        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("Ошибка разбора JSON-ответа от API при разблокировке IP $ip: " . $response);
            return false;
        }
        
        // Проверяем статус разблокировки
        $success = isset($data['status']) && ($data['status'] === 'success' || $data['status'] === 'warning');
        
        // Логируем результат
        if ($success) {
            error_log("IP $ip успешно разблокирован через API");
            return true;
        } else {
            $message = isset($data['message']) ? $data['message'] : 'Неизвестная ошибка';
            error_log("Ошибка разблокировки IP $ip через API: $message");
            return false;
        }
    }

    // Удаление IP из .htaccess
    private function removeIPFromHtaccess($ip) {
        $htaccessPath = dirname($this->dos_dir) . '/.htaccess';
        
        if (!file_exists($htaccessPath)) {
            return false;
        }
        
        // Читаем содержимое файла
        $htaccessContent = file_get_contents($htaccessPath);
        if ($htaccessContent === false) {
            return false;
        }
        
        $lines = explode("\n", $htaccessContent);
        $new_lines = array();
        $removed = false;
        
        // Проходим по каждой строке и удаляем правило блокировки для указанного IP
        foreach ($lines as $line) {
            if (trim($line) === "Deny from $ip") {
                $removed = true;
                continue;
            }
            $new_lines[] = $line;
        }
        
        // Сохраняем обновленное содержимое .htaccess, если было удаление
        if ($removed) {
            $new_content = implode("\n", $new_lines);
            file_put_contents($htaccessPath, $new_content);
        }
        
        return $removed;
    }

    // Удаление IP из ip.conf
    private function removeIPFromConf($ip) {
        $ipConfFile = $this->dos_dir . 'ip.conf';
        
        if (!file_exists($ipConfFile)) {
            return false;
        }
        
        // Читаем содержимое файла
        $lines = file($ipConfFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return false;
        }
        
        $blockedIPs = array();
        $removed = false;
        
        // Собираем все IP, кроме удаляемого
        foreach ($lines as $line) {
            // Пропускаем комментарии
            if (strpos($line, '#') === 0) {
                continue;
            }
            
            // Извлекаем IP из строки (первая часть до пробела или до конца строки)
            $parts = preg_split('/\s+/', trim($line));
            $lineIP = $parts[0];
            
            // Добавляем все IP, кроме того, который нужно удалить
            if ($this->isValidIP($lineIP) && $lineIP !== $ip) {
                $blockedIPs[] = $lineIP;
            } else if ($lineIP === $ip) {
                $removed = true;
            }
        }
        
        // Если IP был найден и удален, обновляем файл
        if ($removed) {
            // Формируем новое содержимое файла
            $fileContent = "# Обновлено " . date('Y-m-d H:i:s') . "\n";
            
            // Добавляем все оставшиеся IP-адреса в формате "IP 1;"
            foreach ($blockedIPs as $blockedIP) {
                $fileContent .= "$blockedIP 1;\n";
            }
            
            // Записываем в файл
            file_put_contents($ipConfFile, $fileContent);
            
            // Перезагружаем Nginx после изменения файла
            $this->reloadNginx();
        }
        
        return $removed;
    }
	// Удаление IP из iptables/ip6tables
    private function unblockIPFromIptables($ip) {
    // Проверяем валидность IP-адреса
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        error_log("Неверный формат IP-адреса для разблокировки в iptables: " . $ip);
        return false;
    }
    
    // Определяем версию IP
    $isIPv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    
    // Порты для разблокировки
    $ports = array(80, 443);
    $success = true;
    
    foreach ($ports as $port) {
        // Формируем команду в зависимости от версии IP
        if ($isIPv6) {
            $command = "sudo ip6tables -D INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
        } else {
            $command = "sudo iptables -D INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
        }
        
        // Удаляем все правила в цикле
        $returnVar = 0;
        $deleted = 0;
        
        // Продолжаем удалять, пока команда возвращает успешный статус
        while ($returnVar === 0) {
            $output = array();
            exec($command, $output, $returnVar);
            
            if ($returnVar === 0) {
                $deleted++;
            }
        }
        
        // Логируем результат удаления
        error_log("Удаление IP $ip из " . ($isIPv6 ? "ip6tables" : "iptables") . " для порта $port: удалено правил: $deleted");
    }
    
    // Также удаляем общее правило (для совместимости со старыми версиями)
    if ($isIPv6) {
        $command = "sudo ip6tables -D INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null";
    } else {
        $command = "sudo iptables -D INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null";
    }
    
    // Удаляем все общие правила в цикле
    $returnVar = 0;
    $deleted = 0;
    
    while ($returnVar === 0) {
        $output = array();
        exec($command, $output, $returnVar);
        
        if ($returnVar === 0) {
            $deleted++;
        }
    }
    
    // Сохраняем правила для сохранения после перезагрузки
    $this->saveIptablesRules($isIPv6);
    
    return true;
}

    // Функция для сохранения правил iptables
    private function saveIptablesRules($isIPv6) {
        $distro = $this->getLinuxDistribution();
        
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
        
        // Логируем предупреждение, если не удалось сохранить правила
        if ($returnVar !== 0) {
            error_log("Предупреждение: Не удалось сохранить правила iptables");
        }
        
        return true;
    }

    // Функция для определения дистрибутива Linux
    private function getLinuxDistribution() {
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

    // Проверка валидности IP-адреса
    private function isValidIP($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP);
    }

    // Перезагрузка Nginx
    private function reloadNginx() {
        // Создаем файл-флаг для внешнего скрипта перезагрузки
        $reload_flag_file = $this->dos_dir . 'nginx_reload_needed';
        file_put_contents($reload_flag_file, date('Y-m-d H:i:s'));
        
        // Попытка использовать exec, если доступно
        if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))))) {
            $output = array();
            $return_var = 0;
            exec('sudo /usr/sbin/nginx -s reload 2>&1', $output, $return_var);
        }
    }
    
    // Поиск DNS по IP (обратный DNS-поиск)
public function getHostByAddr($ip) {
    // Проверяем, отключены ли DNS-запросы в настройках
    if (defined('DISABLE_RDNS_LOOKUP') && DISABLE_RDNS_LOOKUP === true) {
        return 'DNS отключен';
    }
    
    $hostname = gethostbyaddr($ip);
    
    // Если не удалось получить имя хоста или возвращен тот же IP
    if (!$hostname || $hostname === $ip) {
        return 'Не найден';
    }
    
    return $hostname;
}
    
    // Получение истории запросов для IP через Redis
    private function getRequestHistoryRedis($ip, $limit = 50) {
        if (!$this->redis) return array();
        
        try {
            $result = array();
            $ipRequestsKey = $this->prefix . "suspicious_requests:$ip";
            
            // Проверяем, существует ли ключ со списком запросов для этого IP
            if (!$this->redis->exists($ipRequestsKey)) {
                return array();
            }
            
            // Получаем ID запросов для этого IP (не более limit)
            $requestIds = $this->redis->lRange($ipRequestsKey, 0, $limit - 1);
            
            foreach ($requestIds as $requestId) {
                $requestKey = $this->prefix . "request:$requestId";
                if (!$this->redis->exists($requestKey)) {
                    continue;
                }
                
                $requestData = $this->redis->hGetAll($requestKey);
                if (!$requestData) {
                    continue;
                }
                
                // Преобразуем временную метку в формат даты/времени MariaDB
                if (isset($requestData['request_time'])) {
                    $requestData['request_time'] = date('Y-m-d H:i:s', (int)$requestData['request_time']);
                }
                
                $result[] = $requestData;
            }
            
            return $result;
        } catch (Exception $e) {
            error_log("Error getting request history from Redis: " . $e->getMessage());
            return array();
        }
    }
    
    // Получение истории запросов для IP
    public function getRequestHistory($ip, $limit = 50) {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            $redisHistory = $this->getRequestHistoryRedis($ip, $limit);
            if (!empty($redisHistory)) {
                return $redisHistory;
            }
        }
        
        // Иначе через MariaDB
        try {
            if (!$this->db) {
                $this->connectDB();
                if (!$this->db) {
                    return array();
                }
            }
            
            $stmt = $this->db->prepare("
                SELECT request_uri, user_agent, request_time 
                FROM suspicious_requests 
                WHERE ip = ?
                ORDER BY request_time DESC
                LIMIT ?
            ");
            $stmt->bindParam(1, $ip, PDO::PARAM_STR);
            $stmt->bindParam(2, $limit, PDO::PARAM_INT);
            $stmt->execute();
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch(PDOException $e) {
            die("Ошибка при получении истории запросов: " . $e->getMessage());
        }
    }
	// Форматирование времени блокировки
    public function formatBlockDuration($block_until) {
        $now = time();
        $block_time = strtotime($block_until);
        $duration = $block_time - $now;
        
        if ($duration < 0) {
            return "Истекла";
        }
        
        $days = floor($duration / (60 * 60 * 24));
        $hours = floor(($duration - ($days * 60 * 60 * 24)) / (60 * 60));
        $minutes = floor(($duration - ($days * 60 * 60 * 24) - ($hours * 60 * 60)) / 60);
        
        $result = "";
        if ($days > 0) {
            $result .= $days . " " . $this->pluralize($days, "день", "дня", "дней") . " ";
        }
        if ($hours > 0 || $days > 0) {
            $result .= $hours . " " . $this->pluralize($hours, "час", "часа", "часов") . " ";
        }
        $result .= $minutes . " " . $this->pluralize($minutes, "минута", "минуты", "минут");
        
        return $result;
    }
    
    // Функция для правильного склонения слов
    private function pluralize($number, $one, $two, $many) {
        $number = abs($number) % 100;
        $mod10 = $number % 10;
        
        if ($number > 10 && $number < 20) {
            return $many;
        }
        
        if ($mod10 > 1 && $mod10 < 5) {
            return $two;
        }
        
        if ($mod10 == 1) {
            return $one;
        }
        
        return $many;
    }
    
    // Получение списка IP в белом списке через Redis
    private function getWhitelistedIPsRedis() {
        if (!$this->redis) return array();
        
        try {
            $whitelistKey = $this->prefix . "whitelist_ips";
            if (!$this->redis->exists($whitelistKey)) {
                return array();
            }
            
            return $this->redis->sMembers($whitelistKey);
        } catch (Exception $e) {
            error_log("Error getting whitelisted IPs from Redis: " . $e->getMessage());
            return array();
        }
    }
    
    // Добавление IP в белый список через Redis
    private function addToWhitelistRedis($ip) {
        if (!$this->redis) return false;
        
        try {
            $whitelistKey = $this->prefix . "whitelist_ips";
            
            // Проверяем, есть ли уже IP в белом списке
            if ($this->redis->sIsMember($whitelistKey, $ip)) {
                return true; // IP уже в белом списке
            }
            
            // Добавляем IP в белый список в Redis
            $this->redis->sAdd($whitelistKey, $ip);
            
            // Обновляем файловый кеш белого списка
            $this->saveWhitelist();
            
            return true;
        } catch (Exception $e) {
            error_log("Error adding IP to whitelist in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    // Удаление IP из белого списка через Redis
    private function removeFromWhitelistRedis($ip) {
        if (!$this->redis) return false;
        
        try {
            $whitelistKey = $this->prefix . "whitelist_ips";
            
            // Удаляем IP из белого списка в Redis
            $this->redis->sRem($whitelistKey, $ip);
            
            // Обновляем файловый кеш белого списка
            $this->saveWhitelist();
            
            return true;
        } catch (Exception $e) {
            error_log("Error removing IP from whitelist in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    // Получение списка IP из белого списка
    public function getWhitelistedIPs() {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            $redisWhitelist = $this->getWhitelistedIPsRedis();
            if ($redisWhitelist !== false) {
                return $redisWhitelist;
            }
        }
        
        // Если Redis недоступен или вернул ошибку, используем данные, загруженные из файла
        return $this->whitelisted_ips;
    }
    
    // Добавление IP в белый список
    public function addToWhitelist($ip) {
        // Сначала проверяем, является ли это CIDR
        $isCIDR = strpos($ip, '/') !== false;
        
        // Если это обычный IP, валидируем стандартным способом
        if (!$isCIDR && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
            return false;
        }
        
        // Если это CIDR, валидируем через специальный метод
        if ($isCIDR && !$this->validateCIDR($ip)) {
            return false;
        }
        
        // Нормализуем только обычные IP (не CIDR)
        if (!$isCIDR) {
            $ip = $this->normalizeIP($ip);
        }
        
        // Проверяем, есть ли уже такой IP в списке
        foreach ($this->whitelisted_ips as $white_ip) {
            if ($white_ip === $ip) {
                return true; // Уже есть в списке
            }
        }
        
        // Добавляем в Redis, если он доступен
        if ($this->useRedis && $this->redis) {
            $this->addToWhitelistRedis($ip);
        }
        
        // Добавляем в список
        $this->whitelisted_ips[] = $ip;
        return $this->saveWhitelist();
    }
    
    // Проверка, можно ли добавить CIDR-диапазон
    public function validateCIDR($cidr) {
        if (strpos($cidr, '/') === false) {
            return false;
        }
        
        $cidr_parts = explode('/', $cidr);
        $subnet = $cidr_parts[0];
        $mask = isset($cidr_parts[1]) ? $cidr_parts[1] : '';
        
        // Проверка IPv4 CIDR
        if (filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return is_numeric($mask) && $mask >= 0 && $mask <= 32;
        }
        
        // Проверка IPv6 CIDR
        if (filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return is_numeric($mask) && $mask >= 0 && $mask <= 128;
        }
        
        return false;
    }
    
    // Удаление IP из белого списка
    public function removeFromWhitelist($ip) {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            $this->removeFromWhitelistRedis($ip);
        }
        
        // Нормализуем IP для сравнения
        $normalized_ip = $this->normalizeIP($ip);
        
        foreach ($this->whitelisted_ips as $key => $white_ip) {
            if ($this->normalizeIP($white_ip) === $normalized_ip) {
                unset($this->whitelisted_ips[$key]);
                $this->whitelisted_ips = array_values($this->whitelisted_ips); // Переиндексируем массив
                return $this->saveWhitelist();
            }
        }
        return true;
    }
    
    // Сохранение белого списка в файл
    private function saveWhitelist() {
        try {
            // Убеждаемся, что директория существует
            if (!is_dir($this->dos_dir)) {
                mkdir($this->dos_dir, 0755, true);
            }
            
            // Записываем в файл белого списка
            $whitelist_file = $this->dos_dir . 'whitelist_ips.php';
            $content = "<?php\n\$whitelist_ips = " . var_export($this->whitelisted_ips, true) . ";\n";
            
            // Используем атомарную запись
            $tmp_file = $whitelist_file . '.tmp';
            if (file_put_contents($tmp_file, $content) !== false) {
                rename($tmp_file, $whitelist_file);
                return true;
            }
            return false;
        } catch(Exception $e) {
            error_log("Ошибка сохранения белого списка: " . $e->getMessage());
            return false;
        }
    }
	// Обновление файлового кеша блокировок (аналогично методу из LightSecurityMonitor)
    private function updateBlockedIPsCache() {
        try {
            // Если используем Redis
            if ($this->useRedis && $this->redis) {
                // Получаем все активные блокировки из Redis
                $blockedIpsKey = $this->prefix . "blocked_ips";
                $now = time();
                $blocked_ips = array();
                $blocked_info = array();
                
                // Получаем все IP с временем блокировки больше текущего времени
                $blocked_list = $this->redis->zRangeByScore($blockedIpsKey, $now, '+inf', array('WITHSCORES' => true));
                
                foreach ($blocked_list as $ip => $block_until) {
                    $blocked_ips[$ip] = (int)$block_until;
                    
                    // Получаем дополнительную информацию из хеша
                    $blockKey = $this->prefix . "blocked_ip:$ip";
                    if ($this->redis->exists($blockKey)) {
                        $block_count = (int)$this->redis->hGet($blockKey, 'block_count');
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
            // Используем MariaDB
            else if ($this->db) {
                // Получаем все активные блокировки
                $stmt = $this->db->query("
                    SELECT ip, UNIX_TIMESTAMP(block_until) as block_until, block_count 
                    FROM blocked_ips 
                    WHERE block_until > NOW()
                ");
                
                $blocked_ips = array();
                $blocked_info = array();
                
                while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                    $blocked_ips[$row['ip']] = (int)$row['block_until'];
                    $blocked_info[$row['ip']] = array(
                        'until' => (int)$row['block_until'],
                        'count' => (int)$row['block_count']
                    );
                }
            } else {
                return false; // Нет соединения ни с Redis, ни с MariaDB
            }
            
            // Убеждаемся, что директория существует
            if (!is_dir($this->dos_dir)) {
                mkdir($this->dos_dir, 0755, true);
            }
            
            // Записываем в файловый кеш
            $cache_file = $this->dos_dir . 'blocked_ips.php';
            $content = "<?php\n\$blocked_ips = " . var_export($blocked_ips, true) . ";\n";
            
            // Записываем расширенную информацию в отдельный файл
            $info_file = $this->dos_dir . 'blocked_info.php';
            $info_content = "<?php\n\$blocked_info = " . var_export($blocked_info, true) . ";\n";
            
            // Используем атомарную запись, чтобы избежать повреждения файла кеша
            $tmp_file = $cache_file . '.tmp';
            if (file_put_contents($tmp_file, $content) !== false) {
                rename($tmp_file, $cache_file);
            }
            
            $tmp_info_file = $info_file . '.tmp';
            if (file_put_contents($tmp_info_file, $info_content) !== false) {
                rename($tmp_info_file, $info_file);
            }
            
            return true;
        } catch(PDOException $e) {
            die("Ошибка обновления кеша блокировок: " . $e->getMessage());
        } catch(Exception $e) {
            error_log("Error updating blocked IPs cache: " . $e->getMessage());
            return false;
        }
    }
    
    // Получение частоты запросов IP через Redis с пагинацией
    private function getIPRequestRatesRedis($limit = 100, $offset = 0) {
        if (!$this->redis) return array();
        
        try {
            $result = array();
            $pattern = $this->prefix . "ip_request_rate:*";
            
            // Сначала получаем только ключи для оптимизации
            $keys = $this->redis->keys($pattern);
            
            // Сортировка будет выполнена после получения данных
            // Лимитируем выборку ключей сразу
            $total_keys = count($keys);
            $limited_keys = array_slice($keys, $offset, $limit);
            
            // Batch-запрос для всех нужных ключей (вместо получения по одному)
            $pipeline = $this->redis->pipeline();
            foreach ($limited_keys as $key) {
                $pipeline->hGetAll($key);
            }
            $responses = $pipeline->exec();
            
            // Обрабатываем полученные данные
            foreach ($limited_keys as $i => $key) {
                $data = isset($responses[$i]) ? $responses[$i] : null;
                if (!$data) continue;
                
                $ip = str_replace($this->prefix . "ip_request_rate:", "", $key);
                
                // Преобразуем временные метки в формат даты/времени MariaDB
                if (isset($data['first_request_time'])) {
                    $data['first_request_time'] = date('Y-m-d H:i:s', (int)$data['first_request_time']);
                }
                if (isset($data['last_request_time'])) {
                    $data['last_request_time'] = date('Y-m-d H:i:s', (int)$data['last_request_time']);
                }
                
                // Добавляем IP
                $data['ip'] = $ip;
                
                $result[] = $data;
            }
            
            // Сортировка результатов по количеству запросов (от большего к меньшему)
            usort($result, function($a, $b) {
                $count_a = isset($a['request_count']) ? (int)$a['request_count'] : 0;
                $count_b = isset($b['request_count']) ? (int)$b['request_count'] : 0;
                
                if ($count_a == $count_b) {
                    // Если количество запросов одинаковое, сортируем по времени последнего запроса (от новых к старым)
                    $time_a = strtotime(isset($a['last_request_time']) ? $a['last_request_time'] : '0');
                    $time_b = strtotime(isset($b['last_request_time']) ? $b['last_request_time'] : '0');
                    return ($time_b > $time_a) ? 1 : (($time_b < $time_a) ? -1 : 0);
                }
                
                return ($count_b > $count_a) ? 1 : -1; // От большего к меньшему
            });
            
            return [
                'data' => $result,
                'total' => $total_keys
            ];
        } catch (Exception $e) {
            error_log("Error getting IP request rates from Redis: " . $e->getMessage());
            return [
                'data' => array(),
                'total' => 0
            ];
        }
    }
    
    // Получение частоты запросов IP с пагинацией
    public function getIPRequestRates($limit = 25, $page = 1) {
        $offset = ($page - 1) * $limit;
        
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            $redisResult = $this->getIPRequestRatesRedis($limit, $offset);
            if (!empty($redisResult)) {
                return $redisResult;
            }
        }
        
        // Иначе через MariaDB
        try {
            if (!$this->db) {
                $this->connectDB();
                if (!$this->db) {
                    return [
                        'data' => array(),
                        'total' => 0
                    ];
                }
            }
            
            // Сначала получаем общее количество записей для пагинации
            $stmt = $this->db->query("SELECT COUNT(*) FROM ip_request_rate");
            $total_count = $stmt->fetchColumn();
            
            // Затем получаем данные с применением лимита и смещения
            $stmt = $this->db->prepare("
                SELECT ip, request_count, first_request_time, last_request_time
                FROM ip_request_rate
                ORDER BY request_count DESC, last_request_time DESC
                LIMIT ?, ?
            ");
            $stmt->bindParam(1, $offset, PDO::PARAM_INT);
            $stmt->bindParam(2, $limit, PDO::PARAM_INT);
            $stmt->execute();
            
            return [
                'data' => $stmt->fetchAll(PDO::FETCH_ASSOC),
                'total' => $total_count
            ];
        } catch(PDOException $e) {
            error_log("Ошибка при получении данных о частоте запросов IP: " . $e->getMessage());
            return [
                'data' => array(),
                'total' => 0
            ];
        }
    }
	// Получение подозрительных запросов через Redis с пагинацией
    private function getSuspiciousRequestsRedis($limit = 25, $offset = 0) {
        if (!$this->redis) return ['data' => array(), 'total' => 0];
        
        try {
            $result = array();
            
            // Оптимизированный метод определения количества записей
            $pattern = $this->prefix . "request:*";
            $allKeys = $this->redis->keys($pattern);
            $total = count($allKeys);
            
            // Сортировка ключей по времени создания (не все ключи, а только необходимая выборка)
            $sortedKeys = array();
            
            // Получаем только ключи, которые нужны для текущей страницы
            // Это намного эффективнее, чем обрабатывать все записи
            $batchSize = 100; // Обрабатываем по 100 записей за раз
            $pipeline = $this->redis->pipeline();
            
            // Группируем запросы в батчи для оптимизации
            for ($i = 0; $i < min($total, $batchSize); $i++) {
                $key = isset($allKeys[$i]) ? $allKeys[$i] : null;
                if (!$key) continue;
                $pipeline->hGet($key, 'request_time');
            }
            $times = $pipeline->exec();
            
            // Создаем массив "ключ => время" для сортировки
            for ($i = 0; $i < count($times); $i++) {
                $key = isset($allKeys[$i]) ? $allKeys[$i] : null;
                $time = isset($times[$i]) ? $times[$i] : 0;
                if (!$key || !$time) continue;
                $sortedKeys[$key] = (int)$time;
            }
            
            // Сортируем по времени (от нового к старому)
            arsort($sortedKeys);
            
            // Ограничиваем выборку для пагинации
            $paginatedKeys = array_keys(array_slice($sortedKeys, $offset, $limit, true));
            
            // Делаем батч-запрос для всех нужных записей
            if (!empty($paginatedKeys)) {
                $pipeline = $this->redis->pipeline();
                foreach ($paginatedKeys as $key) {
                    $pipeline->hGetAll($key);
                }
                $dataResults = $pipeline->exec();
                
                // Формируем результат
                foreach ($dataResults as $i => $data) {
                    if (!$data) continue;
                    
                    // Преобразуем временную метку в формат даты/времени MariaDB
                    if (isset($data['request_time'])) {
                        $data['request_time'] = date('Y-m-d H:i:s', (int)$data['request_time']);
                    }
                    
                    $result[] = $data;
                }
            }
            
            return [
                'data' => $result,
                'total' => $total
            ];
        } catch (Exception $e) {
            error_log("Error getting suspicious requests from Redis: " . $e->getMessage());
            return [
                'data' => array(),
                'total' => 0
            ];
        }
    }
    
    // Получение подозрительных запросов с пагинацией
    public function getSuspiciousRequests($limit = 25, $page = 1) {
        $offset = ($page - 1) * $limit;
        
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            $redisRequests = $this->getSuspiciousRequestsRedis($limit, $offset);
            if (!empty($redisRequests)) {
                return $redisRequests;
            }
        }
        
        // Иначе через MariaDB
        try {
            if (!$this->db) {
                $this->connectDB();
                if (!$this->db) {
                    return [
                        'data' => array(),
                        'total' => 0
                    ];
                }
            }
            
            // Сначала получаем общее количество записей для пагинации
            $stmt = $this->db->query("SELECT COUNT(*) FROM suspicious_requests");
            $total_count = $stmt->fetchColumn();
            
            // Затем получаем данные с применением лимита и смещения
            $stmt = $this->db->prepare("
                SELECT ip, user_agent, request_uri, request_time
                FROM suspicious_requests
                ORDER BY request_time DESC
                LIMIT ?, ?
            ");
            $stmt->bindParam(1, $offset, PDO::PARAM_INT);
            $stmt->bindParam(2, $limit, PDO::PARAM_INT);
            $stmt->execute();
            
            return [
                'data' => $stmt->fetchAll(PDO::FETCH_ASSOC),
                'total' => $total_count
            ];
        } catch(PDOException $e) {
            error_log("Ошибка при получении подозрительных запросов: " . $e->getMessage());
            return [
                'data' => array(),
                'total' => 0
            ];
        }
    }
    
    // Очистка таблицы частоты запросов IP через Redis
    private function clearIPRequestRatesRedis() {
        if (!$this->redis) return false;
        
        try {
            $pattern = $this->prefix . "ip_request_rate:*";
            $keys = $this->redis->keys($pattern);
            
            if (empty($keys)) {
                return true;
            }
            
            // Удаляем все ключи
            $this->redis->del($keys);
            
            return true;
        } catch (Exception $e) {
            error_log("Error clearing IP request rates in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    // Очистка таблицы частоты запросов IP
    public function clearIPRequestRates() {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            if ($this->clearIPRequestRatesRedis()) {
                return true;
            }
        }
        
        // Иначе через MariaDB
        try {
            if (!$this->db) {
                $this->connectDB();
                if (!$this->db) {
                    return false;
                }
            }
            
            $stmt = $this->db->prepare("TRUNCATE TABLE ip_request_rate");
            $stmt->execute();
            
            return $stmt->rowCount() !== false;
        } catch(PDOException $e) {
            error_log("Ошибка при очистке таблицы частоты запросов IP: " . $e->getMessage());
            return false;
        }
    }
    
    // Очистка таблицы подозрительных запросов через Redis
    private function clearSuspiciousRequestsRedis() {
        if (!$this->redis) return false;
        
        try {
            // Удаляем все записи подозрительных запросов
            $pattern = $this->prefix . "request:*";
            $keys = $this->redis->keys($pattern);
            
            if (!empty($keys)) {
                $this->redis->del($keys);
            }
            
            // Удаляем список всех подозрительных запросов
            $this->redis->del($this->prefix . "all_suspicious_requests");
            
            // Удаляем списки подозрительных запросов для каждого IP
            $pattern = $this->prefix . "suspicious_requests:*";
            $keys = $this->redis->keys($pattern);
            
            if (!empty($keys)) {
                $this->redis->del($keys);
            }
            
            return true;
        } catch (Exception $e) {
            error_log("Error clearing suspicious requests in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    // Очистка таблицы подозрительных запросов
    public function clearSuspiciousRequests() {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            if ($this->clearSuspiciousRequestsRedis()) {
                return true;
            }
        }
        
        // Иначе через MariaDB
        try {
            if (!$this->db) {
                $this->connectDB();
                if (!$this->db) {
                    return false;
                }
            }
            
            $stmt = $this->db->prepare("TRUNCATE TABLE suspicious_requests");
            $stmt->execute();
            
            return $stmt->rowCount() !== false;
        } catch(PDOException $e) {
            error_log("Ошибка при очистке таблицы подозрительных запросов: " . $e->getMessage());
            return false;
        }
    }
	// Получение статистики таблиц мониторинга через Redis
    private function getMonitoringStatsRedis() {
        if (!$this->redis) return array();
        
        try {
            $stats = array(
                'ip_request_rates' => array(
                    'count' => 0,
                    'stats' => array(
                        'max_requests' => 0,
                        'avg_requests' => 0,
                        'oldest_record' => 0,
                        'newest_record' => 0
                    )
                ),
                'suspicious_requests' => array(
                    'count' => 0,
                    'stats' => array(
                        'unique_ips' => 0,
                        'oldest_record' => 0,
                        'newest_record' => 0
                    )
                )
            );
            
            // Получаем статистику по частоте запросов IP
            $pattern = $this->prefix . "ip_request_rate:*";
            $keys = $this->redis->keys($pattern);
            $stats['ip_request_rates']['count'] = count($keys);
            
            if (!empty($keys)) {
                $max_requests = 0;
                $total_requests = 0;
                $oldest_record = PHP_INT_MAX;
                $newest_record = 0;
                
                foreach ($keys as $key) {
                    $request_count = (int)$this->redis->hGet($key, 'request_count');
                    $last_request_time = (int)$this->redis->hGet($key, 'last_request_time');
                    
                    $max_requests = max($max_requests, $request_count);
                    $total_requests += $request_count;
                    $oldest_record = min($oldest_record, $last_request_time);
                    $newest_record = max($newest_record, $last_request_time);
                }
                
                $stats['ip_request_rates']['stats']['max_requests'] = $max_requests;
                $stats['ip_request_rates']['stats']['avg_requests'] = count($keys) > 0 ? $total_requests / count($keys) : 0;
                $stats['ip_request_rates']['stats']['oldest_record'] = $oldest_record !== PHP_INT_MAX ? $oldest_record : 0;
                $stats['ip_request_rates']['stats']['newest_record'] = $newest_record;
            }
            
            // Получаем статистику по подозрительным запросам
            $pattern = $this->prefix . "request:*";
            $keys = $this->redis->keys($pattern);
            $stats['suspicious_requests']['count'] = count($keys);
            
            if (!empty($keys)) {
                $unique_ips = array();
                $oldest_record = PHP_INT_MAX;
                $newest_record = 0;
                
                foreach ($keys as $key) {
                    $ip = $this->redis->hGet($key, 'ip');
                    $request_time = (int)$this->redis->hGet($key, 'request_time');
                    
                    if ($ip) {
                        $unique_ips[$ip] = 1;
                    }
                    
                    $oldest_record = min($oldest_record, $request_time);
                    $newest_record = max($newest_record, $request_time);
                }
                
                $stats['suspicious_requests']['stats']['unique_ips'] = count($unique_ips);
                $stats['suspicious_requests']['stats']['oldest_record'] = $oldest_record !== PHP_INT_MAX ? $oldest_record : 0;
                $stats['suspicious_requests']['stats']['newest_record'] = $newest_record;
            }
            
            return $stats;
        } catch (Exception $e) {
            error_log("Error getting monitoring stats from Redis: " . $e->getMessage());
            return array();
        }
    }
    
    // Получение статистики таблиц мониторинга
    public function getMonitoringStats() {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            $redisStats = $this->getMonitoringStatsRedis();
            if (!empty($redisStats)) {
                return $redisStats;
            }
        }
        
        // Иначе через MariaDB
        try {
            if (!$this->db) {
                $this->connectDB();
                if (!$this->db) {
                    return array(
                        'ip_request_rates' => array(
                            'count' => 0,
                            'stats' => array()
                        ),
                        'suspicious_requests' => array(
                            'count' => 0,
                            'stats' => array()
                        )
                    );
                }
            }
            
            // Количество записей в таблице частоты запросов IP
            $stmt = $this->db->query("SELECT COUNT(*) FROM ip_request_rate");
            $ip_request_rates_count = $stmt->fetchColumn();
            
            // Количество записей в таблице подозрительных запросов
            $stmt = $this->db->query("SELECT COUNT(*) FROM suspicious_requests");
            $suspicious_requests_count = $stmt->fetchColumn();
            
            // Статистика по таблице частоты запросов IP
            $stmt = $this->db->query("
                SELECT 
                    MAX(request_count) as max_requests, 
                    AVG(request_count) as avg_requests,
                    MIN(UNIX_TIMESTAMP(last_request_time)) as oldest_record,
                    MAX(UNIX_TIMESTAMP(last_request_time)) as newest_record
                FROM ip_request_rate
            ");
            $ip_request_rates_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Статистика по таблице подозрительных запросов
            $stmt = $this->db->query("
                SELECT 
                    COUNT(DISTINCT ip) as unique_ips,
                    MIN(UNIX_TIMESTAMP(request_time)) as oldest_record,
                    MAX(UNIX_TIMESTAMP(request_time)) as newest_record
                FROM suspicious_requests
            ");
            $suspicious_requests_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return array(
                'ip_request_rates' => array(
                    'count' => $ip_request_rates_count,
                    'stats' => $ip_request_rates_stats
                ),
                'suspicious_requests' => array(
                    'count' => $suspicious_requests_count,
                    'stats' => $suspicious_requests_stats
                )
            );
        } catch(PDOException $e) {
            error_log("Ошибка при получении статистики таблиц мониторинга: " . $e->getMessage());
            return array(
                'ip_request_rates' => array(
                    'count' => 0,
                    'stats' => array()
                ),
                'suspicious_requests' => array(
                    'count' => 0,
                    'stats' => array()
                )
            );
        }
    }
	// Статистика блокировок через Redis
    private function getBlockingStatsRedis() {
        if (!$this->redis) return array();
        
        try {
            $stats = array(
                'total_blocked' => 0,
                'repeat_blocks' => 0,
                'longest_blocks' => array(),
                'latest_blocks' => array()
            );
            
            $now = time();
            $blockedIpsKey = $this->prefix . "blocked_ips";
            
            // Получаем все активные блокировки
            $blockedList = $this->redis->zRangeByScore($blockedIpsKey, $now, '+inf', array('WITHSCORES' => true));
            $stats['total_blocked'] = count($blockedList);
            
            // Счетчик повторных блокировок и сбор информации о блокировках
            $blockInfos = array();
            foreach ($blockedList as $ip => $blockUntil) {
                $blockKey = $this->prefix . "blocked_ip:$ip";
                if (!$this->redis->exists($blockKey)) {
                    continue;
                }
                
                $blockInfo = $this->redis->hGetAll($blockKey);
                if (!$blockInfo) {
                    continue;
                }
                
                // Преобразуем строковые значения в числовые
                $blockInfo['block_count'] = (int)$blockInfo['block_count'];
                $blockInfo['block_until'] = (int)$blockInfo['block_until'];
                $blockInfo['created_at'] = (int)$blockInfo['created_at'];
                $blockInfo['first_blocked_at'] = (int)$blockInfo['first_blocked_at'];
                
                // Добавляем IP в blockInfo
                $blockInfo['ip'] = $ip;
                
                // Считаем повторные блокировки
                if ($blockInfo['block_count'] > 1) {
                    $stats['repeat_blocks']++;
                }
                
                // Собираем информацию для самых долгих блокировок и последних блокировок
                $blockInfos[] = $blockInfo;
            }
            
            // Сортировка по времени блокировки (от больших к меньшим) для самых долгих блокировок
            usort($blockInfos, function($a, $b) {
                return $b['block_until'] - $a['block_until'];
            });
            
            // Выбираем топ-5 самых долгих блокировок
            $stats['longest_blocks'] = array_slice($blockInfos, 0, 5);
            
            // Преобразуем временные метки в MySQL datetime формат для совместимости с MariaDB
            foreach ($stats['longest_blocks'] as &$block) {
                $block['block_until'] = date('Y-m-d H:i:s', $block['block_until']);
            }
            
            // Сортировка по времени создания (от новых к старым) для последних блокировок
            usort($blockInfos, function($a, $b) {
                return $b['created_at'] - $a['created_at'];
            });
            
            // Выбираем топ-5 последних блокировок
            $stats['latest_blocks'] = array_slice($blockInfos, 0, 5);
            
            // Преобразуем временные метки в MySQL datetime формат для совместимости с MariaDB
            foreach ($stats['latest_blocks'] as &$block) {
                $block['created_at'] = date('Y-m-d H:i:s', $block['created_at']);
            }
            
            return $stats;
        } catch (Exception $e) {
            error_log("Error getting blocking stats from Redis: " . $e->getMessage());
            return array(
                'total_blocked' => 0,
                'repeat_blocks' => 0,
                'longest_blocks' => array(),
                'latest_blocks' => array()
            );
        }
    }
    
    // Проверка активности Redis
    public function isRedisActive() {
        return $this->useRedis && $this->redis !== null;
    }
    
    // Получение информации о Redis
    public function getRedisInfo() {
        return $this->redisInfo;
    }
    
    // Сбор информации о Redis
    private function collectRedisInfo() {
        if (!$this->redis) return;
        
        try {
            // Получаем информацию о Redis
            $info = $this->redis->info();
            
            // Базовая информация
            $this->redisInfo['version'] = isset($info['redis_version']) ? $info['redis_version'] : 'н/д';
            $this->redisInfo['connected_clients'] = isset($info['connected_clients']) ? $info['connected_clients'] : 'н/д';
            
            // Информация о памяти
            if (isset($info['used_memory_human'])) {
                $this->redisInfo['memory_used'] = $info['used_memory_human'];
            } else if (isset($info['used_memory'])) {
                $memory_mb = round($info['used_memory'] / (1024 * 1024), 2);
                $this->redisInfo['memory_used'] = $memory_mb . ' MB';
            } else {
                $this->redisInfo['memory_used'] = 'н/д';
            }
            
            // Дополнительная информация об общей и свободной памяти
            if (isset($info['maxmemory_human']) && $info['maxmemory_human'] !== '0B') {
                $this->redisInfo['total_memory'] = $info['maxmemory_human'];
                
                // Расчет свободной памяти
                if (isset($info['maxmemory']) && isset($info['used_memory'])) {
                    $free_memory = $info['maxmemory'] - $info['used_memory'];
                    $free_memory_mb = round($free_memory / (1024 * 1024), 2);
                    $this->redisInfo['free_memory'] = $free_memory_mb . 'MB';
                    
                    // Процент использования
                    $usage_percent = round(($info['used_memory'] / $info['maxmemory']) * 100, 1);
                    $this->redisInfo['memory_percent'] = $usage_percent . '%';
                }
            } else if (isset($info['total_system_memory_human'])) {
                // Если maxmemory не установлен, используем информацию о системной памяти
                $this->redisInfo['total_memory'] = $info['total_system_memory_human'];
                
                if (isset($info['total_system_memory']) && isset($info['used_memory'])) {
                    $free_memory = $info['total_system_memory'] - $info['used_memory'];
                    $free_memory_mb = round($free_memory / (1024 * 1024), 2);
                    $this->redisInfo['free_memory'] = $free_memory_mb . 'MB';
                    
                    // Процент использования
                    $usage_percent = round(($info['used_memory'] / $info['total_system_memory']) * 100, 1);
                    $this->redisInfo['memory_percent'] = $usage_percent . '%';
                }
            } else {
                $this->redisInfo['total_memory'] = 'н/д';
                $this->redisInfo['free_memory'] = 'н/д';
                $this->redisInfo['memory_percent'] = 'н/д';
            }
            
            // Дополнительная информация
            $this->redisInfo['uptime_days'] = isset($info['uptime_in_days']) ? $info['uptime_in_days'] : 'н/д';
            $this->redisInfo['keys'] = $this->getRedisKeyCount();
            
        } catch (Exception $e) {
            error_log("Error collecting Redis info: " . $e->getMessage());
            $this->redisInfo = array(
                'version' => 'ошибка',
                'connected_clients' => 'ошибка',
                'memory_used' => 'ошибка',
                'total_memory' => 'ошибка',
                'free_memory' => 'ошибка',
                'memory_percent' => 'ошибка',
                'uptime_days' => 'ошибка',
                'keys' => 'ошибка'
            );
        }
	}
	// Получение количества ключей в Redis
    private function getRedisKeyCount() {
        if (!$this->redis) return 'н/д';
        
        try {
            // Получаем количество ключей с нашим префиксом
            $pattern = $this->prefix . '*';
            $keys = $this->redis->keys($pattern);
            return count($keys);
        } catch (Exception $e) {
            error_log("Error counting Redis keys: " . $e->getMessage());
            return 'ошибка';
        }
    }
    
    // Статистика блокировок
    public function getBlockingStats() {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            $redisStats = $this->getBlockingStatsRedis();
            if (!empty($redisStats)) {
                return $redisStats;
            }
        }
        
        // Иначе через MariaDB
        try {
            if (!$this->db) {
                $this->connectDB();
                if (!$this->db) {
                    return array(
                        'total_blocked' => 0,
                        'repeat_blocks' => 0,
                        'longest_blocks' => array(),
                        'latest_blocks' => array()
                    );
                }
            }
            
            // Общее количество заблокированных IP
            $stmt = $this->db->query("SELECT COUNT(*) FROM blocked_ips WHERE block_until > NOW()");
            $total_blocked = $stmt->fetchColumn();
            
            // Количество повторных блокировок
            $stmt = $this->db->query("SELECT COUNT(*) FROM blocked_ips WHERE block_count > 1 AND block_until > NOW()");
            $repeat_blocks = $stmt->fetchColumn();
            
            // Самые долгие блокировки
            $stmt = $this->db->query("
                SELECT ip, block_count, block_until
                FROM blocked_ips 
                WHERE block_until > NOW()
                ORDER BY block_until DESC
                LIMIT 5
            ");
            $longest_blocks = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Последние блокировки
            $stmt = $this->db->query("
                SELECT ip, block_count, created_at, reason
                FROM blocked_ips 
                WHERE block_until > NOW()
                ORDER BY created_at DESC
                LIMIT 5
            ");
            $latest_blocks = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            return array(
                'total_blocked' => $total_blocked,
                'repeat_blocks' => $repeat_blocks,
                'longest_blocks' => $longest_blocks,
                'latest_blocks' => $latest_blocks
            );
        } catch(PDOException $e) {
            error_log("Error getting blocking stats: " . $e->getMessage());
            return array(
                'total_blocked' => 0,
                'repeat_blocks' => 0,
                'longest_blocks' => array(),
                'latest_blocks' => array()
            );
        }
    }
    
    // Очистка всех данных в Redis (с текущим префиксом)
    public function clearRedisData() {
        if (!$this->useRedis || !$this->redis) {
            return false;
        }
        
        try {
            // Получаем все ключи с нашим префиксом
            $pattern = $this->prefix . '*';
            $keys = $this->redis->keys($pattern);
            
            if (empty($keys)) {
                return true; // Нет данных для очистки
            }
            
            // Удаляем все ключи
            $this->redis->del($keys);
            
            // Логируем действие
            error_log("Redis cache cleared. Deleted " . count($keys) . " keys with prefix " . $this->prefix);
            
            return true;
        } catch (Exception $e) {
            error_log("Error clearing Redis data: " . $e->getMessage());
            return false;
        }
    }
    
    // Метод для удаления дублирующихся правил iptables
    public function cleanupIptablesDuplicates() {
        // Проверяем настройки
        if ((defined('ENABLE_FIREWALL_BLOCKING') && !ENABLE_FIREWALL_BLOCKING)) {
            return false;
        }
        
        $total_removed = 0;
        
        // Выполнить очистку для IPv4
        $ipv4_removed = $this->cleanupIptablesDuplicatesForVersion(false);
        
        // Выполнить очистку для IPv6
        $ipv6_removed = $this->cleanupIptablesDuplicatesForVersion(true);
        
        return $ipv4_removed + $ipv6_removed;
    }
    
    // Очистка дублирующихся правил для конкретной версии IP
    private function cleanupIptablesDuplicatesForVersion($isIPv6) {
        // Название команды для логов
        $commandType = $isIPv6 ? "ip6tables" : "iptables";
        error_log("Начало очистки дубликатов $commandType");
        
        // Временный файл для сохранения правил
        $tempFile = tempnam(sys_get_temp_dir(), 'iptables_rules_');
        
        // Сохраняем текущие правила во временный файл
        $saveCommand = $isIPv6 ? 
            "sudo ip6tables-save > $tempFile" : 
            "sudo iptables-save > $tempFile";
        
        exec($saveCommand);
        
        // Читаем содержимое файла
        $output = file($tempFile);
        
        // Удаляем временный файл
        unlink($tempFile);
        
        // Массивы для учета IP-адресов с портами
        $uniqueRules = array();
        $duplicateRules = array();
        
        // Проходим по всем правилам
        foreach ($output as $line) {
            $line = trim($line);
            
            // Интересуют только правила для цепочки INPUT с DROP
            if (strpos($line, '-A INPUT') !== 0 || strpos($line, '-j DROP') === false) {
                continue;
            }
            
            // Извлекаем IP-адрес и порт
            if (preg_match('/-s\s+(\S+).*--dport\s+(\d+)/', $line, $matches)) {
                $ip = $matches[1];
                $port = $matches[2];
                
                // Проверяем, соответствует ли IP-адрес нужной версии
                $isIPv6Address = (strpos($ip, ':') !== false);
                if ($isIPv6 != $isIPv6Address) {
                    continue; // Пропускаем, если версия IP не соответствует ожидаемой
                }
                
                $key = "$ip:$port";
                
                if (!isset($uniqueRules[$key])) {
                    // Первое встреченное правило сохраняем как уникальное
                    $uniqueRules[$key] = $line;
                } else {
                    // Все последующие - добавляем в дубликаты
                    if (!isset($duplicateRules[$key])) {
                        $duplicateRules[$key] = array();
                    }
                    $duplicateRules[$key][] = array('ip' => $ip, 'port' => $port);
                }
            }
        }
        
        $removed_count = 0;
        
        // Удаляем найденные дубликаты
        foreach ($duplicateRules as $key => $rules) {
            list($ip, $port) = explode(':', $key);
            error_log("$commandType: Найдены дубликаты для IP $ip на порту $port: " . (count($rules) + 1) . " правил");
            
            foreach ($rules as $rule) {
                $delCommand = $isIPv6 ? 
                    "sudo ip6tables -D INPUT -s " . escapeshellarg($rule['ip']) . " -p tcp -m tcp --dport " . $rule['port'] . " -j DROP" : 
                    "sudo iptables -D INPUT -s " . escapeshellarg($rule['ip']) . " -p tcp -m tcp --dport " . $rule['port'] . " -j DROP";
                
                $cmdOutput = array();
                $returnVar = 0;
                exec($delCommand, $cmdOutput, $returnVar);
                
                if ($returnVar === 0) {
                    $removed_count++;
                    error_log("Успешно удалено дублирующееся правило $commandType для $ip:$port");
                } else {
                    error_log("Ошибка при удалении правила $commandType для $ip:$port: " . implode(", ", $cmdOutput));
                }
                
                // Небольшая пауза между командами
                usleep(100000); // 100ms
            }
        }
        
        // Сохраняем изменения
        if ($removed_count > 0) {
            error_log("Всего удалено $removed_count дублирующихся правил $commandType");
            $this->saveIptablesRules($isIPv6);
        } else {
            error_log("Дублирующиеся правила не найдены для $commandType");
        }
        
        return $removed_count;
    }
}
// Создаем экземпляр класса администратора
$admin = new SecurityAdmin();

// Обработка очистки дубликатов правил iptables
if (isset($_POST['cleanup_iptables_duplicates'])) {
    $removed_count = $admin->cleanupIptablesDuplicates();
    if ($removed_count > 0) {
        $successMessage = "Дублирующиеся правила iptables успешно очищены. Удалено правил: $removed_count";
    } else {
        $successMessage = "Дублирующиеся правила не найдены или брандмауэр отключен";
    }
}

// Обработка разблокировки IP
if (isset($_POST['unblock']) && !empty($_POST['ip'])) {
    $ip = trim($_POST['ip']);
    if ($admin->unblockIP($ip)) {
        $successMessage = "IP-адрес $ip успешно разблокирован";
    } else {
        $errorMessage = "Не удалось разблокировать IP-адрес $ip";
    }
}

// Обработка массовой разблокировки IP
if (isset($_POST['unblock_all']) && isset($_POST['confirm_unblock_all']) && $_POST['confirm_unblock_all'] === 'yes') {
    $unblocked_count = $admin->unblockAllIPs();
    if ($unblocked_count > 0) {
        $successMessage = "Все IP-адреса успешно разблокированы. Разблокировано: $unblocked_count";
    } else {
        $successMessage = "Нет заблокированных IP-адресов для разблокировки";
    }
}

// Обработка добавления в белый список
if (isset($_POST['add_to_whitelist']) && !empty($_POST['whitelist_ip'])) {
    $ip = trim($_POST['whitelist_ip']);
    
    // Проверка формата IP или CIDR
    if (filter_var($ip, FILTER_VALIDATE_IP) || $admin->validateCIDR($ip)) {
        if ($admin->addToWhitelist($ip)) {
            $successMessage = "IP-адрес $ip успешно добавлен в белый список";
        } else {
            $errorMessage = "Не удалось добавить IP-адрес $ip в белый список";
        }
    } else {
        $errorMessage = "Некорректный формат IP-адреса или CIDR-диапазона";
    }
}

// Обработка удаления из белого списка
if (isset($_POST['remove_from_whitelist']) && !empty($_POST['ip'])) {
    $ip = trim($_POST['ip']);
    if ($admin->removeFromWhitelist($ip)) {
        $successMessage = "IP-адрес $ip успешно удален из белого списка";
    } else {
        $errorMessage = "Не удалось удалить IP-адрес $ip из белого списка";
    }
}

// Обработка очистки таблицы частоты запросов IP
if (isset($_POST['clear_ip_request_rates'])) {
    if ($admin->clearIPRequestRates()) {
        $successMessage = "Таблица частоты запросов IP успешно очищена";
    } else {
        $errorMessage = "Не удалось очистить таблицу частоты запросов IP";
    }
}

// Обработка очистки таблицы подозрительных запросов
if (isset($_POST['clear_suspicious_requests'])) {
    if ($admin->clearSuspiciousRequests()) {
        $successMessage = "Таблица подозрительных запросов успешно очищена";
    } else {
        $errorMessage = "Не удалось очистить таблицу подозрительных запросов";
    }
}

// Обработка очистки Redis
if (isset($_POST['clear_redis_data'])) {
    if ($admin->clearRedisData()) {
        $successMessage = "Данные Redis успешно очищены";
    } else {
        $errorMessage = "Не удалось очистить данные Redis";
    }
}

// Обработка просмотра истории
$historyIP = null;
$requestHistory = array();
if (isset($_GET['history']) && !empty($_GET['ip'])) {
    $historyIP = trim($_GET['ip']);
    $requestHistory = $admin->getRequestHistory($historyIP);
}

// Определяем активную страницу и параметры пагинации
$active_page = isset($_GET['page']) ? $_GET['page'] : 'blocked';
$current_page = isset($_GET['p']) ? max(1, intval($_GET['p'])) : 1;
$per_page = 25; // Количество записей на странице

// Получаем данные в зависимости от активной страницы
$blocked_ips = array();
$ip_request_rates = array();
$suspicious_requests = array();
$monitoring_stats = array();
$pagination = array('total' => 0, 'pages' => 1, 'current' => $current_page);

if ($active_page == 'blocked') {
    // Получаем данные с пагинацией
    $offset = ($current_page - 1) * $per_page;
    $result = $admin->getBlockedIPs($per_page, $offset);
    
    $blocked_ips = $result['data'];
    $total_blocked = $result['total'];
    
    $pagination['total'] = $total_blocked;
    $pagination['pages'] = ceil($total_blocked / $per_page);
    $pagination['current'] = $current_page;
} elseif ($active_page == 'rates') {
    // Получаем данные с пагинацией
    $result = $admin->getIPRequestRates($per_page, $current_page);
    $ip_request_rates = $result['data'];
    $total_ip_rates = $result['total'];
    $pagination['total'] = $total_ip_rates;
    $pagination['pages'] = ceil($total_ip_rates / $per_page);
    $pagination['current'] = $current_page;
    
    $monitoring_stats = $admin->getMonitoringStats();
} elseif ($active_page == 'suspicious') {
    // Получаем данные с пагинацией
    $result = $admin->getSuspiciousRequests($per_page, $current_page);
    $suspicious_requests = $result['data'];
    $total_suspicious = $result['total'];
    $pagination['total'] = $total_suspicious;
    $pagination['pages'] = ceil($total_suspicious / $per_page);
    $pagination['current'] = $current_page;
    
    $monitoring_stats = $admin->getMonitoringStats();
}

// Получаем список IP в белом списке
$whitelisted_ips = $admin->getWhitelistedIPs();

// Определяем текущий IP
$current_ip = $admin->getClientIP();

// Получаем статистику блокировок
$blocking_stats = $admin->getBlockingStats();

// Определяем тип IP для подсказок
$is_ipv6 = filter_var($current_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
// Заголовки для предотвращения кеширования и правильного отображения кодировки
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Content-Type: text/html; charset=utf-8");
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Панель управления безопасностью</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #3498db;
            --primary-dark: #2980b9;
            --secondary-color: #2ecc71;
            --secondary-dark: #27ae60;
            --danger-color: #e74c3c;
            --danger-dark: #c0392b;
            --warning-color: #f39c12;
            --warning-dark: #d35400;
            --light-color: #f8f9fa;
            --dark-color: #343a40;
            --gray-color: #6c757d;
            --border-color: #dee2e6;
            --success-bg: #d4edda;
            --success-text: #155724;
            --danger-bg: #f8d7da;
            --danger-text: #721c24;
            --card-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Roboto', -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            min-height: 100vh;
            overflow-x: hidden;
        }

        .container {
            width: 100%;
            max-width: 1280px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: var(--card-shadow);
            border-radius: 10px;
            margin-top: 20px;
            margin-bottom: 20px;
        }

        @media (max-width: 768px) {
            .container {
                margin-top: 0;
                margin-bottom: 0;
                border-radius: 0;
                padding: 15px;
            }
        }

        /* Заголовки */
        h1 {
            color: var(--dark-color);
            font-size: 28px;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
            font-weight: 500;
        }

        h2 {
            color: var(--primary-color);
            font-size: 22px;
            margin: 25px 0 15px;
            font-weight: 500;
        }

        /* Таблицы */
        .table-container {
            overflow-x: auto;
            margin-bottom: 25px;
            border-radius: 8px;
            box-shadow: var(--card-shadow);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            border-radius: 8px;
            overflow: hidden;
        }

        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background-color: var(--light-color);
            font-weight: 500;
            color: var(--dark-color);
            position: sticky;
            top: 0;
            z-index: 1;
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover {
            background-color: rgba(52, 152, 219, 0.05);
        }

        /* Карточки и дашборд */
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background-color: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: var(--card-shadow);
            transition: var(--transition);
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
        }

        .stat-card h3 {
            color: var(--dark-color);
            margin-top: 0;
            font-size: 18px;
            margin-bottom: 15px;
            font-weight: 500;
        }

        .stat-value {
            font-size: 38px;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 15px;
        }

        .stat-list {
            list-style-type: none;
            padding: 0;
        }

        .stat-list li {
            padding: 10px 0;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
        }

        .stat-list li:last-child {
            border-bottom: none;
        }

        /* Кнопки */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 8px 16px;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            font-weight: 500;
            font-size: 14px;
            transition: var(--transition);
            text-decoration: none;
            white-space: nowrap;
            color: white;
            background-color: var(--primary-color);
            margin-right: 8px;
            margin-bottom: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
            opacity: 0.95;
        }

        .btn:active {
            transform: translateY(0);
        }

        .btn i {
            margin-right: 6px;
        }

        .btn-success {
            background-color: var(--secondary-color);
        }

        .btn-danger {
            background-color: var(--danger-color);
        }

        .btn-warning {
            background-color: var(--warning-color);
        }

        .btn-info {
            background-color: var(--primary-color);
        }

        .btn-sm {
            padding: 6px 12px;
            font-size: 12px;
        }

        .btn-block {
            display: block;
            width: 100%;
        }

        /* Формы */
        .form-group {
            margin-bottom: 20px;
        }

        .form-inline {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 15px;
            margin-bottom: 25px;
        }

        input[type="text"], 
        input[type="password"],
        select,
        textarea {
            padding: 10px 15px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 14px;
            width: 100%;
            transition: var(--transition);
        }

        input[type="text"]:focus, 
        input[type="password"]:focus,
        select:focus,
        textarea:focus {
            border-color: var(--primary-color);
            outline: none;
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
        }

        .form-control {
            width: 100%;
            max-width: 100%;
        }

        /* Уведомления */
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 6px;
            border-left: 5px solid;
            position: relative;
        }

        .alert-success {
            background-color: var(--success-bg);
            color: var(--success-text);
            border-left-color: var(--secondary-color);
        }

        .alert-danger {
            background-color: var(--danger-bg);
            color: var(--danger-text);
            border-left-color: var(--danger-color);
        }

        /* Значки и индикаторы */
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
            text-align: center;
            margin-left: 8px;
            background-color: var(--gray-color);
            color: white;
        }

        .badge-primary {
            background-color: var(--primary-color);
        }

        .badge-success {
            background-color: var(--secondary-color);
        }

        .badge-danger {
            background-color: var(--danger-color);
        }

        .badge-warning {
            background-color: var(--warning-color);
        }

        .count-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 22px;
            height: 22px;
            padding: 0 8px;
            border-radius: 20px;
            background-color: var(--dark-color);
            color: white;
            font-size: 13px;
            font-weight: 700;
            margin-left: 8px;
        }

        .block-count-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 20px;
            color: white;
            font-weight: 500;
            margin-left: 5px;
            font-size: 12px;
        }

        .block-count-badge.low {
            background-color: var(--warning-color);
        }

        .block-count-badge.medium {
            background-color: var(--danger-color);
        }

        .block-count-badge.high {
            background-color: var(--danger-dark);
        }

        .status-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-left: 5px;
        }

        .status-dot.active {
            background-color: var(--secondary-color);
            box-shadow: 0 0 5px var(--secondary-color);
            animation: pulse 2s infinite;
        }

        .status-dot.inactive {
            background-color: var(--danger-color);
        }

        @keyframes pulse {
            0% {
                box-shadow: 0 0 0 0 rgba(46, 204, 113, 0.6);
            }
            70% {
                box-shadow: 0 0 0 5px rgba(46, 204, 113, 0);
            }
            100% {
                box-shadow: 0 0 0 0 rgba(46, 204, 113, 0);
            }
        }

        /* Навигация и табы */
        .tabs {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            margin-bottom: 25px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1px;
            position: sticky;
            top: 0;
            background-color: white;
            z-index: 10;
            padding-top: 10px;
        }

        .tab {
            padding: 10px 20px;
            cursor: pointer;
            background-color: var(--light-color);
            border: 1px solid transparent;
            border-bottom: none;
            margin-right: 5px;
            border-radius: 8px 8px 0 0;
            font-weight: 500;
            transition: var(--transition);
            text-decoration: none;
            color: var(--dark-color);
        }

        .tab.active {
            background-color: white;
            border-color: var(--border-color);
            border-bottom-color: white;
            margin-bottom: -1px;
            color: var(--primary-color);
            box-shadow: 0 -4px 8px -4px rgba(0, 0, 0, 0.1);
        }

        .tab:hover:not(.active) {
            background-color: rgba(52, 152, 219, 0.1);
        }

        /* Пагинация */
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            flex-wrap: wrap;
            margin: 25px 0;
            gap: 10px;
        }

        .pagination-info {
            padding: 8px 15px;
            background-color: var(--light-color);
            border-radius: 6px;
            font-size: 14px;
            color: var(--dark-color);
        }

        /* Дополнительные компоненты */
        .tooltip {
            position: relative;
            display: inline-block;
            margin-left: 5px;
            cursor: help;
        }

        .tooltip i {
            color: var(--primary-color);
            font-size: 16px;
        }

        .tooltip .tooltiptext {
            visibility: hidden;
            width: 280px;
            background-color: var(--dark-color);
            color: white;
            text-align: left;
            border-radius: 6px;
            padding: 10px 15px;
            position: absolute;
            z-index: 100;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            opacity: 0;
            transition: opacity 0.3s, transform 0.3s;
            transform-origin: bottom center;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            font-weight: 400;
            font-size: 13px;
            line-height: 1.5;
            pointer-events: none;
        }

        .tooltip .tooltiptext::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: var(--dark-color) transparent transparent transparent;
        }

        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
            transform: translateX(-50%) translateY(-10px);
        }

        .info-box {
            padding: 15px;
            background-color: #e7f4fd;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 5px solid var(--primary-color);
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
        }

        .storage-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 6px;
            color: white;
            font-weight: 500;
            margin-left: 8px;
            font-size: 14px;
        }

        .storage-badge.redis {
            background-color: #dc382d;
        }

        .storage-badge.mysql {
            background-color: #00758f;
        }

        .storage-badge.disabled {
            background-color: #999;
            opacity: 0.5;
        }

        .storage-info {
            font-size: 13px;
            color: var(--gray-color);
            margin-left: 10px;
            display: block;
            margin-top: 5px;
        }

        .dns-settings {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }

        /* Сворачиваемые разделы */
        .collapsible-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            padding: 5px 0;
            transition: var(--transition);
        }

        .collapsible-header:hover {
            color: var(--primary-color);
        }

        .collapsible-toggle {
            font-size: 16px;
            color: var(--primary-color);
            transition: transform 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            background-color: rgba(52, 152, 219, 0.1);
        }

        .collapsible-toggle.collapsed {
            transform: rotate(-90deg);
        }

        .collapsible-content {
            transition: max-height 0.5s ease-out;
            overflow: hidden;
        }

        .hidden {
            display: none;
        }

        /* Шапка и футер */
        .header-flex {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .refresh {
            display: inline-flex;
            align-items: center;
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 500;
            transition: var(--transition);
        }

        .refresh i {
            margin-right: 5px;
        }

        .refresh:hover {
            color: var(--primary-dark);
            transform: translateY(-2px);
        }

        /* Утилиты */
        .ip-label {
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-weight: 500;
        }

        .highlight {
            background-color: rgba(52, 152, 219, 0.08);
        }

        .text-muted {
            color: var(--gray-color);
            font-size: 0.9em;
        }

        .mt-0 { margin-top: 0 !important; }
        .mt-1 { margin-top: 0.25rem !important; }
        .mt-2 { margin-top: 0.5rem !important; }
        .mt-3 { margin-top: 1rem !important; }
        .mt-4 { margin-top: 1.5rem !important; }
        .mt-5 { margin-top: 3rem !important; }

        .mb-0 { margin-bottom: 0 !important; }
        .mb-1 { margin-bottom: 0.25rem !important; }
        .mb-2 { margin-bottom: 0.5rem !important; }
        .mb-3 { margin-bottom: 1rem !important; }
        .mb-4 { margin-bottom: 1.5rem !important; }
        .mb-5 { margin-bottom: 3rem !important; }

        .p-0 { padding: 0 !important; }
        .p-1 { padding: 0.25rem !important; }
        .p-2 { padding: 0.5rem !important; }
        .p-3 { padding: 1rem !important; }
        .p-4 { padding: 1.5rem !important; }
        .p-5 { padding: 3rem !important; }

        /* Адаптивность для мобильных */
        @media (max-width: 768px) {
            h1 {
                font-size: 24px;
            }

            h2 {
                font-size: 20px;
            }

            .header-flex {
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }

            .form-inline {
                flex-direction: column;
                align-items: stretch;
                width: 100%;
                gap: 10px;
            }

            .form-inline .btn {
                width: 100%;
            }

            .tab {
                padding: 8px 12px;
                font-size: 13px;
            }

            .tabs {
                overflow-x: auto;
                justify-content: flex-start;
                white-space: nowrap;
                padding-bottom: 10px;
            }

            .tabs::-webkit-scrollbar {
                height: 3px;
            }

            .tabs::-webkit-scrollbar-track {
                background: #f1f1f1;
            }

            .tabs::-webkit-scrollbar-thumb {
                background: var(--primary-color);
            }

            .dashboard {
                grid-template-columns: 1fr;
            }

            .table-container {
                margin-left: -15px;
                margin-right: -15px;
                width: calc(100% + 30px);
                border-radius: 0;
            }

            table {
                border-radius: 0;
            }

            .btn {
                padding: 8px 12px;
                font-size: 13px;
            }

            .stat-value {
                font-size: 28px;
            }

            .tooltip .tooltiptext {
                width: 220px;
                font-size: 12px;
                left: auto;
                right: 0;
                transform: none;
            }

            .tooltip:hover .tooltiptext {
                transform: translateY(-10px);
            }

            .tooltip .tooltiptext::after {
                left: auto;
                right: 10px;
            }
        }

        /* Анимации */
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .fade-in {
            animation: fadeIn 0.3s ease-in;
        }
    </style>
</head>
<body>

    <?php if ($historyIP): ?>
    <div class="container">
        <a href="admin.php" class="btn mb-4">
            <i class="fas fa-arrow-left"></i> Вернуться к списку блокировок
        </a>
        <h1>
            <i class="fas fa-history"></i> История запросов для IP: 
            <span class="ip-label"><?php echo htmlspecialchars($historyIP); ?></span>
        </h1>
        
        <div class="info-box mb-4">
            <p><strong>DNS-имя:</strong> <?php echo htmlspecialchars($admin->getHostByAddr($historyIP)); ?></p>
        </div>
        
        <?php if (empty($requestHistory)): ?>
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i> История запросов не найдена для этого IP.
            </div>
        <?php else: ?>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>URL запроса</th>
                            <th>User-Agent</th>
                            <th>Время запроса</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($requestHistory as $record): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($record['request_uri']); ?></td>
                                <td><?php echo htmlspecialchars($record['user_agent']); ?></td>
                                <td><?php echo htmlspecialchars($record['request_time']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
    <?php else: ?>

    <div class="container">
        <div class="header-flex">
            <h1>
                <i class="fas fa-shield-alt"></i> Панель управления безопасностью
            </h1>
            <a href="admin.php?page=<?php echo $active_page; ?>" class="refresh">
                <i class="fas fa-sync-alt"></i> Обновить
            </a>
        </div>
        
        <?php if ($auto_unblocked): ?>
            <div class="alert alert-success">
                <i class="fas fa-unlock-alt"></i> Ваш IP-адрес <?php echo htmlspecialchars($current_ip); ?> был автоматически разблокирован.
            </div>
        <?php endif; ?>
        
        <?php if (isset($successMessage)): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($successMessage); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($errorMessage)): ?>
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($errorMessage); ?>
            </div>
        <?php endif; ?>

        <!-- Индикатор активного хранилища данных -->
        <div class="storage-indicator mb-4">
            <strong>Активное хранилище:</strong>
            <?php if ($admin->isRedisActive()): ?>
                <span class="storage-badge redis">Redis <i class="status-dot active"></i></span>
                <?php 
                    $redis_info = $admin->getRedisInfo();
                    if (!empty($redis_info)):
                        $memory_info = htmlspecialchars($redis_info['memory_used']);
                        
                        // Добавляем информацию о общей и свободной памяти, если она доступна
                        if (isset($redis_info['total_memory']) && $redis_info['total_memory'] != 'н/д') {
                            $memory_info .= " из " . htmlspecialchars($redis_info['total_memory']) . ", ";
                            $memory_info .= "свободно: " . htmlspecialchars($redis_info['free_memory']) . " ";
                            $memory_info .= "(" . htmlspecialchars($redis_info['memory_percent']) . " занято)";
                        }
                ?>
                <span class="storage-info">
                    (<?php echo htmlspecialchars($redis_info['version']); ?>, 
                    память: <?php echo $memory_info; ?>, 
                    подключений: <?php echo htmlspecialchars($redis_info['connected_clients']); ?>)
                </span>
                <?php endif; ?>
                <!-- Добавляем кнопку очистки Redis -->
                <form method="post" style="display: inline-block; margin-left: 15px;" onsubmit="return confirm('Вы уверены, что хотите очистить все данные в Redis? Это действие нельзя отменить.');">
                    <button type="submit" name="clear_redis_data" class="btn btn-warning btn-sm">
                        <i class="fas fa-trash-alt"></i> Очистить Redis
                    </button>
                </form>
            <?php else: ?>
                <span class="storage-badge mysql">MySQL <i class="status-dot active"></i></span>
                <span class="storage-badge redis disabled">Redis <i class="status-dot inactive"></i></span>
            <?php endif; ?>
        </div>
        
        <!-- Настройки DNS-запросов -->
        <div class="dns-settings">
            <form method="post" style="display: inline-block;">
                <strong>DNS-запросы:</strong>
                <label style="margin-left: 10px; display: inline-flex; align-items: center;">
                    <input type="checkbox" name="disable_rdns" style="margin-right: 5px;" 
                        <?php echo ((defined('DISABLE_RDNS_LOOKUP') && DISABLE_RDNS_LOOKUP === true) || 
                                (isset($GLOBALS['DISABLE_RDNS_LOOKUP']) && $GLOBALS['DISABLE_RDNS_LOOKUP'] === true)) 
                                ? 'checked' : ''; ?>> 
                    Отключить обратные DNS-запросы 
                </label>
                <button type="submit" name="toggle_rdns" class="btn btn-sm" style="margin-left: 10px;">
                    <i class="fas fa-check"></i> Применить
                </button>
            </form>
            <small class="text-muted mt-2 d-block">
                Отключение DNS-запросов значительно ускоряет работу админ-панели при большом количестве IP-адресов, но не показывает доменные имена.
            </small>
        </div>

        <!-- Панель управления брандмауэром -->
        <div class="mb-4">
            <strong>Управление брандмауэром:</strong> 
            <div class="mt-2">
                <?php if (defined('API_BLOCK_URL') && defined('API_BLOCK_KEY')): ?>
                <a href="<?php echo API_BLOCK_URL; ?>?api_key=<?php echo urlencode(API_BLOCK_KEY); ?>" target="_blank" class="btn btn-info">
                    <i class="fas fa-shield-alt"></i> Управление правилами блокировки IP
                </a>
                <?php endif; ?>
                <a href="/dos/log-analyzer/LOGS.php" target="_blank" class="btn btn-info">
                    <i class="fas fa-chart-line"></i> Анализатор логов NGINX
                </a>
                <a href="/dos/settings-admin.php" target="_blank" class="btn btn-info">
                    <i class="fas fa-cog"></i> DOS Настройки
                </a>
                <a href="/dos/ip/ip.php" target="_blank" class="btn btn-info">
                    <i class="fas fa-door-open"></i> Открыть порт
                </a>
            </div>
        </div>

        <!-- Навигационные табы -->
        <div class="tabs">
            <a href="?page=blocked" class="tab <?php echo $active_page == 'blocked' ? 'active' : ''; ?>">
                <i class="fas fa-ban"></i> Блокировки IP
            </a>
            <a href="?page=rates" class="tab <?php echo $active_page == 'rates' ? 'active' : ''; ?>">
                <i class="fas fa-tachometer-alt"></i> Частота запросов IP
            </a>
            <a href="?page=suspicious" class="tab <?php echo $active_page == 'suspicious' ? 'active' : ''; ?>">
                <i class="fas fa-exclamation-triangle"></i> Подозрительные запросы
            </a>
            <a href="?page=hard_block_history" class="tab <?php echo $active_page == 'hard_block_history' ? 'active' : ''; ?>">
                <i class="fas fa-history"></i> История жестких блокировок
            </a>
        </div>

        <?php if ($active_page == 'blocked'): ?>
            <!-- Статистика блокировок -->
            <h2><i class="fas fa-chart-pie"></i> Статистика безопасности</h2>
            <div class="dashboard">
                <div class="stat-card">
                    <h3>Активные блокировки</h3>
                    <div class="stat-value"><?php echo $blocking_stats['total_blocked']; ?></div>
                    <p>Всего заблокированных IP-адресов</p>
                </div>
                
                <div class="stat-card">
                    <h3>Повторные блокировки</h3>
                    <div class="stat-value"><?php echo $blocking_stats['repeat_blocks']; ?></div>
                    <p>IP-адреса, блокируемые более одного раза</p>
                </div>
                
                <div class="stat-card">
                    <h3>Самые длительные блокировки</h3>
                    <ul class="stat-list">
                        <?php foreach ($blocking_stats['longest_blocks'] as $block): ?>
                            <li>
                                <span class="ip-label"><?php echo htmlspecialchars($block['ip']); ?></span>
                                <?php if ($block['block_count'] > 1): ?>
                                    <span class="block-count-badge <?php echo $block['block_count'] > 5 ? 'high' : ($block['block_count'] > 2 ? 'medium' : 'low'); ?>">
                                        #<?php echo $block['block_count']; ?>
                                    </span>
                                <?php endif; ?>
                                <div class="text-muted mt-1">
                                    До <?php echo date('d.m.Y H:i', strtotime($block['block_until'])); ?>
                                </div>
                            </li>
                        <?php endforeach; ?>
                        <?php if (empty($blocking_stats['longest_blocks'])): ?>
                            <li>Нет данных</li>
                        <?php endif; ?>
                    </ul>
                </div>
                
                <div class="stat-card">
                    <h3>Последние блокировки</h3>
                    <ul class="stat-list">
                        <?php foreach ($blocking_stats['latest_blocks'] as $block): ?>
                            <li>
                                <span class="ip-label"><?php echo htmlspecialchars($block['ip']); ?></span>
                                <?php if ($block['block_count'] > 1): ?>
                                    <span class="block-count-badge <?php echo $block['block_count'] > 5 ? 'high' : ($block['block_count'] > 2 ? 'medium' : 'low'); ?>">
                                        #<?php echo $block['block_count']; ?>
                                    </span>
                                <?php endif; ?>
                                <div class="text-muted mt-1">
                                    <?php echo date('d.m.Y H:i', strtotime($block['created_at'])); ?>
                                </div>
                            </li>
                        <?php endforeach; ?>
                        <?php if (empty($blocking_stats['latest_blocks'])): ?>
                            <li>Нет данных</li>
                        <?php endif; ?>
                    </ul>
                </div>
            </div>

            <?php if (defined('AUTO_HARD_BLOCK_ENABLED') && AUTO_HARD_BLOCK_ENABLED): ?>
            <div class="info-box">
                <h4 class="mt-0 mb-2"><i class="fas fa-shield-alt"></i> Автоматическая жесткая блокировка: <span class="badge badge-success">Включена</span></h4>
                <p class="mb-1">Порог активации: <strong><?php echo defined('AUTO_HARD_BLOCK_THRESHOLD') ? AUTO_HARD_BLOCK_THRESHOLD : 100; ?> IP-адресов</strong></p>
                <p class="mb-1">Метод блокировки: <strong><?php echo defined('AUTO_HARD_BLOCK_ACTION') ? strtoupper(AUTO_HARD_BLOCK_ACTION) : 'ALL'; ?></strong></p>
                <p class="mb-0">Текущее количество блокировок: <strong><?php echo $blocking_stats['total_blocked']; ?></strong></p>
            </div>
            <?php endif; ?>

            <!-- Сворачиваемый заголовок для белого списка -->
            <div class="collapsible-header" data-target="whitelist-content">
                <h2><i class="fas fa-check-circle"></i> Белый список IP-адресов <span class="count-badge"><?php echo count($whitelisted_ips); ?></span></h2>
                <span class="collapsible-toggle collapsed"><i class="fas fa-chevron-down"></i></span>
            </div>
            <p>IP-адреса из этого списка никогда не будут заблокированы системой.
                <a href="https://mxtoolbox.com/subnetcalculator.aspx" target="_blank" class="btn btn-info btn-sm ml-2">
                    <i class="fas fa-calculator"></i> Subnet Calculator
                </a>
            </p>
            
            <!-- Сворачиваемое содержимое белого списка (изначально скрыто) -->
            <div id="whitelist-content" class="collapsible-content hidden">
                <form method="post" class="form-inline mb-4">
                    <div class="input-group" style="max-width: 380px;">
                        <input type="text" name="whitelist_ip" placeholder="IP-адрес (IPv4 или IPv6)" value="<?php echo htmlspecialchars($current_ip); ?>" class="form-control">
                        <div class="tooltip">
                            <i class="fas fa-question-circle"></i>
                            <span class="tooltiptext">
                                Поддерживаются форматы:<br>
                                - IPv4: 192.168.1.1<br>
                                - IPv6: 2001:0db8:85a3...<br>
                                - CIDR: 192.168.1.0/24
                            </span>
                        </div>
                    </div>
                    <button type="submit" name="add_to_whitelist" class="btn btn-info">
                        <i class="fas fa-plus"></i> Добавить в белый список
                    </button>
                </form>
                
                <p class="mb-4">
                    <strong>Ваш текущий IP:</strong> 
                    <span class="ip-label"><?php echo htmlspecialchars($current_ip); ?></span> 
                    <span class="badge badge-primary"><?php echo $is_ipv6 ? 'IPv6' : 'IPv4'; ?></span>
                </p>
                
                <?php if (empty($whitelisted_ips)): ?>
                    <p>Белый список пуст.</p>
                <?php else: ?>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>IP-адрес</th>
                                    <th>DNS-имя</th>
                                    <th>Действия</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($whitelisted_ips as $ip): ?>
                                    <tr>
                                        <td class="ip-label">
                                            <?php echo htmlspecialchars($ip); ?>
                                            <?php 
                                            if ($admin->normalizeIP($ip) === $admin->normalizeIP($current_ip)) {
                                                echo ' <span style="color: green; font-weight: bold;">(ваш IP)</span>';
                                            }
                                            
                                            // Определение типа IP
                                            if (strpos($ip, '/') !== false) {
                                                echo ' <span class="badge">CIDR</span>';
                                            } else if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                                                echo ' <span class="badge">IPv6</span>';
                                            } else {
                                                echo ' <span class="badge">IPv4</span>';
                                            }
                                            ?>
                                        </td>
                                        <td>
                                            <?php 
                                            if (strpos($ip, '/') === false) {
                                                echo htmlspecialchars($admin->getHostByAddr($ip));
                                            } else {
                                                echo 'CIDR-диапазон';
                                            }
                                            ?>
                                        </td>
                                        <td>
                                            <form method="post" style="display:inline;" onsubmit="return confirm('Вы уверены, что хотите удалить IP-адрес <?php echo htmlspecialchars($ip); ?> из белого списка?');">
                                                <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ip); ?>">
                                                <button type="submit" name="remove_from_whitelist" class="btn btn-danger">
                                                    <i class="fas fa-trash"></i> Удалить
                                                </button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
            
            <h2 class="mt-5"><i class="fas fa-ban"></i> Заблокированные IP-адреса</h2>
            
            <div class="mb-4">
                <form method="post" class="mb-3" onsubmit="return confirm('ВНИМАНИЕ! Вы уверены, что хотите разблокировать ВСЕ заблокированные IP-адреса? Это действие нельзя отменить и может повлиять на безопасность сайта.');">
                    <input type="hidden" name="confirm_unblock_all" value="yes">
                    <button type="submit" name="unblock_all" class="btn btn-danger">
                        <i class="fas fa-unlock-alt"></i> Разблокировать всех
                    </button>
                    <small class="text-muted d-block mt-2">
                        Эта функция разблокирует все заблокированные IP-адреса одним действием. Используйте с осторожностью!
                    </small>
                </form>
                
                <form method="post" style="display:inline;" onsubmit="return confirm('Вы уверены, что хотите очистить дублирующиеся правила iptables?');">
                    <button type="submit" name="cleanup_iptables_duplicates" class="btn btn-warning">
                        <i class="fas fa-broom"></i> Очистить дубликаты правил iptables
                    </button>
                    <small class="text-muted d-block mt-2">
                        Эта функция удаляет лишние повторяющиеся правила брандмауэра, которые могут появиться после нескольких операций блокировки/разблокировки.
                    </small>
                </form>
            </div>

            <?php if ($pagination['pages'] > 1): ?>
            <div class="pagination">
                <?php if ($pagination['current'] > 1): ?>
                    <a href="?page=blocked&p=<?php echo $pagination['current'] - 1; ?>" class="btn btn-sm">
                        <i class="fas fa-chevron-left"></i> Назад
                    </a>
                <?php endif; ?>
                
                <span class="pagination-info">
                    Страница <?php echo $pagination['current']; ?> из <?php echo $pagination['pages']; ?> 
                    (всего <?php echo $pagination['total']; ?> записей)
                </span>
                
                <?php if ($pagination['current'] < $pagination['pages']): ?>
                    <a href="?page=blocked&p=<?php echo $pagination['current'] + 1; ?>" class="btn btn-sm">
                        Вперед <i class="fas fa-chevron-right"></i>
                    </a>
                <?php endif; ?>
            </div>
            <?php endif; ?>

            <?php if (empty($blocked_ips)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> В настоящее время нет заблокированных IP-адресов.
                </div>
            <?php else: ?>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>IP-адрес</th>
                                <th>DNS-имя</th>
                                <th>Причина</th>
                                <th>Осталось</th>
                                <th>Блокировка</th>
                                <th>Дата</th>
                                <th>Действия</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($blocked_ips as $ip_data): ?>
                                <tr class="<?php echo $ip_data['block_count'] > 1 ? 'highlight' : ''; ?>">
                                    <td class="ip-label"><?php echo htmlspecialchars($ip_data['ip']); ?></td>
                                    <td><?php echo htmlspecialchars($admin->getHostByAddr($ip_data['ip'])); ?></td>
                                    <td><?php echo htmlspecialchars($ip_data['reason']); ?></td>
                                    <td><?php echo htmlspecialchars($admin->formatBlockDuration($ip_data['block_until'])); ?></td>
                                    <td>
                                        <?php if ($ip_data['block_count'] > 1): ?>
                                            <span class="block-count-badge <?php echo $ip_data['block_count'] > 5 ? 'high' : ($ip_data['block_count'] > 2 ? 'medium' : 'low'); ?>">
                                                Блокировка #<?php echo htmlspecialchars($ip_data['block_count']); ?>
                                            </span>
                                            <div class="text-muted mt-1">
                                                Первая: <?php echo htmlspecialchars(date('d.m.Y', strtotime($ip_data['first_blocked_at']))); ?>
                                            </div>
                                        <?php else: ?>
                                            <span class="badge">Первая</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?php echo htmlspecialchars(date('d.m.Y H:i', strtotime($ip_data['created_at']))); ?></td>
                                    <td>
                                        <div class="action-btns">
                                            <form method="post" style="display:inline;" onsubmit="return confirm('Вы уверены, что хотите разблокировать IP-адрес <?php echo htmlspecialchars($ip_data['ip']); ?>?');">
                                                <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ip_data['ip']); ?>">
                                                <button type="submit" name="unblock" class="btn btn-danger">
                                                    <i class="fas fa-unlock"></i> Разблокировать
                                                </button>
                                            </form>
                                            <a href="admin.php?history=1&ip=<?php echo htmlspecialchars($ip_data['ip']); ?>" class="btn btn-info">
                                                <i class="fas fa-history"></i> История
                                            </a>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            <tr>
                                <td colspan="7">
                                    <div class="info-box mb-0">
                                        <p class="mb-2"><strong><i class="fas fa-info-circle"></i> Обратите внимание:</strong> Пользователи могут самостоятельно разблокировать свой IP, пройдя проверку reCAPTCHA на странице 
                                        <a href="recaptcha_unlock.php" target="_blank">/dos/recaptcha_unlock.php</a></p>
                                        <p class="mb-0">Система прогрессивной блокировки автоматически увеличивает время блокировки для повторных нарушителей.</p>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <?php if ($pagination['pages'] > 1): ?>
                <div class="pagination">
                    <?php if ($pagination['current'] > 1): ?>
                        <a href="?page=blocked&p=<?php echo $pagination['current'] - 1; ?>" class="btn btn-sm">
                            <i class="fas fa-chevron-left"></i> Назад
                        </a>
                    <?php endif; ?>
                    
                    <span class="pagination-info">
                        Страница <?php echo $pagination['current']; ?> из <?php echo $pagination['pages']; ?>
                    </span>
                    
                    <?php if ($pagination['current'] < $pagination['pages']): ?>
                        <a href="?page=blocked&p=<?php echo $pagination['current'] + 1; ?>" class="btn btn-sm">
                            Вперед <i class="fas fa-chevron-right"></i>
                        </a>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
            <?php endif; ?>
			<?php elseif ($active_page == 'rates'): ?>
            <!-- Статистика частоты запросов IP -->
            <h2><i class="fas fa-tachometer-alt"></i> Частота запросов IP 
                <span class="count-badge"><?php echo $monitoring_stats['ip_request_rates']['count']; ?></span>
            </h2>
            <p>В этой таблице отображаются IP-адреса и статистика их запросов за последние 10 минут.</p>
            
            <!-- Информация и кнопка очистки -->
            <div class="info-box">
                <p><strong><i class="fas fa-info-circle"></i> Информация о таблице:</strong></p>
                <ul class="mb-3">
                    <?php if (!empty($monitoring_stats['ip_request_rates']['stats'])): ?>
                        <li>Максимальное количество запросов: <strong><?php echo htmlspecialchars($monitoring_stats['ip_request_rates']['stats']['max_requests']); ?></strong></li>
                        <li>Среднее количество запросов: <strong><?php echo round(htmlspecialchars($monitoring_stats['ip_request_rates']['stats']['avg_requests']), 2); ?></strong></li>
                        <li>Самая старая запись: <strong><?php echo date('d.m.Y H:i:s', $monitoring_stats['ip_request_rates']['stats']['oldest_record']); ?></strong></li>
                        <li>Самая новая запись: <strong><?php echo date('d.m.Y H:i:s', $monitoring_stats['ip_request_rates']['stats']['newest_record']); ?></strong></li>
                    <?php else: ?>
                        <li>Нет данных</li>
                    <?php endif; ?>
                </ul>
                <p>Данные очищаются автоматически через скрипт cleanup.php (записи старше 10 минут).</p>
                <form method="post" onsubmit="return confirm('Вы уверены, что хотите очистить все записи таблицы частоты запросов IP?');">
                    <button type="submit" name="clear_ip_request_rates" class="btn btn-warning">
                        <i class="fas fa-eraser"></i> Очистить таблицу
                    </button>
                </form>
            </div>
            
            <?php if (empty($ip_request_rates)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> Нет данных о частоте запросов IP.
                </div>
            <?php else: ?>
                <!-- Пагинация -->
                <?php if ($pagination['pages'] > 1): ?>
                <div class="pagination">
                    <?php if ($pagination['current'] > 1): ?>
                        <a href="?page=rates&p=<?php echo $pagination['current'] - 1; ?>" class="btn btn-sm">
                            <i class="fas fa-chevron-left"></i> Назад
                        </a>
                    <?php endif; ?>
                    
                    <span class="pagination-info">
                        Страница <?php echo $pagination['current']; ?> из <?php echo $pagination['pages']; ?> 
                        (всего <?php echo $pagination['total']; ?> записей)
                    </span>
                    
                    <?php if ($pagination['current'] < $pagination['pages']): ?>
                        <a href="?page=rates&p=<?php echo $pagination['current'] + 1; ?>" class="btn btn-sm">
                            Вперед <i class="fas fa-chevron-right"></i>
                        </a>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>IP-адрес</th>
                                <th>DNS-имя</th>
                                <th>Запросов</th>
                                <th>Первый запрос</th>
                                <th>Последний запрос</th>
                                <th>Действия</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($ip_request_rates as $rate): ?>
                                <tr class="<?php echo $rate['request_count'] > 20 ? 'highlight' : ''; ?>">
                                    <td class="ip-label"><?php echo htmlspecialchars($rate['ip']); ?></td>
                                    <td><?php echo htmlspecialchars($admin->getHostByAddr($rate['ip'])); ?></td>
                                    <td>
                                        <?php
                                            // Вносим базовые проверки для PHP 5.6
                                            $requestCount = isset($rate['request_count']) ? intval($rate['request_count']) : 0;
                                            echo htmlspecialchars($requestCount);
                                        ?>
                                        <?php if ($requestCount > 20): ?>
                                            <span class="block-count-badge high">Высокая</span>
                                        <?php elseif ($requestCount > 10): ?>
                                            <span class="block-count-badge medium">Средняя</span>
                                        <?php elseif ($requestCount > 5): ?>
                                            <span class="block-count-badge low">Низкая</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?php echo date('d.m.Y H:i:s', strtotime($rate['first_request_time'])); ?></td>
                                    <td><?php echo date('d.m.Y H:i:s', strtotime($rate['last_request_time'])); ?></td>
                                    <td>
                                        <div class="action-btns">
                                            <a href="admin.php?history=1&ip=<?php echo htmlspecialchars($rate['ip']); ?>" class="btn btn-info">
                                                <i class="fas fa-history"></i> История
                                            </a>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                
                <!-- Пагинация (внизу) -->
                <?php if ($pagination['pages'] > 1): ?>
                <div class="pagination">
                    <?php if ($pagination['current'] > 1): ?>
                        <a href="?page=rates&p=<?php echo $pagination['current'] - 1; ?>" class="btn btn-sm">
                            <i class="fas fa-chevron-left"></i> Назад
                        </a>
                    <?php endif; ?>
                    
                    <span class="pagination-info">
                        Страница <?php echo $pagination['current']; ?> из <?php echo $pagination['pages']; ?>
                    </span>
                    
                    <?php if ($pagination['current'] < $pagination['pages']): ?>
                        <a href="?page=rates&p=<?php echo $pagination['current'] + 1; ?>" class="btn btn-sm">
                            Вперед <i class="fas fa-chevron-right"></i>
                        </a>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
            <?php endif; ?>

        <?php elseif ($active_page == 'suspicious'): ?>
            <!-- Подозрительные запросы -->
            <h2><i class="fas fa-exclamation-triangle"></i> Подозрительные запросы 
                <span class="count-badge"><?php echo $monitoring_stats['suspicious_requests']['count']; ?></span>
            </h2>
            <p>В этой таблице отображаются подозрительные запросы, обнаруженные системой.</p>
            
            <!-- Информация и кнопка очистки -->
            <div class="info-box">
                <p><strong><i class="fas fa-info-circle"></i> Информация о таблице:</strong></p>
                <ul class="mb-3">
                    <?php if (!empty($monitoring_stats['suspicious_requests']['stats'])): ?>
                        <li>Уникальных IP-адресов: <strong><?php echo htmlspecialchars($monitoring_stats['suspicious_requests']['stats']['unique_ips']); ?></strong></li>
                        <li>Самая старая запись: <strong><?php echo date('d.m.Y H:i:s', $monitoring_stats['suspicious_requests']['stats']['oldest_record']); ?></strong></li>
                        <li>Самая новая запись: <strong><?php echo date('d.m.Y H:i:s', $monitoring_stats['suspicious_requests']['stats']['newest_record']); ?></strong></li>
                    <?php else: ?>
                        <li>Нет данных</li>
                    <?php endif; ?>
                </ul>
                <p>Данные очищаются автоматически через скрипт cleanup.php (записи старше 24 часов).</p>
                <form method="post" onsubmit="return confirm('Вы уверены, что хотите очистить все записи таблицы подозрительных запросов?');">
                    <button type="submit" name="clear_suspicious_requests" class="btn btn-warning">
                        <i class="fas fa-eraser"></i> Очистить таблицу
                    </button>
                </form>
            </div>

            
            <?php if (empty($suspicious_requests)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> Нет данных о подозрительных запросах.
                </div>
            <?php else: ?>
                <!-- Пагинация -->
                <?php if ($pagination['pages'] > 1): ?>
                <div class="pagination">
                    <?php if ($pagination['current'] > 1): ?>
                        <a href="?page=suspicious&p=<?php echo $pagination['current'] - 1; ?>" class="btn btn-sm">
                            <i class="fas fa-chevron-left"></i> Назад
                        </a>
                    <?php endif; ?>
                    
                    <span class="pagination-info">
                        Страница <?php echo $pagination['current']; ?> из <?php echo $pagination['pages']; ?> 
                        (всего <?php echo $pagination['total']; ?> записей)
                    </span>
                    
                    <?php if ($pagination['current'] < $pagination['pages']): ?>
                        <a href="?page=suspicious&p=<?php echo $pagination['current'] + 1; ?>" class="btn btn-sm">
                            Вперед <i class="fas fa-chevron-right"></i>
                        </a>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>IP-адрес</th>
                                <th>DNS-имя</th>
                                <th>User-Agent</th>
                                <th>URL запроса</th>
                                <th>Время запроса</th>
                                <th>Действия</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($suspicious_requests as $request): ?>
                                <tr>
                                    <td class="ip-label"><?php echo htmlspecialchars($request['ip']); ?></td>
                                    <td><?php echo htmlspecialchars($admin->getHostByAddr($request['ip'])); ?></td>
                                    <td><?php echo htmlspecialchars($request['user_agent']); ?></td>
                                    <td><?php echo htmlspecialchars($request['request_uri']); ?></td>
                                    <td><?php echo date('d.m.Y H:i:s', strtotime($request['request_time'])); ?></td>
                                    <td>
                                        <div class="action-btns">
                                            <a href="admin.php?history=1&ip=<?php echo htmlspecialchars($request['ip']); ?>" class="btn btn-info">
                                                <i class="fas fa-history"></i> История
                                            </a>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                
                <!-- Пагинация (внизу) -->
                <?php if ($pagination['pages'] > 1): ?>
                <div class="pagination">
                    <?php if ($pagination['current'] > 1): ?>
                        <a href="?page=suspicious&p=<?php echo $pagination['current'] - 1; ?>" class="btn btn-sm">
                            <i class="fas fa-chevron-left"></i> Назад
                        </a>
                    <?php endif; ?>
                    
                    <span class="pagination-info">
                        Страница <?php echo $pagination['current']; ?> из <?php echo $pagination['pages']; ?>
                    </span>
                    
                    <?php if ($pagination['current'] < $pagination['pages']): ?>
                        <a href="?page=suspicious&p=<?php echo $pagination['current'] + 1; ?>" class="btn btn-sm">
                            Вперед <i class="fas fa-chevron-right"></i>
                        </a>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
            <?php endif; ?>
        <?php elseif ($active_page == 'hard_block_history'): ?>
            <!-- История срабатывания жесткой блокировки -->
            <h2><i class="fas fa-history"></i> История срабатывания автоматической жесткой блокировки</h2>
            
            <?php
            // Подключаем класс для работы с базой данных
            if (file_exists('cleanup.php')) {
                require_once 'cleanup.php';
                if (class_exists('SecurityCleanup')) {
                    $cleanup = new SecurityCleanup();
                    $hard_block_history = method_exists($cleanup, 'getHardBlockHistory') ? $cleanup->getHardBlockHistory(100) : [];
                } else {
                    $hard_block_history = [];
                }
            } else {
                $hard_block_history = [];
            }
            
            if (empty($hard_block_history)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> Нет данных о срабатывании жесткой блокировки.
                </div>
            <?php else: ?>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Дата и время</th>
                                <th>Количество блокировок</th>
                                <th>Порог</th>
                                <th>Метод блокировки</th>
                                <th>Уведомление</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($hard_block_history as $event): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars(date('d.m.Y H:i:s', strtotime($event['event_time']))); ?></td>
                                    <td><?php echo htmlspecialchars($event['blocked_count']); ?></td>
                                    <td><?php echo htmlspecialchars($event['threshold']); ?></td>
                                    <td><?php echo htmlspecialchars(strtoupper($event['action_method'])); ?></td>
                                    <td>
                                        <?php if ($event['notification_sent']): ?>
                                            <span class="badge badge-success">Отправлено</span>
                                        <?php else: ?>
                                            <span class="badge">Не отправлено</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        <?php endif; ?>
        
    <?php endif; ?>
    
    <!-- JavaScript для интерактивности -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Функция для переключения видимости раздела
            function toggleCollapsible(sectionId) {
                const content = document.getElementById(sectionId);
                const toggle = document.querySelector('[data-target="' + sectionId + '"] .collapsible-toggle');
                
                if (content.classList.contains('hidden')) {
                    // Показываем содержимое
                    content.classList.remove('hidden');
                    toggle.classList.remove('collapsed');
                } else {
                    // Скрываем содержимое
                    content.classList.add('hidden');
                    toggle.classList.add('collapsed');
                }
            }
            
            // Находим все заголовки сворачиваемых разделов и добавляем обработчики событий
            const headers = document.querySelectorAll('.collapsible-header');
            headers.forEach(function(header) {
                header.addEventListener('click', function() {
                    const targetId = this.getAttribute('data-target');
                    toggleCollapsible(targetId);
                });
            });
            
            // Кеширование результатов getHostByAddr
            const dnsCache = {};
            
            // Поиск всех элементов с DNS и асинхронная загрузка
            document.querySelectorAll('td:nth-child(2)').forEach(function(cell) {
                const ip = cell.previousElementSibling?.textContent?.trim();
                if (ip && !dnsCache[ip]) {
                    // Заменяем getHostByAddr на асинхронную версию
                    setTimeout(function() {
                        // Этот код выполнится после загрузки основной страницы
                    }, 100);
                }
            });
        });
    </script>
</div>
</body>
</html>