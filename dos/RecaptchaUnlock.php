<?php
// RecaptchaUnlock.php
// Полный класс для управления разблокировкой IP с использованием интегрированной защиты от ботов

class RecaptchaUnlock {
    private $db = null;
    private $redis = null;
    private $useRedis = false;
    private $prefix = '';
    private $ip;
    public $dos_dir;
    private $attempts_file;
    private $hard_block_file;
    private $visits_file;
    private $max_failures = 3;
    private $failure_window = 3600;
    private $max_visits = 10;
    private $visits_window = 300;
	
	/**
 * Полная очистка всех файловых счетчиков
 */
private function cleanupAllFileCounters() {
    $directories = [
        'minute_requests/',
        'total_requests/',
        'ip_requests/',
        'ua_tracking/'
    ];
    
    foreach ($directories as $dir) {
        $fullPath = $this->dos_dir . $dir;
        if (is_dir($fullPath)) {
            $this->cleanDirectoryFiles($fullPath, $this->ip);
        }
    }
    
    // Очищаем лог файлы связанные с IP
    $logFiles = [
        'unlock_attempts.log',
        'unlock_visits.log'
    ];
    
    foreach ($logFiles as $logFile) {
        $this->cleanLogFile($this->dos_dir . $logFile, $this->ip);
    }
}

/**
 * Очистка файлов в директории для конкретного IP
 */
private function cleanDirectoryFiles($dir, $ip) {
    if (!is_dir($dir)) return;
    
    $ipSafe = str_replace([':', '.'], '_', $ip);
    $files = glob($dir . $ipSafe . '*');
    
    foreach ($files as $file) {
        if (is_file($file)) {
            @unlink($file);
        }
    }
}

/**
 * Очистка записей IP из лог файла
 */
private function cleanLogFile($logFile, $ip) {
    if (!file_exists($logFile)) return;
    
    $content = file_get_contents($logFile);
    if ($content === false) return;
    
    $lines = explode("\n", $content);
    $newLines = [];
    
    foreach ($lines as $line) {
        if (strpos($line, $ip) === false) {
            $newLines[] = $line;
        }
    }
    
    file_put_contents($logFile, implode("\n", $newLines));
}
    
    public function __construct() {
        $this->ip = $this->getClientIP();
        $this->dos_dir = dirname(__FILE__) . '/'; 
        $this->attempts_file = $this->dos_dir . 'unlock_attempts.log';
        $this->hard_block_file = $this->dos_dir . 'hard_blocked_ips.log';
        $this->visits_file = $this->dos_dir . 'unlock_visits.log';
        
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
        
        // Отслеживаем визиты через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            $this->trackVisitRedis();
        }
    }
    
    /**
     * Получение IP-адреса клиента с поддержкой IPv6
     */
    private function getClientIP() {
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
        
        return $_SERVER['REMOTE_ADDR'];
    }
    
    /**
     * Соединение с Redis
     */
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
            
            if (!$this->redis->connect($host, $port, 2.0)) {
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
            
            return true;
        } catch (Exception $e) {
            error_log("Redis connection error: " . $e->getMessage());
            $this->useRedis = false;
            return false;
        }
    }
    
    /**
     * Отслеживание визитов в Redis
     */
    private function trackVisitRedis() {
        if (!$this->redis) return false;
        
        try {
            $visitsKey = $this->prefix . "unlock_visits:{$this->ip}";
            $now = time();
            
            // Добавляем метку времени текущего визита
            $this->redis->zAdd($visitsKey, $now, $now);
            
            // Устанавливаем срок жизни ключа (24 часа)
            $this->redis->expire($visitsKey, 86400);
            
            // Удаляем все метки времени старше окна отслеживания
            $cutoff = $now - $this->visits_window;
            $this->redis->zRemRangeByScore($visitsKey, 0, $cutoff);
            
            // Логируем визит в общий список для статистики
            $this->redis->lPush($this->prefix . "all_unlock_visits", json_encode([
                'ip' => $this->ip,
                'time' => $now,
                'ua' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''
            ]));
            $this->redis->ltrim($this->prefix . "all_unlock_visits", 0, 999);
            
            return true;
        } catch (Exception $e) {
            error_log("Error tracking visit in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Обнаружение слишком частых посещений страницы через Redis
     */
    public function detectFrequentVisits() {
        // Если используем Redis
        if ($this->useRedis && $this->redis) {
            try {
                $visitsKey = $this->prefix . "unlock_visits:{$this->ip}";
                $recentVisits = $this->redis->zCard($visitsKey);
                
                if ($recentVisits > $this->max_visits) {
                    $reason = "Многократные обновления страницы разблокировки ($recentVisits за " . ($this->visits_window/60) . " минут)";
                    $this->addToHardBlockList($reason);
                    $this->applyHardBlock($reason);
                    return true;
                }
                
                return false;
            } catch (Exception $e) {
                error_log("Redis error checking frequent visits: " . $e->getMessage());
            }
        }
        
        // Fallback: проверка через файл
        if (!file_exists($this->visits_file)) {
            return false;
        }
        
        $content = file_get_contents($this->visits_file);
        $lines = explode("\n", $content);
        $recent_visits = 0;
        $window_time = time() - $this->visits_window;
        
        foreach ($lines as $line) {
            if (empty(trim($line))) continue;
            
            if (strpos($line, $this->ip) !== false) {
                $timestamp = strtotime(substr($line, 0, 19));
                if ($timestamp > $window_time) {
                    $recent_visits++;
                }
            }
        }
        
        if ($recent_visits > $this->max_visits) {
            $reason = "Многократные обновления страницы разблокировки ($recent_visits за " . ($this->visits_window/60) . " минут)";
            $this->addToHardBlockList($reason);
            $this->applyHardBlock($reason);
            return true;
        }
        
        return false;
    }
    
    /**
     * Подключение к БД MariaDB
     */
    private function connectDB() {
        try {
            $this->db = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
            if (defined('PDO::ATTR_ERRMODE')) {
                $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            }
            $this->db->exec("SET NAMES utf8mb4");
        } catch(PDOException $e) {
            error_log("Ошибка подключения к БД: " . $e->getMessage());
        }
    }
    
    /**
     * Проверка блокировки IP через Redis
     */
    public function isIPBlockedRedis() {
        if (!$this->redis) return false;
        
        try {
            // Сначала проверяем в sorted set для более быстрого поиска
            $blockUntil = $this->redis->zScore($this->prefix . "blocked_ips", $this->ip);
            
            // Если нашли в sorted set и блокировка активна
            if ($blockUntil !== false && $blockUntil > time()) {
                // Проверяем с данными hash
                $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
                
                // Если hash существует, подтверждаем флаг is_blocked
                if ($this->redis->exists($blockKey)) {
                    $isBlocked = $this->redis->hGet($blockKey, 'is_blocked');
                    $hashBlockUntil = (int)$this->redis->hGet($blockKey, 'block_until');
                    
                    // Если правильно заблокирован и время совпадает
                    if ($isBlocked === '1' && $hashBlockUntil > time()) {
                        return true;
                    }
                } else {
                    // Hash не существует, но IP в sorted set - создаем hash со значениями по умолчанию
                    $hashData = array(
                        'block_until' => $blockUntil,
                        'reason' => 'Recovered block',
                        'created_at' => time(),
                        'block_count' => 1,
                        'first_blocked_at' => time(),
                        'is_blocked' => 1
                    );
                    $this->redis->hMSet($blockKey, $hashData);
                    $this->redis->expire($blockKey, (int)$blockUntil - time() + 86400);
                    return true;
                }
            }
            
            // Проверяем hash напрямую
            $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
            
            if ($this->redis->exists($blockKey)) {
                $isBlocked = $this->redis->hGet($blockKey, 'is_blocked');
                $blockUntil = (int)$this->redis->hGet($blockKey, 'block_until');
                
                // Активная блокировка
                if ($isBlocked === '1' && $blockUntil > time()) {
                    // Убеждаемся, что IP в sorted set
                    $this->redis->zAdd($this->prefix . "blocked_ips", $blockUntil, $this->ip);
                    return true;
                }
                
                // Истекшая блокировка - обновляем статус
                if ($blockUntil <= time()) {
                    $this->redis->hSet($blockKey, 'is_blocked', 0);
                    $this->redis->zRem($this->prefix . "blocked_ips", $this->ip);
                }
            }
            
            return false;
        } catch (Exception $e) {
            error_log("Ошибка проверки блокировки IP в Redis: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Проверка блокировки IP через БД
     */
    public function isIPBlockedDB() {
        try {
            if (!$this->db) {
                return false;
            }
            
            $stmt = $this->db->prepare("SELECT 1 FROM blocked_ips WHERE ip = ? AND block_until > NOW()");
            $stmt->execute(array($this->ip));
            return $stmt->fetchColumn() ? true : false;
        } catch(PDOException $e) {
            error_log("Error checking if IP is blocked: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Проверка блокировки IP (обобщенный метод)
     */
    public function isIPBlocked() {
        if ($this->useRedis && $this->redis) {
            return $this->isIPBlockedRedis();
        }
        
        return $this->isIPBlockedDB();
    }
    
    /**
     * Проверка наличия IP в списке жестких блокировок через Redis
     */
    public function isInHardBlockListRedis() {
        if (!$this->redis) return false;
        
        try {
            $hardBlockKey = $this->prefix . "hard_blocked:{$this->ip}";
            
            if ($this->redis->exists($hardBlockKey)) {
                return true;
            }
            
            // Проверяем наличие в базе данных с флагом жесткой блокировки
            $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
            if ($this->redis->exists($blockKey)) {
                $blockCount = (int)$this->redis->hGet($blockKey, 'block_count');
                if ($blockCount >= 100) {
                    return true;
                }
            }
            
            return false;
        } catch (Exception $e) {
            error_log("Error checking hard block list in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Проверка наличия IP в списке жестких блокировок через файл и БД
     */
    public function isInHardBlockListFile() {
        // Проверяем запись в файле hard_blocked_ips.log
        $in_file = false;
        if (file_exists($this->hard_block_file)) {
            $content = file_get_contents($this->hard_block_file);
            $in_file = strpos($content, $this->ip) !== false;
        }
        
        // Проверяем наличие в базе данных с флагом жесткой блокировки
        $in_db = false;
        try {
            if ($this->db) {
                $stmt = $this->db->prepare("SELECT 1 FROM blocked_ips WHERE ip = ? AND block_count >= 100 AND block_until > NOW()");
                $stmt->execute(array($this->ip));
                $in_db = $stmt->fetchColumn() ? true : false;
            }
        } catch(PDOException $e) {
            error_log("Ошибка при проверке жесткой блокировки в БД: " . $e->getMessage());
        }
        
        return $in_file || $in_db;
    }
    
    /**
     * Обобщенный метод проверки жесткой блокировки
     */
    public function isInHardBlockList() {
        if ($this->useRedis && $this->redis) {
            return $this->isInHardBlockListRedis();
        }
        
        return $this->isInHardBlockListFile();
    }
    
    /**
     * Получение информации о блокировке из Redis
     */
    public function getBlockInfoRedis() {
        if (!$this->redis) return false;
        
        try {
            $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
            
            if (!$this->redis->exists($blockKey)) {
                return false;
            }
            
            $blockInfo = $this->redis->hGetAll($blockKey);
            
            // Проверка существования индексов перед преобразованием
            $blockInfo['block_count'] = isset($blockInfo['block_count']) ? (int)$blockInfo['block_count'] : 0;
            $blockInfo['block_until'] = isset($blockInfo['block_until']) ? (int)$blockInfo['block_until'] : 0;
            $blockInfo['created_at'] = isset($blockInfo['created_at']) ? (int)$blockInfo['created_at'] : 0;
            $blockInfo['first_blocked_at'] = isset($blockInfo['first_blocked_at']) ? (int)$blockInfo['first_blocked_at'] : 0;
            
            // Для совместимости с форматом из MariaDB
            $blockInfo['block_until'] = date('Y-m-d H:i:s', $blockInfo['block_until']);
            $blockInfo['first_blocked_at'] = date('Y-m-d H:i:s', $blockInfo['first_blocked_at']);
            
            return $blockInfo;
        } catch (Exception $e) {
            error_log("Error getting block info from Redis: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Получение информации о блокировке из БД
     */
    public function getBlockInfoDB() {
        try {
            if (!$this->db) {
                return false;
            }
            
            $stmt = $this->db->prepare("
                SELECT block_count, block_until, first_blocked_at, reason
                FROM blocked_ips 
                WHERE ip = ? AND block_until > NOW()
            ");
            $stmt->execute(array($this->ip));
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } catch(PDOException $e) {
            error_log("Error getting block info: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Обобщенный метод получения информации о блокировке
     */
    public function getBlockInfo() {
        if ($this->useRedis && $this->redis) {
            $redisInfo = $this->getBlockInfoRedis();
            if ($redisInfo) {
                return $redisInfo;
            }
        }
        
        return $this->getBlockInfoDB();
    }
    
    /**
     * Форматирование времени блокировки
     */
    public function formatTimeRemaining($timestamp) {
        $time_diff = $timestamp - time();
        $days = floor($time_diff / (60 * 60 * 24));
        $hours = floor(($time_diff - ($days * 60 * 60 * 24)) / (60 * 60));
        $minutes = floor(($time_diff - ($days * 60 * 60 * 24) - ($hours * 60 * 60)) / 60);
        
        $time_format = "";
        if ($days > 0) $time_format .= "$days д. ";
        if ($hours > 0) $time_format .= "$hours ч. ";
        if ($minutes > 0) $time_format .= "$minutes мин.";
        
        return $time_format;
    }
    
    /**
     * Проверка reCAPTCHA
     */
    public function verifyRecaptcha($recaptcha_response) {
        if (empty($recaptcha_response)) {
            return false;
        }
        
        $url = 'https://www.google.com/recaptcha/api/siteverify';
        $data = array(
            'secret' => RECAPTCHA_SECRET_KEY,
            'response' => $recaptcha_response,
            'remoteip' => $this->ip
        );
        
        $options = array(
            'http' => array(
                'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                'method' => 'POST',
                'content' => http_build_query($data)
            )
        );
        
        $context = stream_context_create($options);
        $result = file_get_contents($url, false, $context);
        
        if ($result === FALSE) {
            return false;
        }
        
        $response = json_decode($result, true);
        return isset($response['success']) && $response['success'] === true;
    }
    
    /**
     * Разблокировка IP через Redis
     */
    /**
 * Улучшенная разблокировка IP через Redis
 */
public function unblockIPRedis() {
    if (!$this->redis) return false;
    
    try {
        $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
        
        // Полная очистка всех связанных ключей Redis
        $keysToDelete = [
            $blockKey,
            $this->prefix . "ip_request_rate:{$this->ip}",
            $this->prefix . "minute_requests:{$this->ip}",
            $this->prefix . "total_requests:{$this->ip}",
            $this->prefix . "unlock_visits:{$this->ip}",
            $this->prefix . "suspicious_requests:{$this->ip}",
            $this->prefix . "throttle:{$this->ip}:default",
            $this->prefix . "throttle:{$this->ip}:api",
            $this->prefix . "throttle:{$this->ip}:login",
            $this->prefix . "throttle:{$this->ip}:search"
        ];
        
        // Удаляем все ключи
        foreach ($keysToDelete as $key) {
            $this->redis->del($key);
        }
        
        // Удаляем из sorted set
        $this->redis->zRem($this->prefix . "blocked_ips", $this->ip);
        $this->redis->zRem($this->prefix . "suspicious_ips", $this->ip);
        
        // Выполняем внешние разблокировки
        $this->removeIPFromConf($this->ip);
        $this->removeIPFromHtaccess($this->ip);
        $this->unblockIPFromIptables($this->ip);
        $this->unblockIPViaAPI($this->ip);
        
        // Обновляем файловый кэш
        $this->updateBlockedIPsCache();
        
        // Очищаем файловые счетчики
        $this->cleanupAllFileCounters();
        
        // Сбрасываем сессионные счетчики
        if (session_status() == PHP_SESSION_ACTIVE) {
            unset($_SESSION['page_requests']);
            unset($_SESSION['requests_log']);
            unset($_SESSION['request_count']);
            unset($_SESSION['last_request_time']);
            unset($_SESSION['url_sequence']);
            unset($_SESSION['referrer_history']);
            unset($_SESSION['request_sizes']);
            unset($_SESSION['http_methods']);
            unset($_SESSION['request_intervals']);
            unset($_SESSION['request_timings']);
            session_regenerate_id(true);
        }
        
        // Логируем разблокировку
        $this->redis->lPush($this->prefix . "unblock_log", json_encode([
            'ip' => $this->ip,
            'time' => time(),
            'method' => 'recaptcha_enhanced'
        ]));
        $this->redis->ltrim($this->prefix . "unblock_log", 0, 999);
        
        error_log("IP {$this->ip} полностью разблокирован через улучшенный метод Redis");
        
        return true;
    } catch (Exception $e) {
        error_log("Error in enhanced unblock IP Redis: " . $e->getMessage());
        return false;
    }
}
    
    /**
     * Разблокировка IP через БД
     */
    /**
 * Улучшенная разблокировка IP через БД
 */
public function unblockIPDB() {
    try {
        if (!$this->db) {
            return false;
        }
        
        // Выполняем все операции разблокировки через внешние системы
        $this->removeIPFromConf($this->ip);
        $this->removeIPFromHtaccess($this->ip);
        $this->unblockIPFromIptables($this->ip);
        $this->unblockIPViaAPI($this->ip);
        
        // Удаляем из всех таблиц БД
        $tables = ['blocked_ips', 'suspicious_requests', 'ip_request_rate'];
        foreach ($tables as $table) {
            try {
                $stmt = $this->db->prepare("DELETE FROM `$table` WHERE ip = ?");
                $stmt->execute(array($this->ip));
            } catch (PDOException $e) {
                error_log("Error deleting from $table: " . $e->getMessage());
            }
        }
        
        // Обновляем кеш блокировок
        $this->updateBlockedIPsCache();
        
        // Очищаем файловые счетчики
        $this->cleanupAllFileCounters();
        
        // Сбрасываем сессионные счетчики
        if (session_status() == PHP_SESSION_ACTIVE) {
            unset($_SESSION['page_requests']);
            unset($_SESSION['requests_log']);
            unset($_SESSION['request_count']);
            unset($_SESSION['last_request_time']);
            session_regenerate_id(true);
        }
        
        error_log("IP {$this->ip} полностью разблокирован через улучшенный метод БД");
        
        return true;
    } catch(PDOException $e) {
        error_log("Error in enhanced unblock IP DB: " . $e->getMessage());
        return false;
    }
}
    
    /**
     * Обобщенный метод разблокировки IP
     */
    public function unblockIP() {
        if ($this->useRedis && $this->redis) {
            if ($this->unblockIPRedis()) {
                return true;
            }
        }
        
        return $this->unblockIPDB();
    }
    
    /**
     * Очистка файлов счетчиков запросов
     */
    public function cleanupRequestCounters() {
        // Очистка файловых счетчиков
        $minute_requests_dir = $this->dos_dir . 'minute_requests/';
        $total_requests_dir = $this->dos_dir . 'total_requests/';
        
        if (is_dir($minute_requests_dir)) {
            $this->cleanDirectory($minute_requests_dir);
        }
        
        if (is_dir($total_requests_dir)) {
            $this->cleanDirectory($total_requests_dir);
        }
        
        // Очистка счетчиков в Redis, если доступен
        if ($this->useRedis && $this->redis) {
            try {
                $minute_keys = $this->redis->keys($this->prefix . "minute_requests:*");
                $total_keys = $this->redis->keys($this->prefix . "total_requests:*");
                
                if (!empty($minute_keys)) {
                    foreach ($minute_keys as $key) {
                        $this->redis->del($key);
                    }
                }
                
                if (!empty($total_keys)) {
                    foreach ($total_keys as $key) {
                        $this->redis->del($key);
                    }
                }
            } catch (Exception $e) {
                error_log("Ошибка при очистке счетчиков в Redis: " . $e->getMessage());
            }
        }
        
        return true;
    }
    
    /**
     * Вспомогательный метод для очистки директории
     */
    private function cleanDirectory($dir) {
        if (!is_dir($dir)) {
            return false;
        }
        
        $files = glob($dir . '*');
        foreach ($files as $file) {
            if (is_file($file)) {
                @unlink($file);
            }
        }
        
        return true;
    }
    
    /**
     * Применение жесткой блокировки через Redis
     */
    private function applyHardBlockRedis($reason = 'Жесткая блокировка') {
        if (!$this->redis) return false;
        
        try {
            $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
            $now = time();
            $block_count = 999;
            $block_days = 7;
            $blockUntil = $now + ($block_days * 86400);
            
            // Обновляем или создаем блокировку в Redis
            $this->redis->multi();
            $this->redis->hMSet($blockKey, [
                'block_until' => $blockUntil,
                'reason' => "Жесткая блокировка: " . $reason,
                'created_at' => $now,
                'block_count' => $block_count,
                'first_blocked_at' => $now
            ]);
            
            $this->redis->expireAt($blockKey, $blockUntil);
            $this->redis->zAdd($this->prefix . "blocked_ips", $blockUntil, $this->ip);
            
            // Добавляем в лог блокировок
            $this->redis->lPush($this->prefix . "block_log", json_encode([
                'ip' => $this->ip,
                'reason' => "Жесткая блокировка: " . $reason,
                'block_until' => $blockUntil,
                'block_count' => $block_count,
                'time' => $now
            ]));
            $this->redis->ltrim($this->prefix . "block_log", 0, 999);
            
            $this->redis->exec();
            
            // Применяем все внешние блокировки
            $this->applyExternalBlockings($this->ip);
            
            return true;
        } catch (Exception $e) {
            error_log("Error applying hard block in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Применение жесткой блокировки через БД
     */
    private function applyHardBlockDB($reason = 'Жесткая блокировка') {
        try {
            if (!$this->db) {
                error_log("Ошибка: нет соединения с БД для жесткой блокировки IP $this->ip");
                return false;
            }
            
            $block_count = 999;
            $block_days = 7;
            
            $stmt = $this->db->prepare("
                INSERT INTO blocked_ips (ip, block_until, reason, block_count, first_blocked_at) 
                VALUES (?, DATE_ADD(NOW(), INTERVAL ? DAY), ?, ?, NOW())
                ON DUPLICATE KEY UPDATE 
                    block_until = DATE_ADD(NOW(), INTERVAL ? DAY),
                    reason = ?,
                    block_count = ?
            ");
            $full_reason = "Жесткая блокировка: " . $reason;
            
            $stmt->execute(array(
                $this->ip, 
                $block_days, 
                $full_reason, 
                $block_count,
                $block_days,
                $full_reason,
                $block_count
            ));
            
            error_log("IP $this->ip добавлен в базу данных с жесткой блокировкой на $block_days дней");
            
            // Обновляем кеш блокировок
            $this->updateBlockedIPsCache();
            
            // Применяем все внешние блокировки
            $this->applyExternalBlockings($this->ip);
            
            return true;
        } catch (PDOException $e) {
            error_log("Ошибка при добавлении IP в базу данных: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Обобщенный метод применения жесткой блокировки
     */
    public function applyHardBlock($reason = 'Жесткая блокировка') {
        if ($this->useRedis && $this->redis) {
            if ($this->applyHardBlockRedis($reason)) {
                return true;
            }
        }
        
        return $this->applyHardBlockDB($reason);
    }
    
    /**
     * Применение всех внешних блокировок
     */
    private function applyExternalBlockings($ip) {
        // Блокировка через .htaccess
        if (defined('ENABLE_HTACCESS_BLOCKING') && ENABLE_HTACCESS_BLOCKING) {
            $this->blockIPInHtaccess($ip);
        }
        
        // Блокировка через Nginx (ip.conf)
        if (defined('ENABLE_NGINX_BLOCKING') && ENABLE_NGINX_BLOCKING) {
            $this->logIPToConf($ip);
        }
        
        // Блокировка через брандмауэр (iptables)
        if (defined('ENABLE_FIREWALL_BLOCKING') && ENABLE_FIREWALL_BLOCKING) {
            $this->blockIPWithIptables($ip);
        }
        
        // Блокировка через API
        if (defined('ENABLE_API_BLOCKING') && ENABLE_API_BLOCKING) {
            $this->blockIPWithAPI($ip);
        }
    }
    
    /**
     * Блокировка IP в .htaccess
     */
    private function blockIPInHtaccess($ip) {
        if (defined('ENABLE_HTACCESS_BLOCKING') && !ENABLE_HTACCESS_BLOCKING) {
            return false;
        }
        
        $htaccessPath = dirname($this->dos_dir) . '/.htaccess';
        
        // Проверяем, не заблокирован ли IP уже
        if ($this->isIPBlockedInHtaccess($ip)) {
            return true;
        }
        
        // Проверка существования файла
        if (!file_exists($htaccessPath)) {
            $result = file_put_contents($htaccessPath, "");
            if ($result === false) {
                error_log("Ошибка при создании файла .htaccess");
                return false;
            }
        }
        
        // Проверка разрешений на запись
        if (!is_writable($htaccessPath)) {
            error_log("Файл .htaccess не доступен для записи");
            return false;
        }
        
        // Подготовка правила блокировки
        $rule = "Deny from $ip\n";
        
        // Проверяем содержимое файла
        $currentContent = file_get_contents($htaccessPath);
        
        if (!empty($currentContent) && substr($currentContent, -1) !== "\n") {
            $rule = "\n" . $rule;
        }
        
        // Попытка записи в файл
        $success = file_put_contents($htaccessPath, $rule, FILE_APPEND);
        
        if (!$success) {
            error_log("Ошибка при записи в .htaccess");
            return false;
        }
        
        return $this->isIPBlockedInHtaccess($ip);
    }
    
    /**
     * Проверка, заблокирован ли IP в .htaccess
     */
    private function isIPBlockedInHtaccess($ip) {
        $htaccessPath = dirname($this->dos_dir) . '/.htaccess';
        
        if (!file_exists($htaccessPath)) {
            return false;
        }
        
        $htaccessContent = file_get_contents($htaccessPath);
        
        if ($htaccessContent === false || empty($htaccessContent)) {
            return false;
        }
        
        return strpos($htaccessContent, "Deny from $ip") !== false;
    }
    
    /**
     * Удаление IP из .htaccess
     */
    private function removeIPFromHtaccess($ip) {
        $htaccessPath = dirname($this->dos_dir) . '/.htaccess';
        
        if (!file_exists($htaccessPath)) {
            return false;
        }
        
        $htaccessContent = file_get_contents($htaccessPath);
        if ($htaccessContent === false) {
            return false;
        }
        
        $lines = explode("\n", $htaccessContent);
        $new_lines = array();
        $removed = false;
        
        foreach ($lines as $line) {
            if (trim($line) === "Deny from $ip") {
                $removed = true;
                continue;
            }
            $new_lines[] = $line;
        }
        
        if ($removed) {
            $new_content = implode("\n", $new_lines);
            file_put_contents($htaccessPath, $new_content);
        }
        
        return $removed;
    }
    
    /**
     * Функция для проверки валидности IP-адреса (IPv4 или IPv6)
     */
    private function isValidIP($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP);
    }
    
    /**
     * Функция для записи IP в ip.conf в формате "IP 1;"
     */
    private function logIPToConf($ip) {
        if (defined('ENABLE_NGINX_BLOCKING') && !ENABLE_NGINX_BLOCKING) {
            return false;
        }
        
        if (!$this->isValidIP($ip)) {
            error_log("IP $ip не является корректным IPv4 или IPv6 адресом");
            return false;
        }
        
        $ipConfFile = $this->dos_dir . 'ip.conf';
        $blockedIPs = array();
        
        if (file_exists($ipConfFile)) {
            $lines = file($ipConfFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            
            if ($lines !== false) {
                foreach ($lines as $line) {
                    if (strpos($line, '#') === 0) {
                        continue;
                    }
                    
                    $parts = explode(' ', trim($line));
                    $lineIP = $parts[0];
                    
                    if ($this->isValidIP($lineIP)) {
                        $blockedIPs[] = $lineIP;
                    }
                }
            }
        }
        
        if (!in_array($ip, $blockedIPs)) {
            $blockedIPs[] = $ip;
        } else {
            return true;
        }
        
        $fileContent = "# Обновлено " . date('Y-m-d H:i:s') . "\n";
        
        foreach ($blockedIPs as $blockedIP) {
            $fileContent .= "$blockedIP 1;\n";
        }
        
        $success = file_put_contents($ipConfFile, $fileContent);

        if ($success !== false) {
            $this->reloadNginx();            
            return true;
        }
        
        return false;
    }
    
    /**
     * Удаление IP из ip.conf
     */
    private function removeIPFromConf($ip) {
        $ipConfFile = $this->dos_dir . 'ip.conf';
        
        if (!file_exists($ipConfFile)) {
            return false;
        }
        
        $lines = file($ipConfFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return false;
        }
        
        $blockedIPs = array();
        $removed = false;
        
        foreach ($lines as $line) {
            if (strpos($line, '#') === 0) {
                continue;
            }
            
            $parts = preg_split('/\s+/', trim($line));
            $lineIP = $parts[0];
            
            if ($this->isValidIP($lineIP) && $lineIP !== $ip) {
                $blockedIPs[] = $lineIP;
            } else if ($lineIP === $ip) {
                $removed = true;
            }
        }
        
        if ($removed) {
            $fileContent = "# Обновлено " . date('Y-m-d H:i:s') . "\n";
            
            foreach ($blockedIPs as $blockedIP) {
                $fileContent .= "$blockedIP 1;\n";
            }
            
            file_put_contents($ipConfFile, $fileContent);
            $this->reloadNginx();
        }
        
        return $removed;
    }
    
    /**
     * Перезагрузка Nginx
     */
    private function reloadNginx() {
        $reload_flag_file = $this->dos_dir . 'nginx_reload_needed';
        file_put_contents($reload_flag_file, date('Y-m-d H:i:s'));
        
        if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))))) {
            $output = array();
            $return_var = 0;
            exec('sudo /usr/sbin/nginx -s reload 2>&1', $output, $return_var);
        }
    }
    
    /**
     * Блокировка IP через iptables/ip6tables
     */
    public function blockIPWithIptables($ip) {
        if (defined('ENABLE_FIREWALL_BLOCKING') && !ENABLE_FIREWALL_BLOCKING) {
            return false;
        }
        
        if (!$this->isValidIP($ip)) {
            error_log("Ошибка: IP $ip не является валидным для блокировки");
            return false;
        }
        
        $isIPv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        $ports = array(80, 443);
        
        error_log("Блокируем IP в iptables: $ip, IPv6: " . ($isIPv6 ? "да" : "нет"));
        
        foreach ($ports as $port) {
            if ($isIPv6) {
                $command = "sudo ip6tables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
            } else {
                $command = "sudo iptables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
            }
            
            exec($command);
        }
        
        if ($isIPv6) {
            exec("sudo sh -c 'ip6tables-save > /etc/iptables/rules.v6'");
        } else {
            exec("sudo sh -c 'iptables-save > /etc/iptables/rules.v4'");
        }
        
        error_log("IP $ip успешно заблокирован через iptables");
        return true;
    }
    
    /**
     * Удаление IP из iptables/ip6tables
     */
    private function unblockIPFromIptables($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            error_log("Неверный формат IP-адреса для разблокировки в iptables: " . $ip);
            return false;
        }
        
        $isIPv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        $ports = array(80, 443);
        
        foreach ($ports as $port) {
            if ($isIPv6) {
                $command = "sudo ip6tables -D INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
            } else {
                $command = "sudo iptables -D INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
            }
            
            $output = array();
            $returnVar = 0;
            exec($command, $output, $returnVar);
            
            error_log("Удаление IP $ip из " . ($isIPv6 ? "ip6tables" : "iptables") . " для порта $port: " . 
                         ($returnVar == 0 ? "успешно" : "правило не найдено или ошибка"));
        }
        
        if ($isIPv6) {
            $command = "sudo ip6tables -D INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null";
        } else {
            $command = "sudo iptables -D INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null";
        }
        
        exec($command);
        $this->saveIptablesRules($isIPv6);
        
        return true;
    }
    
    /**
     * Функция для сохранения правил iptables
     */
    private function saveIptablesRules($isIPv6) {
        $distro = $this->getLinuxDistribution();
        
        switch ($distro) {
            case 'ubuntu':
            case 'debian':
                $command = $isIPv6 ? 
                    "sudo sh -c 'ip6tables-save > /etc/iptables/rules.v6'" : 
                    "sudo sh -c 'iptables-save > /etc/iptables/rules.v4'";
                break;
                
            case 'centos':
            case 'fedora':
            case 'rhel':
                $command = $isIPv6 ? 
                    "sudo service ip6tables save" : 
                    "sudo service iptables save";
                break;
                
            default:
                $command = $isIPv6 ? 
                    "sudo sh -c 'ip6tables-save > /etc/iptables/rules.v6'" : 
                    "sudo sh -c 'iptables-save > /etc/iptables/rules.v4'";
        }
        
        if (in_array($distro, array('ubuntu', 'debian')) || $distro === 'default') {
            exec('sudo mkdir -p /etc/iptables 2>/dev/null');
        }
        
        $output = array();
        $returnVar = 0;
        exec($command, $output, $returnVar);
        
        if ($returnVar !== 0) {
            error_log("Предупреждение: Не удалось сохранить правила iptables");
        }
        
        return true;
    }
    
    /**
     * Функция для определения дистрибутива Linux
     */
    private function getLinuxDistribution() {
        $output = array();
        exec('lsb_release -i 2>/dev/null', $output);
        
        if (!empty($output)) {
            $distro = strtolower(trim(str_replace('Distributor ID:', '', $output[0])));
            return $distro;
        }
        
        if (file_exists('/etc/debian_version')) return 'debian';
        if (file_exists('/etc/redhat-release')) return 'rhel';
        if (file_exists('/etc/fedora-release')) return 'fedora';
        if (file_exists('/etc/centos-release')) return 'centos';
        
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
        
        return 'ubuntu';
    }
    
    /**
     * Метод для разблокировки IP через внешний API
     */
    private function unblockIPViaAPI($ip) {
        if (defined('ENABLE_API_BLOCKING') && !ENABLE_API_BLOCKING) {
            return true;
        }
        
        if (!defined('API_BLOCK_URL') || !defined('API_BLOCK_KEY')) {
            error_log("Ошибка: API_BLOCK_URL или API_BLOCK_KEY не определены в настройках");
            return false;
        }
        
        $url = API_BLOCK_URL;
        $api_key = API_BLOCK_KEY;
        $userAgent = defined('API_USER_AGENT') ? API_USER_AGENT : 'PHP/' . PHP_VERSION;
        
        $params = array(
            'action' => 'unblock',
            'ip' => $ip,
            'api_key' => $api_key,
            'api' => 1
        );
        
        $requestUrl = $url . '?' . http_build_query($params);
        
        error_log("Выполняем разблокировку IP $ip через API: $requestUrl");
        
        $ch = curl_init();
        
        curl_setopt($ch, CURLOPT_URL, $requestUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_USERAGENT, $userAgent);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        
        curl_close($ch);
        
        if ($error) {
            error_log("Ошибка API разблокировки для IP $ip: $error");
            return false;
        }
        
        if ($httpCode !== 200) {
            error_log("Ошибка API разблокировки для IP $ip: HTTP код $httpCode");
            return false;
        }
        
        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("Ошибка разбора JSON-ответа от API при разблокировке IP $ip: " . $response);
            return false;
        }
        
        $success = isset($data['status']) && ($data['status'] === 'success' || $data['status'] === 'warning');
        
        if ($success) {
            error_log("IP $ip успешно разблокирован через API");
            return true;
        } else {
            $message = isset($data['message']) ? $data['message'] : 'Неизвестная ошибка';
            error_log("Ошибка разблокировки IP $ip через API: $message");
            return false;
        }
    }
    
    /**
     * Функция для блокировки IP через внешний API
     */
    private function blockIPWithAPI($ip) {
        if (defined('ENABLE_API_BLOCKING') && !ENABLE_API_BLOCKING) {
            return false;
        }
        
        if (!$this->isValidIP($ip)) {
            error_log("Ошибка: IP $ip некорректен для блокировки через API");
            return false;
        }
        
        $url = defined('API_BLOCK_URL') ? API_BLOCK_URL : '';
        if (empty($url)) {
            error_log("Ошибка: API_BLOCK_URL не определен в настройках");
            return false;
        }
        
        $api_key = defined('API_BLOCK_KEY') ? API_BLOCK_KEY : '';
        $userAgent = defined('API_USER_AGENT') ? API_USER_AGENT : 'PHP/' . PHP_VERSION;
        
        $params = array(
            'action' => 'block',
            'ip' => $ip,
            'api_key' => $api_key,
            'api' => 1
        );
        
        $requestUrl = $url . '?' . http_build_query($params);
        
        error_log("Выполняем блокировку IP $ip через API: $requestUrl");
        
        $ch = curl_init();
        
        curl_setopt($ch, CURLOPT_URL, $requestUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_USERAGENT, $userAgent);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        
        curl_close($ch);
        
        if ($error) {
            error_log("Ошибка API блокировки для IP $ip: $error");
            return false;
        }
        
        if ($httpCode !== 200) {
            error_log("Ошибка API блокировки для IP $ip: HTTP код $httpCode");
            return false;
        }
        
        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("Ошибка разбора JSON-ответа от API для IP $ip: " . $response);
            return false;
        }
        
        $success = isset($data['status']) && $data['status'] === 'success';
        
        if ($success) {
            error_log("IP $ip успешно заблокирован через API");
        } else {
            $message = isset($data['message']) ? $data['message'] : 'Неизвестная ошибка';
            error_log("Ошибка блокировки IP $ip через API: $message");
        }
        
        return $success;
    }
    
    /**
     * Обновление файлового кеша блокировок с расширенной информацией
     */
    private function updateBlockedIPsCache() {
        try {
            $blocked_ips = array();
            $blocked_info = array();
            
            // Если используем Redis
            if ($this->useRedis && $this->redis) {
                try {
                    $blockedIpsKey = $this->prefix . 'blocked_ips';
                    $now = time();
                    
                    $blocked_list = $this->redis->zRangeByScore($blockedIpsKey, $now, '+inf', array('WITHSCORES' => true));
                    
                    if (is_array($blocked_list)) {
                        foreach ($blocked_list as $ip => $block_until) {
                            $blocked_ips[$ip] = (int)$block_until;
                            
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
                } catch (Exception $e) {
                    error_log("Ошибка при получении данных блокировки из Redis: " . $e->getMessage());
                }
            }
            // Если используем MariaDB
            else if ($this->db) {
                $stmt = $this->db->query("
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
            } else {
                return false;
            }
            
            if (!is_dir($this->dos_dir)) {
                mkdir($this->dos_dir, 0755, true);
            }
            
            $cache_file = $this->dos_dir . 'blocked_ips.php';
            $content = "<?php\n\$blocked_ips = " . var_export($blocked_ips, true) . ";\n";
            
            $info_file = $this->dos_dir . 'blocked_info.php';
            $info_content = "<?php\n\$blocked_info = " . var_export($blocked_info, true) . ";\n";
            
            $tmp_file = $cache_file . '.tmp';
            if (file_put_contents($tmp_file, $content) !== false) {
                rename($tmp_file, $cache_file);
            }
            
            $tmp_info_file = $info_file . '.tmp';
            if (file_put_contents($tmp_info_file, $info_content) !== false) {
                rename($tmp_info_file, $info_file);
            }
            
            return true;
        } catch (Exception $e) {
            error_log("Error updating blocked IPs cache: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Добавление в список жесткой блокировки
     */
    public function addToHardBlockList($reason = 'Превышено количество попыток разблокировки') {
        $entry = date('Y-m-d H:i:s') . " - " . $this->ip . " - " . $reason . "\n";
        return @file_put_contents($this->hard_block_file, $entry, FILE_APPEND) !== false;
    }
    
    /**
     * Логирование попытки разблокировки
     */
    public function logUnlockAttempt($success) {
        $log_file = $this->dos_dir . 'recaptcha_unlock.log';
        $log_message = date('Y-m-d H:i:s') . ' - IP: ' . $this->ip . ' - ' . 
                      ($success ? 'Успешная разблокировка' : 'Неудачная попытка разблокировки') . "\n";
        @file_put_contents($log_file, $log_message, FILE_APPEND);
        
        if (!$success) {
            $this->logUnlockAttemptFile($success);
        }
    }
    
    /**
     * Логирование неудачной попытки разблокировки
     */
    public function logUnlockAttemptFile($success) {
        if ($success) {
            return;
        }
        
        $log_entry = date('Y-m-d H:i:s') . " - " . $this->ip . " - Неудачная попытка\n";
        @file_put_contents($this->attempts_file, $log_entry, FILE_APPEND);
        
        $recent_failures = $this->countRecentFailures();
        
        if ($recent_failures >= $this->max_failures) {
            $reason = "Превышено количество попыток разблокировки ($recent_failures)";
            $this->addToHardBlockList($reason);
            $this->applyHardBlock($reason);
        }
    }
    
    /**
     * Подсчет количества неудачных попыток за последний час
     */
    private function countRecentFailures() {
        if (!file_exists($this->attempts_file)) {
            return 0;
        }
        
        $content = file_get_contents($this->attempts_file);
        $lines = explode("\n", $content);
        
        $one_hour_ago = time() - $this->failure_window;
        $recent_failures = 0;
        
        foreach ($lines as $line) {
            if (empty(trim($line))) {
                continue;
            }
            
            if (strpos($line, $this->ip) !== false) {
                $timestamp = strtotime(substr($line, 0, 19));
                
                if ($timestamp > $one_hour_ago) {
                    $recent_failures++;
                }
            }
        }
        
        return $recent_failures;
    }
    
    /**
     * Получение IP-адреса
     */
    public function getIP() {
        return $this->ip;
    }
}
?>
