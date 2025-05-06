<?php
require_once 'settings.php';
// /dos/recaptcha_unlock.php
// Страница разблокировки IP с использованием reCAPTCHA и поддержкой Redis

// Отключаем мониторинг безопасности для этой страницы
define('DISABLE_SECURITY_MONITOR', true);

// Подключаем класс мониторинга безопасности
require_once 'security_monitor.php';

// Определение переменных для работы с Redis
$useRedis = defined('USE_REDIS') ? USE_REDIS : false;
$redis = null;
$redisPrefix = defined('REDIS_PREFIX') ? REDIS_PREFIX : 'dos:';

// Отслеживание частоты посещений страницы разблокировки
$visits_file = dirname(__FILE__) . '/unlock_visits.log';
$current_ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
$current_time = time();
$visit_log_entry = date('Y-m-d H:i:s') . " - " . $current_ip . "\n";

// Логируем каждое посещение страницы (файловый лог как запасной вариант)
@file_put_contents($visits_file, $visit_log_entry, FILE_APPEND);

// Сохраняем страницу-источник в сессии
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Получаем URL из GET-параметра, если он есть (для прямого указания возвратного URL)
if (isset($_GET['return_to']) && !empty($_GET['return_to'])) {
    // Базовая проверка для предотвращения открытого перенаправления
    $return_to = $_GET['return_to'];
    // Compat check for FILTER_VALIDATE_URL in older PHP versions
    if ((function_exists('filter_var') && filter_var($return_to, FILTER_VALIDATE_URL)) && 
        (strpos($return_to, '/') === 0 || parse_url($return_to, PHP_URL_HOST) === $_SERVER['HTTP_HOST'])) {
        $_SESSION['original_url'] = $return_to;
    }
}

// Получаем URL страницы, с которой произошло перенаправление, если не было GET параметра
if (!isset($_SESSION['original_url']) && isset($_SERVER['HTTP_REFERER'])) {
    $referer = $_SERVER['HTTP_REFERER'];
    // Проверяем, что реферер не указывает на страницу разблокировки
    if (strpos($referer, 'recaptcha_unlock.php') === false) {
        $_SESSION['original_url'] = $referer;
    }
}

// Класс для управления разблокировкой IP через reCAPTCHA с поддержкой Redis
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
    private $max_failures = 3; // Максимальное количество неудачных попыток
    private $failure_window = 3600; // Окно в 1 час (в секундах)
    private $max_visits = 10; // Максимальное количество посещений
    private $visits_window = 300; // Окно в 5 минут (в секундах)
    
	/**
 * Очистка файлов счетчиков запросов
 */
public function cleanupRequestCounters() {
    // Очистка файловых счетчиков
    $minute_requests_dir = $this->dos_dir . 'minute_requests/';
    $total_requests_dir = $this->dos_dir . 'total_requests/';
    
    // Очистка директории minute_requests
    if (is_dir($minute_requests_dir)) {
        $this->cleanDirectory($minute_requests_dir);
    }
    
    // Очистка директории total_requests
    if (is_dir($total_requests_dir)) {
        $this->cleanDirectory($total_requests_dir);
    }
    
    // Очистка счетчиков в Redis, если доступен
    if ($this->useRedis && $this->redis) {
        try {
            // Получаем все ключи minute_requests
            $minute_keys = $this->redis->keys($this->prefix . "minute_requests:*");
            
            // Получаем все ключи total_requests
            $total_keys = $this->redis->keys($this->prefix . "total_requests:*");
            
            // Удаляем ключи
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
    
    // Получение IP-адреса клиента
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
        
        // Если ничего не нашли, возвращаем REMOTE_ADDR
        return $_SERVER['REMOTE_ADDR'];
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
            
            return true;
        } catch (Exception $e) {
            error_log("Redis connection error: " . $e->getMessage());
            $this->useRedis = false;
            return false;
        }
    }
    
    // Отслеживание визитов в Redis
    private function trackVisitRedis() {
        if (!$this->redis) return false;
        
        try {
            // Ключ для отслеживания визитов этого IP
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
            $this->redis->ltrim($this->prefix . "all_unlock_visits", 0, 999); // Ограничиваем список 1000 записями
            
            return true;
        } catch (Exception $e) {
            error_log("Error tracking visit in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    // Обнаружение слишком частых посещений страницы через Redis
    public function detectFrequentVisits() {
        // Если используем Redis
        if ($this->useRedis && $this->redis) {
            try {
                // Получаем количество визитов в окне отслеживания
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
                // Fallback to file-based check
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
    
    // Подключение к БД
    private function connectDB() {
        try {
            $this->db = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
            if (defined('PDO::ATTR_ERRMODE')) {
                $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            }
            $this->db->exec("SET NAMES utf8mb4");
        } catch(PDOException $e) {
            error_log("Ошибка подключения к БД: " . $e->getMessage());
            // Не прерываем работу скрипта, даже если соединение не удалось
        }
    }
    
    // Проверка блокировки IP через Redis
    public function isIPBlockedRedis() {
        if (!$this->redis) return false;
        
        try {
            // Проверяем наличие ключа блокировки
            $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
            
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
                $this->redis->zRem($this->prefix . "blocked_ips", $this->ip);
            }
            
            return false;
        } catch (Exception $e) {
            error_log("Error checking IP block in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    // Проверка блокировки IP через БД
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
    
    // Проверка блокировки IP (обобщенный метод)
    public function isIPBlocked() {
        // Сначала проверяем через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            return $this->isIPBlockedRedis();
        }
        
        // Иначе через MariaDB
        return $this->isIPBlockedDB();
    }
    
    // Проверка наличия IP в списке жестких блокировок через Redis
    public function isInHardBlockListRedis() {
        if (!$this->redis) return false;
        
        try {
            // Проверяем наличие IP в списке жестких блокировок
            $hardBlockKey = $this->prefix . "hard_blocked:{$this->ip}";
            
            // Если ключ существует, IP в жестком списке
            if ($this->redis->exists($hardBlockKey)) {
                return true;
            }
            
            // Проверяем наличие в базе данных с флагом жесткой блокировки
            // Получаем информацию о блокировке из Redis
            $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
            if ($this->redis->exists($blockKey)) {
                // Проверяем счетчик блокировок (жесткая блокировка при block_count >= 100)
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
    
    // Проверка, находится ли IP в списке для жесткой блокировки через файл и БД
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
        
        // Возвращаем true, если IP находится либо в файле, либо в БД с флагом жесткой блокировки
        return $in_file || $in_db;
    }
    
    // Обобщенный метод проверки жесткой блокировки
    public function isInHardBlockList() {
        // Сначала проверяем через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            return $this->isInHardBlockListRedis();
        }
        
        // Иначе через файл и MariaDB
        return $this->isInHardBlockListFile();
    }
    
    // Получение информации о блокировке из Redis
    public function getBlockInfoRedis() {
    if (!$this->redis) return false;
    
    try {
        // Получаем данные о блокировке
        $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
        
        // Если ключ не существует, нет блокировки
        if (!$this->redis->exists($blockKey)) {
            return false;
        }
        
        // Получаем информацию из хэша
        $blockInfo = $this->redis->hGetAll($blockKey);
        
        // Проверка существования индексов перед преобразованием
        // Преобразуем строковые значения в числовые, где необходимо
        $blockInfo['block_count'] = isset($blockInfo['block_count']) ? (int)$blockInfo['block_count'] : 0;
        $blockInfo['block_until'] = isset($blockInfo['block_until']) ? (int)$blockInfo['block_until'] : 0;
        $blockInfo['created_at'] = isset($blockInfo['created_at']) ? (int)$blockInfo['created_at'] : 0;
        $blockInfo['first_blocked_at'] = isset($blockInfo['first_blocked_at']) ? (int)$blockInfo['first_blocked_at'] : 0;
        
        // Для совместимости с форматом из MariaDB
        // Преобразуем временные метки в MySQL datetime формат
        $blockInfo['block_until'] = date('Y-m-d H:i:s', $blockInfo['block_until']);
        $blockInfo['first_blocked_at'] = date('Y-m-d H:i:s', $blockInfo['first_blocked_at']);
        
        return $blockInfo;
    } catch (Exception $e) {
        error_log("Error getting block info from Redis: " . $e->getMessage());
        return false;
    }
}
    
    // Получение информации о блокировке из БД
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
    
    // Обобщенный метод получения информации о блокировке
    public function getBlockInfo() {
        // Сначала проверяем Redis, если доступен
        if ($this->useRedis && $this->redis) {
            $redisInfo = $this->getBlockInfoRedis();
            if ($redisInfo) {
                return $redisInfo;
            }
        }
        
        // Иначе через MariaDB
        return $this->getBlockInfoDB();
    }
    
    // Метод для форматирования времени блокировки
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
 * Разблокировка IP через Redis
 */
public function unblockIPRedis() {
    if (!$this->redis) return false;
    
    try {
        // Ключ блокировки
        $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
        
        // Проверяем, существует ли блокировка
        if (!$this->redis->exists($blockKey)) {
            return true; // Нечего разблокировать
        }
        
        // Удаляем из Redis
        // 1. Удаляем ключ блокировки
        $this->redis->del($blockKey);
        
        // 2. Удаляем из отсортированного множества
        $this->redis->zRem($this->prefix . "blocked_ips", $this->ip);
        
        // Выполняем внешние разблокировки
        $this->removeIPFromConf($this->ip);
        $this->removeIPFromHtaccess($this->ip);
        $this->unblockIPFromIptables($this->ip);
        $this->unblockIPViaAPI($this->ip);
        
        // Сбрасываем счетчики запросов для IP
        $this->redis->del($this->prefix . "ip_request_rate:{$this->ip}");
        
        // Сбрасываем счетчики для новых лимитов
        $this->redis->del($this->prefix . "minute_requests:{$this->ip}");
        $this->redis->del($this->prefix . "total_requests:{$this->ip}");
        
        // Логируем разблокировку
        $this->redis->lPush($this->prefix . "unblock_log", json_encode([
            'ip' => $this->ip,
            'time' => time(),
            'method' => 'recaptcha'
        ]));
        $this->redis->ltrim($this->prefix . "unblock_log", 0, 999);
        
        // Сбрасываем сессионные счетчики
        if (session_status() == PHP_SESSION_ACTIVE) {
            $_SESSION['page_requests'] = array();
            $_SESSION['requests_log'] = array();
            $_SESSION['request_count'] = 0;
            $_SESSION['last_request_time'] = time();
        }
        
        return true;
    } catch (Exception $e) {
        error_log("Error unblocking IP in Redis: " . $e->getMessage());
        return false;
    }
}
    
    /**
 * Разблокировка IP через БД
 */
public function unblockIPDB() {
    try {
        if (!$this->db) {
            return false;
        }
        
        // Сначала выполняем все операции разблокировки через внешние системы
        
        // Разблокировка через IP.conf
        $this->removeIPFromConf($this->ip);
        
        // Разблокировка через .htaccess
        $this->removeIPFromHtaccess($this->ip);
        
        // Разблокировка через iptables
        $this->unblockIPFromIptables($this->ip);
        
        // Разблокировка через API
        $this->unblockIPViaAPI($this->ip);
        
        // Затем удаляем из базы данных
        $stmt = $this->db->prepare("DELETE FROM blocked_ips WHERE ip = ?");
        $result = $stmt->execute(array($this->ip));
        
        if ($result) {
            // Обновляем кеш блокировок
            $this->updateBlockedIPsCache();
            
            // Сбрасываем счетчики запросов для IP
            $this->db->prepare("DELETE FROM ip_request_rate WHERE ip = ?")->execute(array($this->ip));
            
            // Сбрасываем файловые счетчики для новых лимитов
            $minute_requests_file = $this->dos_dir . 'minute_requests/' . str_replace([':', '.'], '_', $this->ip) . '.txt';
            $total_requests_file = $this->dos_dir . 'total_requests/' . str_replace([':', '.'], '_', $this->ip) . '.txt';
            if (file_exists($minute_requests_file)) {
                @unlink($minute_requests_file);
            }
            if (file_exists($total_requests_file)) {
                @unlink($total_requests_file);
            }
            
            // Сбрасываем сессионные счетчики
            if (session_status() == PHP_SESSION_ACTIVE) {
                $_SESSION['page_requests'] = array();
                $_SESSION['requests_log'] = array();
                $_SESSION['request_count'] = 0;
                $_SESSION['last_request_time'] = time();
            }
            
            return true;
        }
        
        return false;
    } catch(PDOException $e) {
        error_log("Error unblocking IP: " . $e->getMessage());
        return false;
    }
}
    
    // Обобщенный метод разблокировки IP
    public function unblockIP() {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            if ($this->unblockIPRedis()) {
                return true;
            }
        }
        
        // Иначе через MariaDB
        return $this->unblockIPDB();
    }
    
    // Проверка reCAPTCHA
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
    
    // Обновление файлового кеша блокировок с расширенной информацией
    private function updateBlockedIPsCache() {
        try {
            // Используем Redis
            if ($this->useRedis && $this->redis) {
                // Получаем все активные блокировки из Redis
                $blockedIpsKey = $this->prefix . 'blocked_ips';
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
        } catch (Exception $e) {
            error_log("Error updating blocked IPs cache: " . $e->getMessage());
            return false;
        }
    }
    
    // Логирование попытки разблокировки в Redis
    public function logUnlockAttemptRedis($success) {
        if (!$this->redis) return false;
        
        try {
            // Логируем в Redis
            $now = time();
            
            // Добавляем запись в лог попыток
            $this->redis->lPush($this->prefix . "unlock_attempts", json_encode([
                'ip' => $this->ip,
                'time' => $now,
                'success' => $success
            ]));
            $this->redis->ltrim($this->prefix . "unlock_attempts", 0, 999);
            
            // Если успешно, очищаем счетчик неудачных попыток и выходим
            if ($success) {
                $this->redis->del($this->prefix . "unlock_failures:{$this->ip}");
                return true;
            }
            
            // Увеличиваем счетчик неудачных попыток
            $attemptsKey = $this->prefix . "unlock_failures:{$this->ip}";
            $this->redis->zAdd($attemptsKey, $now, $now);
            $this->redis->expire($attemptsKey, $this->failure_window * 2); // TTL в 2 раза больше окна
            
            // Удаляем все попытки старше окна отслеживания
            $cutoff = $now - $this->failure_window;
            $this->redis->zRemRangeByScore($attemptsKey, 0, $cutoff);
            
            // Проверяем количество неудачных попыток за последний час
            $recentFailures = $this->redis->zCard($attemptsKey);
            
            // Если больше максимального количества неудачных попыток, добавляем в список жесткой блокировки
            if ($recentFailures >= $this->max_failures) {
                $reason = "Превышено количество попыток разблокировки ($recentFailures)";
                $this->addToHardBlockList($reason);
                $this->applyHardBlock($reason);
            }
            
            return true;
        } catch (Exception $e) {
            error_log("Error logging unlock attempt in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    // Запись в лог (файл)
    public function logUnblock($success) {
        $log_file = $this->dos_dir . 'recaptcha_unlock.log';
        $log_message = date('Y-m-d H:i:s') . ' - IP: ' . $this->ip . ' - ' . 
                      ($success ? 'Успешная разблокировка' : 'Неудачная попытка разблокировки') . "\n";
        @file_put_contents($log_file, $log_message, FILE_APPEND);
    }
    
    // Логирование попытки разблокировки (файл)
    public function logUnlockAttemptFile($success) {
        // Логируем в основной лог
        $this->logUnblock($success);
        
        // Если успешно, не нужно ничего делать дальше
        if ($success) {
            return;
        }
        
        // Логируем неудачную попытку в отдельный лог
        $log_entry = date('Y-m-d H:i:s') . " - " . $this->ip . " - Неудачная попытка\n";
        @file_put_contents($this->attempts_file, $log_entry, FILE_APPEND);
        
        // Проверяем количество неудачных попыток за последний час
        $recent_failures = $this->countRecentFailures();
        
        // Если больше максимального количества неудачных попыток, добавляем в список жесткой блокировки
        if ($recent_failures >= $this->max_failures) {
            $reason = "Превышено количество попыток разблокировки ($recent_failures)";
            $this->addToHardBlockList($reason);
            $this->applyHardBlock($reason);
        }
    }
    
    // Обобщенный метод логирования попытки разблокировки
    public function logUnlockAttempt($success) {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            if ($this->logUnlockAttemptRedis($success)) {
                // Для совместимости, также пишем в файловый лог
                $this->logUnblock($success);
                return true;
            }
        }
        
        // Иначе через файл
        $this->logUnlockAttemptFile($success);
        return true;
    }
    
    // Подсчет количества неудачных попыток за последний час (через файл)
    private function countRecentFailures() {
        // Если файл не существует, нет неудачных попыток
        if (!file_exists($this->attempts_file)) {
            return 0;
        }
        
        // Читаем содержимое файла
        $content = file_get_contents($this->attempts_file);
        $lines = explode("\n", $content);
        
        // Устанавливаем время для сравнения (час назад)
        $one_hour_ago = time() - $this->failure_window;
        
        // Счетчик неудачных попыток
        $recent_failures = 0;
        
        // Проходим по каждой строке
        foreach ($lines as $line) {
            // Пропускаем пустые строки
            if (empty(trim($line))) {
                continue;
            }
            
            // Проверяем, содержит ли строка текущий IP
            if (strpos($line, $this->ip) !== false) {
                // Извлекаем дату из строки
                $timestamp = strtotime(substr($line, 0, 19));
                
                // Если дата попадает в окно (последний час)
                if ($timestamp > $one_hour_ago) {
                    $recent_failures++;
                }
            }
        }
        
        return $recent_failures;
    }
    
    // Добавление в список жесткой блокировки через Redis
    private function addToHardBlockListRedis($reason = 'Превышено количество попыток разблокировки') {
        if (!$this->redis) return false;
        
        try {
            $now = time();
            
            // Создаем запись о жесткой блокировке
            $hardBlockKey = $this->prefix . "hard_blocked:{$this->ip}";
            $this->redis->hMSet($hardBlockKey, [
                'reason' => $reason,
                'time' => $now
            ]);
            
            // Устанавливаем большой TTL (30 дней)
            $this->redis->expire($hardBlockKey, 30 * 86400);
            
            // Добавляем в лог жестких блокировок
            $this->redis->lPush($this->prefix . "hard_block_log", json_encode([
                'ip' => $this->ip,
                'reason' => $reason,
                'time' => $now
            ]));
            $this->redis->ltrim($this->prefix . "hard_block_log", 0, 999);
            
            return true;
        } catch (Exception $e) {
            error_log("Error adding to hard block list in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    // Добавление в список жесткой блокировки через файл
    private function addToHardBlockListFile($reason = 'Превышено количество попыток разблокировки') {
        $entry = date('Y-m-d H:i:s') . " - " . $this->ip . " - " . $reason . "\n";
        return @file_put_contents($this->hard_block_file, $entry, FILE_APPEND) !== false;
    }
    
    // Обобщенный метод добавления в список жесткой блокировки
    public function addToHardBlockList($reason = 'Превышено количество попыток разблокировки') {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            if ($this->addToHardBlockListRedis($reason)) {
                // Для совместимости, также пишем в файл
                $this->addToHardBlockListFile($reason);
                return true;
            }
        }
        
        // Иначе через файл
        return $this->addToHardBlockListFile($reason);
    }
    
    // Применение жесткой блокировки через Redis
    private function applyHardBlockRedis($reason = 'Жесткая блокировка') {
        if (!$this->redis) return false;
        
        try {
            $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
            $now = time();
            $block_count = 999; // Высокое значение для обозначения жесткой блокировки
            $block_days = 7;    // Блокировка на 7 дней
            $blockUntil = $now + ($block_days * 86400);
            
            // Обновляем или создаем блокировку в Redis
            $this->redis->multi();
            $this->redis->hMSet($blockKey, [
                'block_until' => $blockUntil,
                'reason' => "Жесткая блокировка: " . $reason,
                'created_at' => $now,
                'block_count' => $block_count,
                'first_blocked_at' => isset($blockData['first_blocked_at']) ? $blockData['first_blocked_at'] : $now
            ]);
            
            // Устанавливаем TTL
            $this->redis->expireAt($blockKey, $blockUntil);
            
            // Добавляем в отсортированное множество
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
    
    // Применение жесткой блокировки через БД
    private function applyHardBlockDB($reason = 'Жесткая блокировка') {
        try {
            if (!$this->db) {
                error_log("Ошибка: нет соединения с БД для жесткой блокировки IP $this->ip");
                return false;
            }
            
            // Блокируем IP на 7 дней с высоким значением счетчика
            $block_count = 999; // Используем высокое значение как флаг жесткой блокировки
            $block_days = 7;    // Блокировка на 7 дней
            
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
    
    // Обобщенный метод применения жесткой блокировки
    public function applyHardBlock($reason = 'Жесткая блокировка') {
        // Сначала через Redis, если доступен
        if ($this->useRedis && $this->redis) {
            if ($this->applyHardBlockRedis($reason)) {
                return true;
            }
        }
        
        // Иначе через БД
        return $this->applyHardBlockDB($reason);
    }
    
    // Применение всех внешних блокировок
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
    
    // Блокировка IP в .htaccess
    private function blockIPInHtaccess($ip) {
        // Пропускаем, если блокировка через .htaccess отключена
        if (defined('ENABLE_HTACCESS_BLOCKING') && !ENABLE_HTACCESS_BLOCKING) {
            return false;
        }
        
        // Проверяем, не заблокирован ли IP уже
        if ($this->isIPBlockedInHtaccess($ip)) {
            return true;
        }
        
        $htaccessPath = dirname($this->dos_dir) . '/.htaccess';
        
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
        
        // Если в файле уже что-то есть и последний символ не перенос строки,
        // добавляем перенос строки перед правилом
        if (!empty($currentContent) && substr($currentContent, -1) !== "\n") {
            $rule = "\n" . $rule;
        }
        
        // Попытка записи в файл
        $success = file_put_contents($htaccessPath, $rule, FILE_APPEND);
        
        if (!$success) {
            error_log("Ошибка при записи в .htaccess");
            
            // Пробуем другой метод (чтение и запись всего файла)
            $htaccessContent = file_exists($htaccessPath) ? file_get_contents($htaccessPath) : "";
            
            // Проверяем, нужно ли добавить перенос строки
            if (!empty($htaccessContent) && substr($htaccessContent, -1) !== "\n") {
                $htaccessContent .= "\n";
            }
            
            $htaccessContent .= $rule;
            
            $result = file_put_contents($htaccessPath, $htaccessContent);
            
            if ($result !== false && $this->isIPBlockedInHtaccess($ip)) {
                return true;
            } else {
                error_log("Все методы блокировки через .htaccess не удались");
                return false;
            }
        }
        
        // Проверяем, что запись действительно произошла
        if ($this->isIPBlockedInHtaccess($ip)) {
            return true;
        }
        
        return false;
    }
    
    // Проверка, заблокирован ли IP в .htaccess
    private function isIPBlockedInHtaccess($ip) {
        $htaccessPath = dirname($this->dos_dir) . '/.htaccess';
        
        // Если файл не существует, IP точно не заблокирован
        if (!file_exists($htaccessPath)) {
            return false;
        }
        
        // Чтение содержимого файла
        $htaccessContent = file_get_contents($htaccessPath);
        
        // Если файл пуст или ошибка чтения
        if ($htaccessContent === false || empty($htaccessContent)) {
            return false;
        }
        
        // Проверка наличия правила блокировки
        return strpos($htaccessContent, "Deny from $ip") !== false;
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
    
    // Функция для проверки валидности IP-адреса (IPv4 или IPv6)
    private function isValidIP($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP);
    }
    
    // Функция для записи IP в ip.conf в формате "IP 1;" и перезагрузки Nginx
    private function logIPToConf($ip) {
        // Пропускаем, если блокировка через Nginx отключена
        if (defined('ENABLE_NGINX_BLOCKING') && !ENABLE_NGINX_BLOCKING) {
            return false;
        }
        
        // Проверяем, что IP-адрес валидный
        if (!$this->isValidIP($ip)) {
            error_log("IP $ip не является корректным IPv4 или IPv6 адресом");
            return false;
        }
        
        $ipConfFile = $this->dos_dir . 'ip.conf';
        
        // Массив для хранения IP-адресов
        $blockedIPs = array();
        
        // Если файл существует, читаем существующие заблокированные IP
        if (file_exists($ipConfFile)) {
            $lines = file($ipConfFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            
            if ($lines !== false) {
                foreach ($lines as $line) {
                    // Пропускаем комментарии
                    if (strpos($line, '#') === 0) {
                        continue;
                    }
                    
                    // Извлекаем IP из строки (первая часть до пробела)
                    $parts = explode(' ', trim($line));
                    $lineIP = $parts[0];
                    
                    // Проверяем, что это валидный IP
                    if ($this->isValidIP($lineIP)) {
                        $blockedIPs[] = $lineIP;
                    }
                }
            }
        }
        
        // Добавляем текущий IP, если его нет в списке
        if (!in_array($ip, $blockedIPs)) {
            $blockedIPs[] = $ip;
        } else {
            return true; // Ничего не делаем, если IP уже в списке
        }
        
        // Формируем новое содержимое файла в требуемом формате
        $fileContent = "# Обновлено " . date('Y-m-d H:i:s') . "\n";
        
        // Добавляем все IP-адреса в формате "IP 1;"
        foreach ($blockedIPs as $blockedIP) {
            $fileContent .= "$blockedIP 1;\n";
        }
        
        // Записываем в файл (полная перезапись)
        $success = file_put_contents($ipConfFile, $fileContent);

        if ($success !== false) {
            // Выполняем команду перезагрузки Nginx
            $reload_output = array();
            $reload_result = 0;
            exec('sudo /usr/sbin/nginx -s reload 2>&1', $reload_output, $reload_result);
            
            // Логируем результат перезагрузки
            if ($reload_result !== 0) {
                error_log("Ошибка при перезагрузке Nginx: " . implode("\n", $reload_output));
            } else {
                error_log("Nginx успешно перезагружен после обновления ip.conf");
            }
            
            return true;
        }
        
        return false;
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
    
    // Блокировка IP через iptables/ip6tables
    public function blockIPWithIptables($ip) {
        // Пропускаем, если блокировка через брандмауэр отключена
        if (defined('ENABLE_FIREWALL_BLOCKING') && !ENABLE_FIREWALL_BLOCKING) {
            return false;
        }
        
        // Определяем версию IP
        $isIPv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        
        // Блокируем порты 80 и 443
        $ports = array(80, 443);
        
        error_log("Блокируем IP в iptables: $ip, IPv6: " . ($isIPv6 ? "да" : "нет"));
        
        foreach ($ports as $port) {
            // Формируем команду в зависимости от версии IP
            if ($isIPv6) {
                $command = "sudo ip6tables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
            } else {
                $command = "sudo iptables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
            }
            
            // Выполняем команду блокировки
            exec($command);
        }
        
        // Сохраняем правила для сохранения после перезагрузки
        if ($isIPv6) {
            exec("sudo sh -c 'ip6tables-save > /etc/iptables/rules.v6'");
        } else {
            exec("sudo sh -c 'iptables-save > /etc/iptables/rules.v4'");
        }
        
        error_log("IP $ip успешно заблокирован через iptables");
        return true;
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
            
            // Выполняем команду
            $output = array();
            $returnVar = 0;
            exec($command, $output, $returnVar);
            
            // Логируем результат удаления
            error_log("Удаление IP $ip из " . ($isIPv6 ? "ip6tables" : "iptables") . " для порта $port: " . 
                         ($returnVar == 0 ? "успешно" : "правило не найдено или ошибка"));
        }
        
        // Также удаляем общее правило (для совместимости со старыми версиями)
        if ($isIPv6) {
            $command = "sudo ip6tables -D INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null";
        } else {
            $command = "sudo iptables -D INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null";
        }
        
        // Выполняем команду не проверяя результат
        exec($command);
        
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
    
    // Функция для блокировки IP через внешний API
    private function blockIPWithAPI($ip) {
        // Пропускаем, если блокировка через API отключена
        if (defined('ENABLE_API_BLOCKING') && !ENABLE_API_BLOCKING) {
            return false;
        }
        
        // Проверяем валидность IP-адреса
        if (!$this->isValidIP($ip)) {
            error_log("Ошибка: IP $ip некорректен для блокировки через API");
            return false;
        }
        
        // Получаем URL из настроек
        $url = defined('API_BLOCK_URL') ? API_BLOCK_URL : '';
        if (empty($url)) {
            error_log("Ошибка: API_BLOCK_URL не определен в настройках");
            return false;
        }
        
        // Получаем API ключ из настроек
        $api_key = defined('API_BLOCK_KEY') ? API_BLOCK_KEY : '';
        
        // Получаем User-Agent из настроек или используем значение по умолчанию
        $userAgent = defined('API_USER_AGENT') ? API_USER_AGENT : 'PHP/' . PHP_VERSION;
        
        // Подготавливаем параметры запроса
        $params = array(
            'action' => 'block',
            'ip' => $ip,
            'api_key' => $api_key,
            'api' => 1 // Включаем режим API для получения JSON-ответа
        );
        
        // Формируем URL запроса
        $requestUrl = $url . '?' . http_build_query($params);
        
        error_log("Выполняем блокировку IP $ip через API: $requestUrl");
        
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
            error_log("Ошибка API блокировки для IP $ip: $error");
            return false;
        }
        
        // Если код ответа не 200 OK
        if ($httpCode !== 200) {
            error_log("Ошибка API блокировки для IP $ip: HTTP код $httpCode");
            return false;
        }
        
        // Пытаемся разобрать JSON-ответ
        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("Ошибка разбора JSON-ответа от API для IP $ip: " . $response);
            return false;
        }
        
        // Проверяем статус блокировки
        $success = isset($data['status']) && $data['status'] === 'success';
        
        // Логируем результат
        if ($success) {
            error_log("IP $ip успешно заблокирован через API");
        } else {
            $message = isset($data['message']) ? $data['message'] : 'Неизвестная ошибка';
            error_log("Ошибка блокировки IP $ip через API: $message");
        }
        
        return $success;
    }
    
    // Получение IP-адреса
    public function getIP() {
        return $this->ip;
    }
}

// Создаем экземпляр класса
$unlocker = new RecaptchaUnlock();

// Проверяем частоту посещений страницы до любых других проверок
$too_many_visits = $unlocker->detectFrequentVisits();

// Переменные для шаблона
$success_message = '';
$error_message = '';
$is_blocked = $unlocker->isIPBlocked();
$current_ip = $unlocker->getIP();
$is_hard_blocked = $unlocker->isInHardBlockList() || $too_many_visits;

// Получаем URL для возврата до обработки формы
$return_url = isset($_SESSION['original_url']) ? $_SESSION['original_url'] : '/';

// Обработка формы
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['g-recaptcha-response'])) {
    $recaptcha_response = $_POST['g-recaptcha-response'];
    
    // Сохраняем URL возврата из POST-запроса, если он есть
    if (isset($_POST['return_url']) && !empty($_POST['return_url'])) {
        $return_url = $_POST['return_url'];
        // Базовая проверка URL для безопасности
        if ((function_exists('filter_var') && filter_var($return_url, FILTER_VALIDATE_URL)) && 
            (strpos($return_url, '/') === 0 || parse_url($return_url, PHP_URL_HOST) === $_SERVER['HTTP_HOST'])) {
            $_SESSION['original_url'] = $return_url;
        }
    }
    
    // Проверяем, не находится ли IP в списке жестких блокировок
    if ($is_hard_blocked) {
        $error_message = "Ваш IP-адрес был жестко заблокирован из-за подозрительной активности. Свяжитесь с администратором.";
        $unlocker->logUnlockAttempt(false);
    } else {
        // Проверяем reCAPTCHA
        if ($unlocker->verifyRecaptcha($recaptcha_response)) {
            if ($unlocker->unblockIP()) {
                // Очищаем счетчики запросов для новых лимитов
                $unlocker->cleanupRequestCounters();
                
                $success_message = "Ваш IP-адрес $current_ip успешно разблокирован!";
                $unlocker->logUnlockAttempt(true);
                $is_blocked = false;
                // НЕ удаляем $_SESSION['original_url'] здесь
            } else {
                $error_message = "Не удалось разблокировать IP-адрес. Пожалуйста, попробуйте еще раз.";
                $unlocker->logUnlockAttempt(false);
            }
        } else {
            $error_message = "Проверка reCAPTCHA не пройдена. Пожалуйста, попробуйте еще раз.";
            $unlocker->logUnlockAttempt(false);
        }
    }
    
    // Обновляем переменную return_url после обработки формы
    $return_url = isset($_SESSION['original_url']) ? $_SESSION['original_url'] : '/';
}

// Заголовки для предотвращения кеширования
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Content-Type: text/html; charset=utf-8");
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Разблокировка доступа</title>
    <script src="https://www.google.com/recaptcha/api.js?render=<?php echo RECAPTCHA_SITE_KEY; ?>"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            margin-top: 0;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }
        .message {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .success {
            background-color: #dff0d8;
            color: #3c763d;
            border: 1px solid #d6e9c6;
        }
        .error {
            background-color: #f2dede;
            color: #a94442;
            border: 1px solid #ebccd1;
        }
        .warning {
            background-color: #fff3cd;
            color: #856404;
            padding: 15px;
            border-left: 5px solid #ffeeba;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .danger {
            background-color: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-left: 5px solid #f5c6cb;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .btn {
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 10px 15px;
            text-decoration: none;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        .btn:hover {
            background-color: #2980b9;
        }
        .info {
            margin-top: 20px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 4px;
            border-left: 3px solid #3498db;
        }
        .footer {
            margin-top: 20px;
            font-size: 14px;
            color: #777;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Разблокировка доступа</h1>
        
        <?php if (!empty($success_message)): ?>
            <div class="message success"><?php echo htmlspecialchars($success_message); ?></div>
            <div class="info">
                <p>Доступ к сайту восстановлен. <a href="<?php echo htmlspecialchars($return_url); ?>">Вернуться на предыдущую страницу</a>
				<br>Ваш щит в цифровом мире. © MurKir Security, 2025 </p>
            </div>
        <?php elseif (!$is_blocked): ?>
            <div class="info">
                <p>Ваш IP-адрес (<?php echo htmlspecialchars($current_ip); ?>) не заблокирован.</p>
                <p><a href="<?php echo htmlspecialchars($return_url); ?>">Вернуться на предыдущую страницу</a>
				<br>Ваш щит в цифровом мире. © MurKir Security, 2025 </p>
            </div>
        <?php elseif ($is_hard_blocked): ?>
            <div class="danger">
                <p><strong>Внимание: Ваш IP-адрес жестко заблокирован!</strong></p>
                <p>Ваш IP-адрес (<?php echo htmlspecialchars($current_ip); ?>) был заблокирован на уровне брандмауэра из-за подозрительной активности:</p>
                <ul>
                    <li>Многократные неудачные попытки разблокировки</li>
                    <li>Слишком частое обновление страницы разблокировки</li>
                    <li>Другие подозрительные действия</li>
                </ul>
                <p>Для разблокировки необходимо связаться с администрацией сайта. <br>Ваш щит в цифровом мире. © MurKir Security, 2025 </p>
            </div>
        <?php else: ?>
            <?php 
            $block_info = $unlocker->getBlockInfo();
            if ($block_info): 
                $block_count = $block_info['block_count'];
                $block_until = strtotime($block_info['block_until']);
                $time_remaining = $unlocker->formatTimeRemaining($block_until);
            ?>
                <div class="warning">
                    <p><strong>Информация о блокировке:</strong></p>
                    <p>Ваш IP-адрес заблокирован <?php echo $block_count > 1 ? "повторно (блокировка #$block_count)" : ""; ?></p>
                    <p>Причина: <?php echo htmlspecialchars($block_info['reason']); ?></p>
                    <p>Блокировка автоматически истечет через: <strong><?php echo $time_remaining; ?></strong></p>
                    <?php if ($block_count > 1): ?>
                        <p><strong>Внимание:</strong> Из-за повторных блокировок время блокировки было увеличено.</p>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            
            <div class="info">
                <p>Ваш IP-адрес (<?php echo htmlspecialchars($current_ip); ?>) временно заблокирован системой безопасности.</p>
                <p>Для разблокировки пройдите проверку reCAPTCHA ниже.</p>
                <p><strong>Внимание:</strong> После трех неудачных попыток разблокировки ваш IP будет заблокирован на уровне брандмауэра. Также слишком частое обновление этой страницы может привести к блокировке.</p>
            </div>
            
            <?php if (!empty($error_message)): ?>
                <div class="message error"><?php echo htmlspecialchars($error_message); ?></div>
            <?php endif; ?>
            
            <form method="post" action="" id="captcha-form">
                <input type="hidden" id="recaptcha-token" name="g-recaptcha-response">
                <input type="hidden" name="return_url" value="<?php echo htmlspecialchars($return_url); ?>">
                <div class="form-group">
                    <p>Нажмите кнопку ниже для проверки и разблокировки:</p>
                </div>
                <button type="button" id="verify-button" class="btn">Разблокировать</button>
            </form>
            
            <div class="footer">
                <p>Если у вас возникли проблемы с разблокировкой, пожалуйста, свяжитесь с администратором сайта.<br>
				MurKir Security, 2025</p>
            </div>
        <?php endif; ?>
    </div>
    
    <script>
    document.getElementById('verify-button')?.addEventListener('click', function() {
        grecaptcha.ready(function() {
            grecaptcha.execute('<?php echo RECAPTCHA_SITE_KEY; ?>', {action: 'unlock'})
            .then(function(token) {
                document.getElementById('recaptcha-token').value = token;
                document.getElementById('captcha-form').submit();
            });
        });
    });
    </script>
	
<script>
// После успешной разблокировки
<?php if (!empty($success_message)): ?>
// Автоматический редирект после успешной разблокировки
document.addEventListener('DOMContentLoaded', function() {
    var returnLink = document.querySelector('.info a');
    var returnUrl = returnLink.href;
    var count = 2;
    
    returnLink.textContent = 'Автоматическое перенаправление через ' + count + ' сек...';
    
    var timer = setInterval(function() {
        count--;
        if (count <= 0) {
            clearInterval(timer);
            window.location.href = returnUrl; // Автоматический переход по ссылке
        } else {
            returnLink.textContent = 'Автоматическое перенаправление через ' + count + ' сек...';
        }
    }, 1000);
});
<?php endif; ?>
</script>
</body>
</html>