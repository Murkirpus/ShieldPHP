<?php
require_once 'settings.php';
/**
 * /dos/cleanup.php
 * Скрипт для периодической очистки базы данных, Redis и обновления кеша
 * Рекомендуется запускать через cron раз в час
 * Пример строки в crontab:
 * 0 * * * * php /path/to/your/site/dos/cleanup.php > /dev/null 2>&1
 */

// Отключаем лимит времени выполнения для больших баз данных
set_time_limit(300);

// Устанавливаем путь к директории
$dos_dir = dirname(__FILE__) . '/';

// Подключаем класс мониторинга безопасности
require_once $dos_dir . 'security_monitor.php';

// Класс для выполнения обслуживания системы безопасности
class SecurityCleanup {
    private $db;
    private $redis = null;
    private $useRedis = false;
    private $prefix = '';
    private $dos_dir;
    private $log_file;
    private $log_files = array();
    private $max_log_size;
    private $max_log_age;
    private $htaccessPath; // Путь к .htaccess
    private $ipConfFile; // Путь к ip.conf
    private $blockedIpsCacheFile; // Путь к файлу кеша blocked_ips.php
    private $blockedInfoCacheFile; // Путь к файлу кеша blocked_info.php

// Функция для синхронизации правил iptables с активными блокировками
public function syncIptablesWithActiveBlocks() {
    // Пропускаем, если блокировка через брандмауэр отключена
    if (defined('ENABLE_FIREWALL_BLOCKING') && !ENABLE_FIREWALL_BLOCKING) {
        $this->log("Синхронизация с iptables пропущена: блокировка через брандмауэр отключена");
        return 0;
    }
    
    try {
        // 1. Получаем список всех активных блокировок IP
        $active_blocks = $this->getActiveBlockedIPs();
        
        $this->log("Получено активных блокировок: " . count($active_blocks));
        
        // 2. Получаем список всех IP, заблокированных в iptables
        $iptables_blocks_ipv4 = $this->getIptablesBlockedIPs(false);
        $iptables_blocks_ipv6 = $this->getIptablesBlockedIPs(true);
        
        $this->log("Получено IPv4 IP, заблокированных в iptables: " . count($iptables_blocks_ipv4));
        $this->log("Получено IPv6 IP, заблокированных в iptables: " . count($iptables_blocks_ipv6));
        
        // 3. Удаляем IP из iptables, которых нет в активных блокировках
        $removed_count = 0;
        
        // Обрабатываем IPv4
        foreach ($iptables_blocks_ipv4 as $ip) {
            // Удаляем маску /32 для сравнения (стандартная для IPv4)
            $clean_ip = str_replace('/32', '', $ip);
            
            if (!in_array($clean_ip, $active_blocks)) {
                $this->log("IP $ip найден в iptables, но отсутствует в активных блокировках. Удаление...");
                $result = $this->unblockIPFromIptables($clean_ip);
                if ($result) {
                    $removed_count++;
                    $this->log("IP $ip успешно удален из iptables");
                } else {
                    $this->log("Ошибка при удалении IP $ip из iptables");
                }
            }
        }
        
        // Обрабатываем IPv6
        foreach ($iptables_blocks_ipv6 as $ip) {
            // Удаляем маску /128 для сравнения (стандартная для IPv6)
            $clean_ip = str_replace('/128', '', $ip);
            
            if (!in_array($clean_ip, $active_blocks)) {
                $this->log("IPv6 $ip найден в ip6tables, но отсутствует в активных блокировках. Удаление...");
                $result = $this->unblockIPFromIptables($clean_ip);
                if ($result) {
                    $removed_count++;
                    $this->log("IPv6 $ip успешно удален из ip6tables");
                } else {
                    $this->log("Ошибка при удалении IPv6 $ip из ip6tables");
                }
            }
        }
        
        $this->log("Синхронизация iptables с активными блокировками завершена. Удалено правил: $removed_count");
        
        return $removed_count;
    } catch (Exception $e) {
        $this->log("Ошибка при синхронизации iptables с активными блокировками: " . $e->getMessage());
        return 0;
    }
}

// Метод для проверки и создания структуры базы данных, если она отсутствует
private function ensureDatabaseStructure() {
    if (!$this->db) {
        $this->connectDB();
        if (!$this->db) {
            $this->log("Ошибка: не удалось подключиться к базе данных для проверки структуры");
            return false;
        }
    }
    
    try {
        // Проверяем существование таблиц
        $tables = array('blocked_ips', 'hard_block_events', 'ip_request_rate', 'suspicious_requests');
        $missingTables = array();
        
        foreach ($tables as $table) {
            // Проверяем существование таблицы
            $stmt = $this->db->query("SHOW TABLES LIKE '$table'");
            if ($stmt->rowCount() == 0) {
                $missingTables[] = $table;
            }
        }
        
        // Если все таблицы существуют, завершаем работу
        if (empty($missingTables)) {
            return true;
        }
        
        $this->log("Обнаружены отсутствующие таблицы: " . implode(", ", $missingTables));
        
        // Создаем отсутствующие таблицы
        if (in_array('blocked_ips', $missingTables)) {
            $this->db->exec("
                CREATE TABLE IF NOT EXISTS `blocked_ips` (
                  `ip` varchar(45) COLLATE utf8mb4_unicode_ci NOT NULL,
                  `block_until` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
                  `reason` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
                  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
                  `block_count` int(10) unsigned NOT NULL DEFAULT 1,
                  `first_blocked_at` timestamp NULL DEFAULT current_timestamp(),
                  PRIMARY KEY (`ip`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ");
            $this->log("Создана таблица blocked_ips");
        }
        
        if (in_array('hard_block_events', $missingTables)) {
            $this->db->exec("
                CREATE TABLE IF NOT EXISTS `hard_block_events` (
                  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                  `event_time` timestamp NOT NULL DEFAULT current_timestamp(),
                  `blocked_count` int(10) unsigned NOT NULL,
                  `threshold` int(10) unsigned NOT NULL,
                  `action_method` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
                  `notification_sent` tinyint(1) DEFAULT 0,
                  PRIMARY KEY (`id`),
                  KEY `event_time` (`event_time`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ");
            $this->log("Создана таблица hard_block_events");
        }
        
        if (in_array('ip_request_rate', $missingTables)) {
            $this->db->exec("
                CREATE TABLE IF NOT EXISTS `ip_request_rate` (
                  `ip` varchar(45) COLLATE utf8mb4_unicode_ci NOT NULL,
                  `request_count` int(10) unsigned NOT NULL DEFAULT 1,
                  `first_request_time` timestamp NOT NULL DEFAULT current_timestamp(),
                  `last_request_time` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
                  PRIMARY KEY (`ip`),
                  KEY `last_request_time` (`last_request_time`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ");
            $this->log("Создана таблица ip_request_rate");
        }
        
        if (in_array('suspicious_requests', $missingTables)) {
            $this->db->exec("
                CREATE TABLE IF NOT EXISTS `suspicious_requests` (
                  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                  `ip` varchar(45) COLLATE utf8mb4_unicode_ci NOT NULL,
                  `user_agent` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
                  `request_uri` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
                  `request_time` timestamp NOT NULL DEFAULT current_timestamp(),
                  PRIMARY KEY (`id`),
                  KEY `ip` (`ip`),
                  KEY `request_time` (`request_time`)
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ");
            $this->log("Создана таблица suspicious_requests");
        }
        
        $this->log("Структура базы данных успешно создана");
        return true;
    } catch(PDOException $e) {
        $this->log("Ошибка при создании структуры базы данных: " . $e->getMessage());
        return false;
    }
}

// Метод для экспорта активных блокировок в текстовые файлы
public function exportBlockedIPsToFiles() {
    // Пропускаем, если экспорт отключен в настройках
    if (defined('EXPORT_BLOCKED_IPS_TO_FILES') && !EXPORT_BLOCKED_IPS_TO_FILES) {
        $this->log("Экспорт заблокированных IP в файлы отключен в настройках");
        return false;
    }
    
    try {
        // Получаем список всех активно заблокированных IP
        $active_blocks = $this->getActiveBlockedIPs();
        
        if (empty($active_blocks)) {
            $this->log("Нет активных блокировок для экспорта в файлы");
            return true;
        }
        
        // Разделяем IPv4 и IPv6 адреса
        $ipv4_list = array();
        $ipv6_list = array();
        
        foreach ($active_blocks as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ipv4_list[] = $ip;
            } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $ipv6_list[] = $ip;
            }
        }
        
        // Удаляем дубликаты IP-адресов
        $ipv4_list = array_unique($ipv4_list);
        $ipv6_list = array_unique($ipv6_list);
        
        // Сортируем IP-адреса для лучшей читаемости
        sort($ipv4_list, SORT_STRING);
        sort($ipv6_list, SORT_STRING);
        
        // Определяем пути к файлам
        $ipv4_file = $this->dos_dir . (defined('BLOCKED_IPV4_FILE') ? BLOCKED_IPV4_FILE : 'blocked_ipv4.txt');
        $ipv6_file = $this->dos_dir . (defined('BLOCKED_IPV6_FILE') ? BLOCKED_IPV6_FILE : 'blocked_ipv6.txt');
        
        // Записываем IPv4 адреса в файл
        if (!empty($ipv4_list)) {
            $ipv4_content = implode("\n", $ipv4_list);
            file_put_contents($ipv4_file, $ipv4_content);
            $this->log("Экспортировано " . count($ipv4_list) . " уникальных IPv4 адресов в файл " . basename($ipv4_file));
        } else {
            // Если нет IPv4 адресов, создаем пустой файл
            file_put_contents($ipv4_file, "");
            $this->log("Создан пустой файл IPv4 " . basename($ipv4_file) . " (нет активных блокировок)");
        }
        
        // Записываем IPv6 адреса в файл
        if (!empty($ipv6_list)) {
            $ipv6_content = implode("\n", $ipv6_list);
            file_put_contents($ipv6_file, $ipv6_content);
            $this->log("Экспортировано " . count($ipv6_list) . " уникальных IPv6 адресов в файл " . basename($ipv6_file));
        } else {
            // Если нет IPv6 адресов, создаем пустой файл
            file_put_contents($ipv6_file, "");
            $this->log("Создан пустой файл IPv6 " . basename($ipv6_file) . " (нет активных блокировок)");
        }
        
        return true;
    } catch (Exception $e) {
        $this->log("Ошибка при экспорте заблокированных IP в файлы: " . $e->getMessage());
        return false;
    }
}

// Функция для получения списка всех IP, заблокированных в iptables
private function getIptablesBlockedIPs($isIPv6 = false) {
    $iptables_ips = array();
    
    // Выбираем правильную команду
    $command = $isIPv6 ? 'ip6tables-save' : 'iptables-save';
    
    // Получаем список всех правил
    $output = array();
    exec("sudo $command", $output);
    
    // Извлекаем IP-адреса из правил DROP
    foreach ($output as $line) {
        if (strpos($line, '-A INPUT') === 0 && strpos($line, '-j DROP') !== false) {
            // Правило для блокировки IP
            if (preg_match('/-s\s+([^\s]+)/', $line, $matches)) {
                $ip = trim($matches[1]);
                
                // Проверяем, что это действительно IP-адрес
                if (($isIPv6 && filter_var(str_replace('/128', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) || 
                    (!$isIPv6 && filter_var(str_replace('/32', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))) {
                    $iptables_ips[] = $ip;
                }
            }
        }
    }
    
    // Удаляем дубликаты перед возвращением результата
    return array_unique($iptables_ips);
}

// Функция для получения списка всех активно заблокированных IP
private function getActiveBlockedIPs() {
    $active_ips = array();
    
    // Если используем Redis
    if ($this->useRedis && $this->redis) {
        $now = time();
        $blockedIpsKey = $this->prefix . 'blocked_ips';
        
        // Получаем все IP с временем блокировки больше текущего времени
        $blocked_list = $this->redis->zRangeByScore($blockedIpsKey, $now, '+inf');
        
        if (!empty($blocked_list)) {
            $active_ips = $blocked_list;
        }
    }
    
    // Если Redis недоступен или не содержит данных, используем MariaDB
    if ($this->db) {
        $stmt = $this->db->query("SELECT ip FROM blocked_ips WHERE block_until > NOW()");
        $db_ips = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        // Объединяем IP из базы данных с IP из Redis (если есть)
        if (!empty($db_ips)) {
            $active_ips = array_unique(array_merge($active_ips, $db_ips));
        }
    }
    
    // Выводим в лог для отладки
    $this->log("Активные блокировки IP: " . implode(", ", $active_ips));
    
    return $active_ips;
}
    
    public function __construct() {
        $this->dos_dir = dirname(__FILE__) . '/';
        $this->log_file = $this->dos_dir . 'cleanup.log';
        $this->htaccessPath = dirname($this->dos_dir) . '/.htaccess';
        $this->ipConfFile = $this->dos_dir . 'ip.conf';
        $this->blockedIpsCacheFile = $this->dos_dir . 'blocked_ips.php';
        $this->blockedInfoCacheFile = $this->dos_dir . 'blocked_info.php';
        
        // Инициализация настроек из settings.php с возможностью переопределения
        $this->max_log_size = defined('LOG_MAX_SIZE') ? LOG_MAX_SIZE : 1048576; // 1 MB в байтах
        $this->max_log_age = defined('LOG_MAX_AGE') ? LOG_MAX_AGE : 30; // Максимальный возраст записей лога в днях
        
        // Определяем все лог-файлы для очистки
        $this->log_files = array(
            $this->dos_dir . 'cleanup.log',
            $this->dos_dir . 'blocked_ips.log',
            $this->dos_dir . 'recaptcha_unlock.log',
            $this->dos_dir . 'unlock_attempts.log',
            $this->dos_dir . 'unlock_visits.log',
            $this->dos_dir . 'hard_blocked_ips.log',
            $this->dos_dir . 'redis_errors.log'
        );
        
        // Определяем, использовать ли Redis
        $this->useRedis = defined('USE_REDIS') ? USE_REDIS : false;
        $this->prefix = defined('REDIS_PREFIX') ? REDIS_PREFIX : 'dos:';
        
        // Инициализируем соединение с Redis, если используется
        if ($this->useRedis) {
            $this->connectRedis();
        }
        
        // Подключаемся к БД в любом случае для синхронизации
        $this->connectDB();
        
        $this->log("Начало выполнения задачи очистки. Redis: " . ($this->useRedis && $this->redis ? "активен" : "неактивен"));
    }
    
    // Соединение с Redis
    private function connectRedis() {
        try {
            if (!class_exists('Redis')) {
                $this->log("Redis PHP extension not available. Using MariaDB fallback.");
                $this->useRedis = false;
                return false;
            }
            
            $this->redis = new Redis();
            $host = defined('REDIS_HOST') ? REDIS_HOST : '127.0.0.1';
            $port = defined('REDIS_PORT') ? REDIS_PORT : 6379;
            
            if (!$this->redis->connect($host, $port, 2.0)) { // 2 секунды таймаут
                $this->log("Failed to connect to Redis at $host:$port. Using MariaDB fallback.");
                $this->useRedis = false;
                return false;
            }
            
            // Аутентификация, если настроен пароль
            if (defined('REDIS_PASSWORD') && REDIS_PASSWORD) {
                if (!$this->redis->auth(REDIS_PASSWORD)) {
                    $this->log("Redis authentication failed. Using MariaDB fallback.");
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
            $this->log("Redis connection error: " . $e->getMessage());
            $this->useRedis = false;
            return false;
        }
    }
    
    // Запись в лог
    private function log($message) {
        $log_entry = date('Y-m-d H:i:s') . ' - ' . $message . "\n";
        file_put_contents($this->log_file, $log_entry, FILE_APPEND);
    }
    
    // Обработка всех лог-файлов
    public function cleanupLogFiles() {
        foreach ($this->log_files as $log_file) {
            if (file_exists($log_file)) {
                // Проверяем размер файла
                if (filesize($log_file) > $this->max_log_size) {
                    $this->truncateLogFile($log_file);
                    $this->log("Файл лога " . basename($log_file) . " был усечен из-за превышения размера");
                }
                
                // Удаляем старые записи
                $this->removeOldLogEntries($log_file);
                
                $this->log("Лог-файл " . basename($log_file) . " обработан");
            }
        }
        return true;
    }
    
    // Усечение лог-файла при превышении допустимого размера
    private function truncateLogFile($file_path) {
        $log_content = file_get_contents($file_path);
        $log_lines = explode("\n", $log_content);
        
        // Оставляем только последние 500 строк
        if (count($log_lines) > 500) {
            $log_lines = array_slice($log_lines, -500);
            file_put_contents($file_path, implode("\n", $log_lines));
        }
    }
    
    // Удаление устаревших записей из лог-файла
    private function removeOldLogEntries($file_path) {
        // Проверяем, существует ли файл
        if (!file_exists($file_path)) {
            return false;
        }
        
        // Читаем содержимое файла
        $log_content = file_get_contents($file_path);
        if (empty($log_content)) {
            return false;
        }
        
        $log_lines = explode("\n", $log_content);
        $new_log_lines = array();
        $current_date = new DateTime();
        $removed_count = 0;
        
        foreach ($log_lines as $line) {
            // Пропускаем пустые строки
            if (empty(trim($line))) {
                continue;
            }
            
            // Пытаемся извлечь дату из начала строки (формат: YYYY-MM-DD HH:MM:SS)
            if (preg_match('/^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})/', $line, $matches)) {
                try {
                    $entry_date = new DateTime($matches[1]);
                    $diff = $current_date->diff($entry_date);
                    
                    // Пропускаем записи старше max_log_age дней
                    if ($diff->days >= $this->max_log_age) {
                        $removed_count++;
                        continue;
                    }
                } catch (Exception $e) {
                    // Если не удалось разобрать дату, сохраняем строку
                }
            }
            
            // Сохраняем актуальные записи
            $new_log_lines[] = $line;
        }
        
        // Записываем обновленный лог, если были удалены записи
        if ($removed_count > 0) {
            file_put_contents($file_path, implode("\n", $new_log_lines));
            $this->log("Удалено $removed_count устаревших записей из " . basename($file_path));
        }
        
        return true;
    }
    
    // Подключение к БД
    private function connectDB() {
        try {
            // Добавляем опцию буферизации запросов для решения проблемы с оптимизацией
            $options = array(
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true
            );
            
            $this->db = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS, $options);
            $this->db->exec("SET NAMES utf8mb4");
            $this->log("Успешное подключение к базе данных");
        } catch(PDOException $e) {
            $this->log("Ошибка подключения к БД: " . $e->getMessage());
            die("Ошибка подключения к БД: " . $e->getMessage());
        }
    }
    
    // Очистка Redis от устаревших блокировок
    public function cleanupRedisBlocks() {
        if (!$this->redis) return false;
        
        try {
            $now = time();
            $blockedIpsKey = $this->prefix . 'blocked_ips';
            
            // Получаем IP с истекшим сроком блокировки
            $expired_ips = $this->redis->zRangeByScore($blockedIpsKey, 0, $now);
            $expired_count = count($expired_ips);
            
            if ($expired_count > 0) {
                $this->log("Найдено $expired_count IP с истекшим сроком блокировки в Redis");
                
                // Удаляем IP из отсортированного множества
                $this->redis->zRemRangeByScore($blockedIpsKey, 0, $now);
                
                // Удаляем детальную информацию для каждого истекшего IP
                foreach ($expired_ips as $ip) {
                    $blockKey = $this->prefix . "blocked_ip:$ip";
                    $this->redis->del($blockKey);
                    
                    // Логируем разблокировку
                    $this->redis->lPush($this->prefix . 'unblock_log', json_encode([
                        'ip' => $ip,
                        'time' => $now,
                        'method' => 'auto_cleanup'
                    ]));
                }
                
                // Ограничиваем лог разблокировок
                $this->redis->ltrim($this->prefix . 'unblock_log', 0, 999);
            }
            
            // Очищаем старые записи о частоте запросов IP (старше 10 минут)
            $clearOlderThan = $now - 600; // 10 минут
            $requestRatePattern = $this->prefix . "ip_request_rate:*";
            $requestRateKeys = $this->redis->keys($requestRatePattern);
            
            $oldRequestRateCount = 0;
            foreach ($requestRateKeys as $key) {
                $lastRequestTime = (int)$this->redis->hGet($key, 'last_request_time');
                if ($lastRequestTime < $clearOlderThan) {
                    $this->redis->del($key);
                    $oldRequestRateCount++;
                }
            }
            
            if ($oldRequestRateCount > 0) {
                $this->log("Удалено $oldRequestRateCount устаревших записей частоты запросов IP из Redis");
            }
            
            // Очищаем старые подозрительные запросы (старше 24 часов)
            $clearOlderThan = $now - 86400; // 24 часа
            $requestPattern = $this->prefix . "request:*";
            $requestKeys = $this->redis->keys($requestPattern);
            
            $oldRequestCount = 0;
            foreach ($requestKeys as $key) {
                $requestTime = (int)$this->redis->hGet($key, 'request_time');
                if ($requestTime < $clearOlderThan) {
                    $this->redis->del($key);
                    $oldRequestCount++;
                }
            }
            
            if ($oldRequestCount > 0) {
                $this->log("Удалено $oldRequestCount устаревших записей подозрительных запросов из Redis");
            }
            
            // Очищаем списки подозрительных запросов для IP с удаленными запросами
            if ($oldRequestCount > 0) {
                $suspiciousPattern = $this->prefix . "suspicious_requests:*";
                $suspiciousKeys = $this->redis->keys($suspiciousPattern);
                
                foreach ($suspiciousKeys as $key) {
                    // Проверяем, есть ли в списке запросов ID удаленных запросов
                    // Просто обновляем TTL, чтобы эти записи сами истекли
                    $this->redis->expire($key, 86400);
                }
            }
            
            return true;
        } catch (Exception $e) {
            $this->log("Ошибка при очистке Redis: " . $e->getMessage());
            return false;
        }
    }
    
    // Удаление старых записей из таблиц и очистка файлов блокировок
    public function cleanupOldRecords() {
        try {
            // Очищаем Redis, если он доступен
            if ($this->useRedis && $this->redis) {
                $this->cleanupRedisBlocks();
                
                // Синхронизируем информацию между Redis и MariaDB, если включено
                if (defined('CLEANUP_SYNC_DATABASES') && CLEANUP_SYNC_DATABASES) {
                    $this->syncRedisWithMariaDB();
                }
            }
            
            // Получаем список IP-адресов с истекшим сроком блокировки в MariaDB
            $stmt = $this->db->prepare("SELECT ip FROM blocked_ips WHERE block_until < NOW()");
            $stmt->execute();
            $expired_ips = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            // Если есть IP с истекшим сроком блокировки, удаляем их из всех систем блокировки
            if (!empty($expired_ips)) {
                $this->log("Найдены IP-адреса с истекшим сроком блокировки в MariaDB: " . implode(", ", $expired_ips));
                
                foreach ($expired_ips as $ip) {
                    // Удаляем из .htaccess
                    $this->removeIPFromHtaccess($ip);
                    
                    // Удаляем из ip.conf
                    $this->removeIPFromConf($ip);
                    
                    // Удаляем из iptables/ip6tables
                    $this->unblockIPFromIptables($ip);
                    
                    // Удаляем из API
                    $this->unblockIPViaAPI($ip);
                    
                    // Если используется Redis, удаляем и оттуда
                    if ($this->useRedis && $this->redis) {
                        $blockKey = $this->prefix . "blocked_ip:$ip";
                        $blockedIpsKey = $this->prefix . 'blocked_ips';
                        
                        $this->redis->del($blockKey);
                        $this->redis->zRem($blockedIpsKey, $ip);
                    }
                }
            }
            
            // Старые запросы в БД (старше 24 часов)
            $stmt = $this->db->prepare("DELETE FROM suspicious_requests WHERE request_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            $stmt->execute();
            $deleted_requests = $stmt->rowCount();
            $this->log("Удалено $deleted_requests старых записей из таблицы suspicious_requests");
            
            // Истекшие блокировки - удаляем из базы данных
            $stmt = $this->db->prepare("DELETE FROM blocked_ips WHERE block_until < NOW()");
            $stmt->execute();
            $expired_blocks = $stmt->rowCount();
            $this->log("Удалено $expired_blocks истекших блокировок из таблицы blocked_ips");
            
            // ВАЖНО: Сразу обновляем кеш блокировок, чтобы синхронизировать с базой данных
            $this->updateBlockedIPsCache();
            
            // Старые записи частоты запросов (старше 10 минут)
            $stmt = $this->db->prepare("DELETE FROM ip_request_rate WHERE last_request_time < DATE_SUB(NOW(), INTERVAL 10 MINUTE)");
            $stmt->execute();
            $deleted_rates = $stmt->rowCount();
            $this->log("Удалено $deleted_rates старых записей из таблицы ip_request_rate");
            
            // Также убедимся, что файлы кеша актуальны
            $this->ensureCacheFilesUpdated();
            
            return true;
        } catch(PDOException $e) {
            $this->log("Ошибка при очистке старых записей в MariaDB: " . $e->getMessage());
            return false;
        } catch(Exception $e) {
            $this->log("Общая ошибка при очистке старых записей: " . $e->getMessage());
            return false;
        }
    }
    
    // Синхронизация данных между Redis и MariaDB
    private function syncRedisWithMariaDB() {
        if (!$this->redis || !$this->db) return false;
        
        try {
            $now = time();
            $blockedIpsKey = $this->prefix . 'blocked_ips';
            
            // 1. Синхронизация блокировок из Redis в MariaDB
            // Получаем все активные блокировки из Redis
            $redis_blocks = $this->redis->zRangeByScore($blockedIpsKey, $now, '+inf', array('WITHSCORES' => true));
            
            // Получаем все активные блокировки из MariaDB
            $stmt = $this->db->prepare("SELECT ip, UNIX_TIMESTAMP(block_until) as block_until FROM blocked_ips WHERE block_until > NOW()");
            $stmt->execute();
            $db_blocks = array();
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $db_blocks[$row['ip']] = $row['block_until'];
            }
            
            // Сравниваем и обновляем
            $redis_only_ips = array_diff_key($redis_blocks, $db_blocks);
            $db_only_ips = array_diff_key($db_blocks, $redis_blocks);
            $common_ips = array_intersect_key($redis_blocks, $db_blocks);
            
            // IP в Redis, но не в MariaDB - добавляем в MariaDB
            foreach ($redis_only_ips as $ip => $block_until) {
                // Получаем дополнительную информацию о блокировке из Redis
                $blockKey = $this->prefix . "blocked_ip:$ip";
                $blockInfo = $this->redis->hGetAll($blockKey);
                
                if (empty($blockInfo)) {
                    // Если нет детальной информации, создаем минимально необходимую
                    $block_count = 1;
                    $reason = 'Блокировка из Redis';
                } else {
                    $block_count = isset($blockInfo['block_count']) ? (int)$blockInfo['block_count'] : 1;
                    $reason = isset($blockInfo['reason']) ? $blockInfo['reason'] : 'Блокировка из Redis';
                }
                
                // Добавляем блокировку в MariaDB
                $stmt = $this->db->prepare("
                    INSERT INTO blocked_ips (ip, block_until, reason, created_at, block_count, first_blocked_at) 
                    VALUES (?, FROM_UNIXTIME(?), ?, NOW(), ?, NOW())
                    ON DUPLICATE KEY UPDATE 
                        block_until = FROM_UNIXTIME(?),
                        reason = ?
                ");
                $stmt->execute(array($ip, $block_until, $reason, $block_count, $block_until, $reason));
                
                $this->log("Синхронизация: IP $ip добавлен в MariaDB из Redis");
            }
            
            // IP в MariaDB, но не в Redis - добавляем в Redis
            foreach ($db_only_ips as $ip => $block_until) {
                // Получаем полную информацию о блокировке из MariaDB
                $stmt = $this->db->prepare("
                    SELECT reason, block_count, UNIX_TIMESTAMP(first_blocked_at) as first_blocked_at
                    FROM blocked_ips
                    WHERE ip = ?
                ");
                $stmt->execute(array($ip));
                $blockInfo = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($blockInfo) {
                    // Добавляем блокировку в Redis
                    $blockKey = $this->prefix . "blocked_ip:$ip";
                    
                    $this->redis->hMSet($blockKey, array(
                        'block_until' => $block_until,
                        'reason' => $blockInfo['reason'],
                        'created_at' => $now,
                        'block_count' => $blockInfo['block_count'],
                        'first_blocked_at' => $blockInfo['first_blocked_at']
                    ));
                    
                    // Устанавливаем TTL на блокировку
                    $this->redis->expireAt($blockKey, $block_until);
                    
                    // Добавляем IP в отсортированное множество
                    $this->redis->zAdd($blockedIpsKey, $block_until, $ip);
                    
                    $this->log("Синхронизация: IP $ip добавлен в Redis из MariaDB");
                }
            }
            
            // IP и в Redis, и в MariaDB, но разное время блокировки - синхронизируем
            foreach ($common_ips as $ip => $redis_block_until) {
                $db_block_until = $db_blocks[$ip];
                
                // Если время блокировки различается, обновляем блокировку с наиболее длительным сроком
                if (abs($redis_block_until - $db_block_until) > 10) { // 10 секунд погрешность
                    if ($redis_block_until > $db_block_until) {
                        // Redis блокировка дольше - обновляем в MariaDB
                        $stmt = $this->db->prepare("
                            UPDATE blocked_ips
                            SET block_until = FROM_UNIXTIME(?)
                            WHERE ip = ?
                        ");
                        $stmt->execute(array($redis_block_until, $ip));
                        
                        $this->log("Синхронизация: время блокировки IP $ip в MariaDB обновлено из Redis");
                    } else {
                        // MariaDB блокировка дольше - обновляем в Redis
                        $blockKey = $this->prefix . "blocked_ip:$ip";
                        $this->redis->hSet($blockKey, 'block_until', $db_block_until);
                        $this->redis->expireAt($blockKey, $db_block_until);
                        $this->redis->zAdd($blockedIpsKey, $db_block_until, $ip);
                        
                        $this->log("Синхронизация: время блокировки IP $ip в Redis обновлено из MariaDB");
                    }
                }
            }
            
            // 2. Синхронизация белого списка
            $this->syncWhitelistWithRedis();
            // 3. Синхронизация счетчиков запросов
if (defined('MAX_REQUESTS_PER_MINUTE') || defined('MAX_REQUESTS_PER_IP')) {
    $this->log("Синхронизация счетчиков запросов между Redis и MariaDB");
    
    // Получаем все ключи счетчиков минутных запросов
    $minuteKeysPattern = $this->prefix . "minute_requests:*";
    $minuteKeys = $this->redis->keys($minuteKeysPattern);
    
    // Получаем все ключи общих счетчиков запросов
    $totalKeysPattern = $this->prefix . "total_requests:*";
    $totalKeys = $this->redis->keys($totalKeysPattern);
    
    // Синхронизация минутных счетчиков с БД
    foreach ($minuteKeys as $key) {
        $ip = str_replace($this->prefix . "minute_requests:", "", $key);
        $count = $this->redis->zCard($key);
        
        // Сохраняем в БД
        try {
            $stmt = $this->db->prepare("
                INSERT INTO ip_request_rate (ip, request_count, first_request_time)
                VALUES (?, ?, NOW())
                ON DUPLICATE KEY UPDATE 
                    request_count = VALUES(request_count),
                    last_request_time = NOW()
            ");
            $stmt->execute(array($ip, $count));
        } catch (PDOException $e) {
            $this->log("Ошибка синхронизации минутных счетчиков: " . $e->getMessage());
        }
    }
    
    // Синхронизация общих счетчиков с БД
    // Для этого потребуется создать отдельную таблицу, если её нет
    $this->db->exec("
        CREATE TABLE IF NOT EXISTS `total_ip_requests` (
            `ip` VARCHAR(45) PRIMARY KEY,
            `request_count` INT UNSIGNED NOT NULL DEFAULT 0,
            `last_update` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX (`last_update`)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    ");
    
    foreach ($totalKeys as $key) {
        $ip = str_replace($this->prefix . "total_requests:", "", $key);
        $count = $this->redis->get($key);
        
        if ($count) {
            // Сохраняем в БД
            try {
                $stmt = $this->db->prepare("
                    INSERT INTO total_ip_requests (ip, request_count)
                    VALUES (?, ?)
                    ON DUPLICATE KEY UPDATE 
                        request_count = VALUES(request_count)
                ");
                $stmt->execute(array($ip, $count));
            } catch (PDOException $e) {
                $this->log("Ошибка синхронизации общих счетчиков: " . $e->getMessage());
            }
        }
    }
    
    // Синхронизация из MariaDB в Redis, если данные отсутствуют в Redis
    // Получаем счетчики из БД для IP, отсутствующих в Redis
    if ($this->db) {
        try {
            // Для минутных счетчиков
            $stmt = $this->db->query("
                SELECT ip, request_count 
                FROM ip_request_rate 
                WHERE last_request_time > DATE_SUB(NOW(), INTERVAL 2 MINUTE)
            ");
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $ip = $row['ip'];
                $redisKey = $this->prefix . "minute_requests:$ip";
                
                // Если ключа нет в Redis, создаем его
                if (!$this->redis->exists($redisKey)) {
                    $now = time();
                    // Создаем запись с метками времени для последней минуты
                    for ($i = 0; $i < min($row['request_count'], 100); $i++) {
                        $timestamp = $now - rand(0, 60);
                        $this->redis->zAdd($redisKey, $timestamp, "$timestamp:" . mt_rand(1000, 9999));
                    }
                    $this->redis->expire($redisKey, 120); // TTL 2 минуты
                    $this->log("Восстановлен минутный счетчик для IP $ip: {$row['request_count']} запросов");
                }
            }
            
            // Для общих счетчиков
            $stmt = $this->db->query("
                SELECT ip, request_count 
                FROM total_ip_requests
                WHERE last_update > DATE_SUB(NOW(), INTERVAL 1 DAY)
            ");
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $ip = $row['ip'];
                $redisKey = $this->prefix . "total_requests:$ip";
                
                // Если ключа нет в Redis, создаем его
                if (!$this->redis->exists($redisKey)) {
                    $this->redis->set($redisKey, $row['request_count']);
                    $this->redis->expire($redisKey, 86400); // TTL 24 часа
                    $this->log("Восстановлен общий счетчик для IP $ip: {$row['request_count']} запросов");
                }
            }
        } catch (PDOException $e) {
            $this->log("Ошибка при синхронизации счетчиков из БД в Redis: " . $e->getMessage());
        }
    }
    
    $this->log("Синхронизация счетчиков запросов завершена");
}
            return true;
        } catch (PDOException $e) {
            $this->log("Ошибка при синхронизации Redis с MariaDB (SQL): " . $e->getMessage());
            return false;
        } catch (Exception $e) {
            $this->log("Ошибка при синхронизации Redis с MariaDB: " . $e->getMessage());
            return false;
        }
    }
    
    // Синхронизация белого списка между Redis и файлом
    private function syncWhitelistWithRedis() {
        if (!$this->redis) return false;
        
        try {
            $whitelistKey = $this->prefix . "whitelist_ips";
            $whitelist_file = $this->dos_dir . 'whitelist_ips.php';
            
            // Если файл белого списка существует, загружаем его
            $file_whitelist = array();
            if (file_exists($whitelist_file)) {
                include $whitelist_file;
                if (isset($whitelist_ips) && is_array($whitelist_ips)) {
                    $file_whitelist = $whitelist_ips;
                }
            }
            
            // Получаем белый список из Redis
            $redis_whitelist = $this->redis->sMembers($whitelistKey);
            
            // Сравниваем и обновляем
            $redis_only_ips = array_diff($redis_whitelist, $file_whitelist);
            $file_only_ips = array_diff($file_whitelist, $redis_whitelist);
            
            // IP в Redis, но не в файле - добавляем в файл
            $updated = false;
            foreach ($redis_only_ips as $ip) {
                $file_whitelist[] = $ip;
                $updated = true;
                $this->log("Синхронизация: IP $ip добавлен в файл белого списка из Redis");
            }
            
            // IP в файле, но не в Redis - добавляем в Redis
            foreach ($file_only_ips as $ip) {
                $this->redis->sAdd($whitelistKey, $ip);
                $this->log("Синхронизация: IP $ip добавлен в Redis белый список из файла");
            }
            
            // Обновляем файл белого списка, если были изменения
            if ($updated) {
                $content = "<?php\n\$whitelist_ips = " . var_export($file_whitelist, true) . ";\n";
                $tmp_file = $whitelist_file . '.tmp';
                
                if (file_put_contents($tmp_file, $content) !== false) {
                    rename($tmp_file, $whitelist_file);
                }
            }
            
            return true;
        } catch (Exception $e) {
            $this->log("Ошибка при синхронизации белого списка: " . $e->getMessage());
            return false;
        }
    }
    
    // Метод для проверки актуальности файлов кеша
    private function ensureCacheFilesUpdated() {
        // Проверяем, существуют ли файлы кеша и актуальны ли они
        if (!file_exists($this->blockedIpsCacheFile) || 
            !file_exists($this->blockedInfoCacheFile) || 
            filemtime($this->blockedIpsCacheFile) < time() - 3600) {
            
            $this->log("Принудительное обновление файлов кеша блокировок");
            $this->updateBlockedIPsCache();
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
            $this->log("Ошибка: API_BLOCK_URL или API_BLOCK_KEY не определены в настройках");
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
        
        $this->log("Выполняем разблокировку IP $ip через API: $requestUrl");
        
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
            $this->log("Ошибка API разблокировки для IP $ip: $error");
            return false;
        }
        
        // Если код ответа не 200 OK
        if ($httpCode !== 200) {
            $this->log("Ошибка API разблокировки для IP $ip: HTTP код $httpCode");
            return false;
        }
        
        // Пытаемся разобрать JSON-ответ
        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->log("Ошибка разбора JSON-ответа от API при разблокировке IP $ip: " . $response);
            return false;
        }
        
        // Проверяем статус разблокировки
        $success = isset($data['status']) && ($data['status'] === 'success' || $data['status'] === 'warning');
        
        // Логируем результат
        if ($success) {
            $this->log("IP $ip успешно разблокирован через API");
            return true;
        } else {
            $message = isset($data['message']) ? $data['message'] : 'Неизвестная ошибка';
            $this->log("Ошибка разблокировки IP $ip через API: $message");
            return false;
        }
    }
    
    // Удаление IP-адресов из .htaccess
    private function removeIPFromHtaccess($ip) {
        if (!file_exists($this->htaccessPath)) {
            $this->log("Файл .htaccess не существует");
            return false;
        }
        
        // Читаем содержимое файла
        $htaccessContent = file_get_contents($this->htaccessPath);
        if ($htaccessContent === false) {
            $this->log("Ошибка чтения файла .htaccess");
            return false;
        }
        
        $lines = explode("\n", $htaccessContent);
        $new_lines = array();
        $removed_count = 0;
        
        // Проходим по каждой строке и удаляем правила блокировки для указанных IP
        foreach ($lines as $line) {
            if (trim($line) === "Deny from $ip") {
                $removed_count++;
                continue;
            }
            $new_lines[] = $line;
        }
        
        // Сохраняем обновленное содержимое .htaccess
        if ($removed_count > 0) {
            $new_content = implode("\n", $new_lines);
            if (file_put_contents($this->htaccessPath, $new_content) !== false) {
                $this->log("Удалено $removed_count правил блокировки из .htaccess для IP: $ip");
                return true;
            } else {
                $this->log("Ошибка при записи в файл .htaccess");
                return false;
            }
        }
        
        return true;
    }
    
    // Проверка, валидный ли IP-адрес
    private function isValidIP($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP);
    }
    
    // Удаление IP-адресов из ip.conf
    private function removeIPFromConf($ip) {
        if (!file_exists($this->ipConfFile)) {
            $this->log("Файл ip.conf не существует");
            return false;
        }
        
        // Читаем содержимое файла
        $lines = file($this->ipConfFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            $this->log("Ошибка чтения файла ip.conf");
            return false;
        }
        
        $blockedIPs = array();
        $removed = false;
        
        // Собираем все IP, которые нужно оставить
        foreach ($lines as $line) {
            // Пропускаем комментарии
            if (strpos($line, '#') === 0) {
                continue;
            }
            
            // Извлекаем IP из строки (первая часть до пробела или до конца строки)
            $parts = preg_split('/\s+/', trim($line));
            $lineIP = $parts[0];
            
            // Проверяем, что IP валидный и не в списке на удаление
            if ($this->isValidIP($lineIP) && $lineIP !== $ip) {
                $blockedIPs[] = $lineIP;
            } else if ($lineIP === $ip) {
                $removed = true;
            }
        }
        
        // Формируем новое содержимое файла
        $fileContent = "# Обновлено " . date('Y-m-d H:i:s') . "\n";
        
        // Добавляем все оставшиеся IP-адреса в формате "IP 1;"
        foreach ($blockedIPs as $blockedIP) {
            $fileContent .= "$blockedIP 1;\n";
        }
        
        // Записываем в файл (полная перезапись)
        if (file_put_contents($this->ipConfFile, $fileContent) !== false) {
            if ($removed) {
                $this->log("Удален IP-адрес $ip из ip.conf");
            }
            
            // Перезагрузка Nginx после изменения файла
            $this->reloadNginx();
            
            return true;
        } else {
            $this->log("Ошибка при записи в файл ip.conf");
            return false;
        }
    }
    
    // Удаление IP из iptables/ip6tables
    private function unblockIPFromIptables($ip) {
        // Пропускаем, если блокировка через брандмауэр отключена
        if (defined('ENABLE_FIREWALL_BLOCKING') && !ENABLE_FIREWALL_BLOCKING) {
            return true;
        }
        
        // Проверяем валидность IP-адреса
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->log("Неверный формат IP-адреса для разблокировки в iptables: " . $ip);
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
            $this->log("Удаление IP $ip из " . ($isIPv6 ? "ip6tables" : "iptables") . " для порта $port: " . 
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
            $this->log("Предупреждение: Не удалось сохранить правила iptables");
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
    
    // Метод для перезагрузки Nginx
    private function reloadNginx() {
        // Пропускаем, если блокировка через Nginx отключена
        if (defined('ENABLE_NGINX_BLOCKING') && !ENABLE_NGINX_BLOCKING) {
            return true;
        }
        
        // Создаем файл-флаг для внешней системы перезагрузки
        $reload_flag_file = $this->dos_dir . 'nginx_reload_needed';
        file_put_contents($reload_flag_file, date('Y-m-d H:i:s'));
        $this->log("Создан файл-флаг для перезагрузки Nginx");
        
        // Попытка использовать exec, если доступно
        if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))))) {
            $output = array();
            $return_var = 0;
            exec('sudo /usr/sbin/nginx -s reload 2>&1', $output, $return_var);
            
            if ($return_var === 0) {
                $this->log("Nginx успешно перезагружен с помощью exec");
            } else {
                $this->log("Ошибка при перезагрузке Nginx: " . implode("\n", $output));
            }
        } else {
            $this->log("Функция exec недоступна, используйте внешний скрипт для перезагрузки Nginx");
        }
    }
    
    // Оптимизация таблиц
    public function optimizeTables() {
        // Пропускаем, если оптимизация таблиц отключена
        if (defined('CLEANUP_OPTIMIZE_TABLES') && !CLEANUP_OPTIMIZE_TABLES) {
            $this->log("Оптимизация таблиц отключена в настройках");
            return true;
        }
        
        try {
            $tables = array('suspicious_requests', 'blocked_ips', 'ip_request_rate', 'hard_block_events');
            
            foreach ($tables as $table) {
                // В MySQL/MariaDB
                $stmt = $this->db->prepare("OPTIMIZE TABLE $table");
                $stmt->execute();
                $stmt->closeCursor(); // Закрываем курсор после каждого запроса
                
                $this->log("Таблица $table оптимизирована");
            }
            
            return true;
        } catch(PDOException $e) {
            $this->log("Ошибка при оптимизации таблиц: " . $e->getMessage());
            return false;
        }
    }
    
    // Оптимизация использования памяти Redis
    public function optimizeRedisMemory() {
        if (!$this->redis) return false;
        
        try {
            // Получаем информацию о памяти Redis
            $info = $this->redis->info('memory');
            
            if (!isset($info['used_memory']) || !isset($info['maxmemory'])) {
                $this->log("Невозможно получить информацию о памяти Redis");
                return false;
            }
            
            $used_memory = $info['used_memory'];
            $max_memory = $info['maxmemory'];
            
            // Если maxmemory не установлен, логируем предупреждение
            if ($max_memory == 0) {
                $this->log("Внимание: maxmemory для Redis не установлен. Рекомендуется установить в конфигурации.");
                return false;
            }
            
            // Вычисляем процент использования памяти
            $memory_percent = ($used_memory / $max_memory) * 100;
            $this->log("Redis использует {$memory_percent}% памяти ({$info['used_memory_human']} из {$info['maxmemory_human']})");
            
            // Лимиты памяти
            $warning_threshold = defined('REDIS_MEMORY_LIMIT_PERCENT') ? REDIS_MEMORY_LIMIT_PERCENT : 80;
            $emergency_threshold = defined('REDIS_EMERGENCY_MEMORY_PERCENT') ? REDIS_EMERGENCY_MEMORY_PERCENT : 95;
            
            // Если использование памяти выше порога, выполняем очистку
            if ($memory_percent > $warning_threshold) {
                $this->log("Запуск очистки Redis из-за высокого использования памяти ({$memory_percent}%)");
                
                // 1. Установка TTL для ключей, у которых его нет
                // Получаем все ключи с нашим префиксом
                $allKeys = $this->redis->keys($this->prefix . '*');
                $keysWithoutTTL = 0;
                
                foreach ($allKeys as $key) {
                    $ttl = $this->redis->ttl($key);
                    
                    // Если TTL не установлен (-1) или бесконечный (-2 в Redis >= 2.8), устанавливаем TTL
                    if ($ttl == -1) {
                        // Устанавливаем TTL в 30 дней
                        $this->redis->expire($key, 30 * 86400);
                        $keysWithoutTTL++;
                    }
                }
                
                $this->log("Установлен TTL для $keysWithoutTTL ключей Redis без TTL");
                
                // 2. Удаление старых логов и объемных данных
                // Лимитируем размер списков логов
                $logKeys = array(
                    $this->prefix . 'unblock_log',
                    $this->prefix . 'block_log',
                    $this->prefix . 'all_suspicious_requests'
                );
                
                foreach ($logKeys as $logKey) {
                    if ($this->redis->exists($logKey)) {
                        $listSize = $this->redis->lLen($logKey);
                        
                        if ($listSize > 1000) {
                            $this->redis->ltrim($logKey, 0, 999);
                            $this->log("Лог Redis $logKey усечен до 1000 записей (было $listSize)");
                        }
                    }
                }
                
                // 3. Если использование памяти критическое (>95%), выполняем более агрессивную очистку
                if ($memory_percent > $emergency_threshold) {
                    $this->log("ВНИМАНИЕ: Критически высокое использование памяти Redis ({$memory_percent}%). Выполняем экстренную очистку.");
                    
                    // Удаляем старые записи о частоте запросов IP
                    $requestRatePattern = $this->prefix . "ip_request_rate:*";
                    $requestRateKeys = $this->redis->keys($requestRatePattern);
                    
                    // Удаляем 50% самых старых записей
                    $keysToDeleteCount = ceil(count($requestRateKeys) * 0.5);
                    
                    if ($keysToDeleteCount > 0) {
                        $keysToDelete = array_slice($requestRateKeys, 0, $keysToDeleteCount);
                        
                        foreach ($keysToDelete as $key) {
                            $this->redis->del($key);
                        }
                        
                        $this->log("Экстренная очистка: удалено $keysToDeleteCount записей о частоте запросов IP из Redis");
                    }
                    
                    // Удаляем старые подозрительные запросы
                    $requestPattern = $this->prefix . "request:*";
                    $requestKeys = $this->redis->keys($requestPattern);
                    
                    // Удаляем 50% ключей
                    $keysToDeleteCount = ceil(count($requestKeys) * 0.5);
                    
                    if ($keysToDeleteCount > 0) {
                        $keysToDelete = array_slice($requestKeys, 0, $keysToDeleteCount);
                        
                        foreach ($keysToDelete as $key) {
                            $this->redis->del($key);
                        }
                        
                        $this->log("Экстренная очистка: удалено $keysToDeleteCount записей подозрительных запросов из Redis");
                    }
                }
            }
            
            return true;
        } catch (Exception $e) {
            $this->log("Ошибка при оптимизации памяти Redis: " . $e->getMessage());
            return false;
        }
    }
    
    // Обновление кеша блокировок
    public function updateBlockedIPsCache() {
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
            
            // Используем атомарную запись, чтобы избежать повреждения файла кеша
            $tmp_file = $cache_file . '.tmp';
            if (file_put_contents($tmp_file, $content) !== false) {
                rename($tmp_file, $cache_file);
            }
            
            $tmp_info_file = $info_file . '.tmp';
            if (file_put_contents($tmp_info_file, $info_content) !== false) {
                rename($tmp_info_file, $info_file);
            }
            
            $active_blocks = count($blocked_ips);
            $this->log("Файлы кеша блокировок обновлены. Активных блокировок: $active_blocks");
            
            return true;
        } catch(PDOException $e) {
            $this->log("Ошибка обновления кеша блокировок (SQL): " . $e->getMessage());
            return false;
        } catch(Exception $e) {
            $this->log("Ошибка обновления кеша блокировок: " . $e->getMessage());
            return false;
        }
    }
    
    // Проверка наличия устаревших кешей блокировок
    private function checkOutdatedCaches() {
        // Проверяем, содержат ли файлы кеша IP, которых нет в базе
        if (file_exists($this->blockedIpsCacheFile)) {
            include $this->blockedIpsCacheFile;
            
            if (isset($blocked_ips) && is_array($blocked_ips)) {
                $current_time = time();
                $found_expired = false;
                
                foreach ($blocked_ips as $ip => $block_until) {
                    // Если уже истек срок блокировки, но IP все еще в кеше
                    if ($block_until <= $current_time) {
                        $this->log("Обнаружен истекший IP в кеше: $ip");
                        $found_expired = true;
                        
                        // Проверяем наличие в базе
                        $stmt = $this->db->prepare("SELECT 1 FROM blocked_ips WHERE ip = ?");
                        $stmt->execute(array($ip));
                        if (!$stmt->fetchColumn()) {
                            // IP нет в базе - удаляем из всех систем
                            $this->removeIPFromHtaccess($ip);
                            $this->removeIPFromConf($ip);
                            $this->unblockIPFromIptables($ip);
                            $this->unblockIPViaAPI($ip);
                            
                            // Если используем Redis, удаляем и оттуда
                            if ($this->useRedis && $this->redis) {
                                $blockKey = $this->prefix . "blocked_ip:$ip";
                                $blockedIpsKey = $this->prefix . 'blocked_ips';
                                
                                $this->redis->del($blockKey);
                                $this->redis->zRem($blockedIpsKey, $ip);
                            }
                        }
                    }
                }
                
                // Если были найдены истекшие IP, принудительно обновляем кеш
                if ($found_expired) {
                    $this->updateBlockedIPsCache();
                }
            }
        }
    }
    
    // Проверка согласованности данных
    public function checkDataConsistency() {
        try {
            // Проверяем, нет ли IP-адресов одновременно в белом списке и в списке блокировок
            $whitelist_file = $this->dos_dir . 'whitelist_ips.php';
            $whitelisted_ips = array();
            
            if (file_exists($whitelist_file)) {
                include $whitelist_file;
                if (isset($whitelist_ips) && is_array($whitelist_ips)) {
                    $whitelisted_ips = $whitelist_ips;
                }
            }
            
            // Если используем Redis, синхронизируем белый список
            if ($this->useRedis && $this->redis) {
                $whitelistKey = $this->prefix . "whitelist_ips";
                
                // Синхронизируем с Redis
                foreach ($whitelisted_ips as $white_ip) {
                    $this->redis->sAdd($whitelistKey, $white_ip);
                }
            }
            
            foreach ($whitelisted_ips as $white_ip) {
                // Проверяем, не содержит ли белый список CIDR-нотацию
                if (strpos($white_ip, '/') !== false) {
                    continue; // CIDR-диапазоны требуют особой обработки
                }
                
                // Проверяем блокировку в MariaDB
                $stmt = $this->db->prepare("SELECT 1 FROM blocked_ips WHERE ip = ? AND block_until > NOW()");
                $stmt->execute(array($white_ip));
                
                if ($stmt->fetchColumn()) {
                    // Удаляем IP из списка блокировок, т.к. он находится в белом списке
                    $this->db->prepare("DELETE FROM blocked_ips WHERE ip = ?")->execute(array($white_ip));
                    $this->log("Обнаружено и устранено несоответствие: IP $white_ip был одновременно в белом списке и в списке блокировок");
                    
                    // Также удаляем его из .htaccess, ip.conf, iptables и API
                    $this->removeIPFromHtaccess($white_ip);
                    $this->removeIPFromConf($white_ip);
                    $this->unblockIPFromIptables($white_ip);
                    $this->unblockIPViaAPI($white_ip);
                    
                    // Если используем Redis, удаляем и оттуда
                    if ($this->useRedis && $this->redis) {
                        $blockKey = $this->prefix . "blocked_ip:$white_ip";
                        $blockedIpsKey = $this->prefix . 'blocked_ips';
                        
                        $this->redis->del($blockKey);
                        $this->redis->zRem($blockedIpsKey, $white_ip);
                    }
                }
                
                // Проверяем блокировку в Redis
                if ($this->useRedis && $this->redis) {
                    $blockKey = $this->prefix . "blocked_ip:$white_ip";
                    
                    if ($this->redis->exists($blockKey)) {
                        // Удаляем IP из Redis
                        $this->redis->del($blockKey);
                        $this->redis->zRem($this->prefix . 'blocked_ips', $white_ip);
                        
                        $this->log("Обнаружено и устранено несоответствие в Redis: IP $white_ip был одновременно в белом списке и в списке блокировок");
                    }
                }
            }
            
            // Проверяем согласованность файлов кеша
            $this->checkOutdatedCaches();
            
            return true;
        } catch(PDOException $e) {
            $this->log("Ошибка при проверке согласованности данных (SQL): " . $e->getMessage());
            return false;
        } catch(Exception $e) {
            $this->log("Ошибка при проверке согласованности данных: " . $e->getMessage());
            return false;
        }
    }
    
    // Удаление неактуальных файлов кеша
    private function cleanupCacheFiles() {
        // Максимальный возраст файлов кеша
        $cache_age = defined('CACHE_FILES_MAX_AGE') ? CACHE_FILES_MAX_AGE : 86400;
        
        // Проверяем, существуют ли устаревшие или ненужные файлы кеша
        $cache_patterns = array(
            $this->dos_dir . 'blocked_ips.php.tmp',
            $this->dos_dir . 'blocked_info.php.tmp',
            $this->dos_dir . '*.cache.php'
        );
        
        foreach ($cache_patterns as $pattern) {
            $files = glob($pattern);
            if ($files) {
                foreach ($files as $file) {
                    if (file_exists($file) && (time() - filemtime($file)) > $cache_age) {
                        unlink($file);
                        $this->log("Удален устаревший файл кеша: " . basename($file));
                    }
                }
            }
        }
    }
    
    // Очистка дублирующихся правил iptables
    public function cleanupDuplicateIptablesRules() {
        // Пропускаем, если блокировка через брандмауэр отключена
        if (defined('ENABLE_FIREWALL_BLOCKING') && !ENABLE_FIREWALL_BLOCKING) {
            $this->log("Очистка дублирующихся правил iptables пропущена: блокировка через брандмауэр отключена");
            return true;
        }
        
        // Пропускаем, если очистка дублей отключена в настройках
        if (defined('CLEANUP_IPTABLES_DUPLICATES') && !CLEANUP_IPTABLES_DUPLICATES) {
            $this->log("Очистка дублирующихся правил iptables отключена в настройках");
            return true;
        }
        
        $this->log("Начало очистки дублирующихся правил iptables");
        
        // Очистка для IPv4
        $this->cleanupDuplicatesForVersion(false);
        
        // Очистка для IPv6
        $this->cleanupDuplicatesForVersion(true);
        
        $this->log("Очистка дублирующихся правил iptables завершена");
        return true;
    }

    // Очистка дублирующихся правил для конкретной версии IP
    private function cleanupDuplicatesForVersion($isIPv6) {
    // Название команды для логов
    $commandType = $isIPv6 ? "ip6tables" : "iptables";
    $this->log("Начало очистки дубликатов $commandType");
    
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
        $this->log("$commandType: Найдены дубликаты для IP $ip на порту $port: " . (count($rules) + 1) . " правил");
        
        foreach ($rules as $rule) {
            $delCommand = $isIPv6 ? 
                "sudo ip6tables -D INPUT -s " . escapeshellarg($rule['ip']) . " -p tcp -m tcp --dport " . $rule['port'] . " -j DROP" : 
                "sudo iptables -D INPUT -s " . escapeshellarg($rule['ip']) . " -p tcp -m tcp --dport " . $rule['port'] . " -j DROP";
            
            $cmdOutput = array();
            $returnVar = 0;
            exec($delCommand, $cmdOutput, $returnVar);
            
            if ($returnVar === 0) {
                $removed_count++;
                $this->log("Успешно удалено дублирующееся правило $commandType для $ip:$port");
            } else {
                $this->log("Ошибка при удалении правила $commandType для $ip:$port: " . implode(", ", $cmdOutput));
            }
            
            // Небольшая пауза между командами
            usleep(100000); // 100ms
        }
    }
    
    // Сохраняем изменения
    if ($removed_count > 0) {
        $this->log("Всего удалено $removed_count дублирующихся правил $commandType");
        $this->saveIptablesRules($isIPv6);
    } else {
        $this->log("Дублирующиеся правила не найдены для $commandType");
    }
    
    return $removed_count;
}

    // Инициализация необходимых таблиц
    private function initializeTables() {
        if (!$this->db) {
            $this->connectDB();
            if (!$this->db) {
                return false;
            }
        }
        
        try {
            // Создаем таблицу для логирования событий жесткой блокировки
            $this->db->exec("
                CREATE TABLE IF NOT EXISTS `hard_block_events` (
                    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `event_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    `blocked_count` INT UNSIGNED NOT NULL,
                    `threshold` INT UNSIGNED NOT NULL,
                    `action_method` VARCHAR(50) NOT NULL,
                    `notification_sent` TINYINT(1) DEFAULT 0,
                    INDEX (`event_time`)
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ");
            
            return true;
        } catch(PDOException $e) {
            $this->log("Ошибка при создании таблиц: " . $e->getMessage());
            return false;
        }
    }

    // Метод для записи информации о срабатывании жесткой блокировки
    private function logHardBlockEvent($blocked_count, $threshold) {
        if (!$this->db) {
            $this->connectDB();
            if (!$this->db) {
                $this->log("Ошибка: не удалось подключиться к базе данных для записи события жесткой блокировки");
                return false;
            }
        }
        
        // Получаем метод блокировки из настроек
        $block_method = defined('AUTO_HARD_BLOCK_ACTION') ? AUTO_HARD_BLOCK_ACTION : 'all';
        
        try {
            // Записываем информацию в таблицу
            $stmt = $this->db->prepare("
                INSERT INTO hard_block_events 
                (blocked_count, threshold, action_method, notification_sent) 
                VALUES (?, ?, ?, ?)
            ");
            
            // Определяем, было ли отправлено уведомление
            $notification_sent = defined('AUTO_HARD_BLOCK_NOTIFY_ADMIN') && AUTO_HARD_BLOCK_NOTIFY_ADMIN ? 1 : 0;
            
            $stmt->execute(array(
                $blocked_count,
                $threshold,
                $block_method,
                $notification_sent
            ));
            
            $this->log("Информация о срабатывании жесткой блокировки успешно записана в базу данных");
            return true;
        } catch(PDOException $e) {
            $this->log("Ошибка при записи информации о жесткой блокировке: " . $e->getMessage());
            return false;
        }
    }

    // Получение информации о Redis
    private function collectRedisInfo() {
        if (!$this->redis) return;
        
        try {
            // Получаем информацию о Redis для логирования
            $info = $this->redis->info();
            $used_memory = isset($info['used_memory_human']) ? $info['used_memory_human'] : 'н/д';
            $this->log("Redis подключен успешно. Версия: " . (isset($info['redis_version']) ? $info['redis_version'] : 'н/д') . ", память: $used_memory");
        } catch(Exception $e) {
            $this->log("Ошибка при получении информации о Redis: " . $e->getMessage());
        }
    }

    // Метод для получения количества заблокированных IP
    private function getBlockedIPsCount() {
        // Если используем Redis
        if ($this->useRedis && $this->redis) {
            try {
                $now = time();
                $blockedIpsKey = $this->prefix . "blocked_ips";
                
                // Подсчитываем IP с временем блокировки больше текущего времени
                return $this->redis->zCount($blockedIpsKey, $now, '+inf');
            } catch (Exception $e) {
                $this->log("Ошибка при подсчете блокировок в Redis: " . $e->getMessage());
            }
        }
        
        // Используем MariaDB
        try {
            if (!$this->db) {
                $this->connectDB();
                if (!$this->db) {
                    return 0;
                }
            }
            
            $stmt = $this->db->query("SELECT COUNT(*) FROM blocked_ips WHERE block_until > NOW()");
            return (int)$stmt->fetchColumn();
        } catch(PDOException $e) {
            $this->log("Ошибка при подсчете блокировок в БД: " . $e->getMessage());
            return 0;
        }
    }

    // Проверка, нужно ли отправлять уведомление (не чаще чем раз в X часов)
    private function shouldSendNotification() {
        $notification_interval = defined('AUTO_HARD_BLOCK_NOTIFY_INTERVAL') ? 
                             AUTO_HARD_BLOCK_NOTIFY_INTERVAL : 6; // По умолчанию 6 часов
        
        $last_notification_file = $this->dos_dir . 'last_hard_block_notification.txt';
        
        // Если файл не существует, нужно отправить уведомление
        if (!file_exists($last_notification_file)) {
            return true;
        }
        
        // Получаем время последнего уведомления
        $last_notification_time = (int)file_get_contents($last_notification_file);
        $current_time = time();
        
        // Если прошло достаточно времени с момента последнего уведомления
        if (($current_time - $last_notification_time) > ($notification_interval * 3600)) {
            return true;
        }
        
        return false;
    }

    // Обновление времени последнего отправленного уведомления
    private function updateLastNotificationTime() {
        $last_notification_file = $this->dos_dir . 'last_hard_block_notification.txt';
        file_put_contents($last_notification_file, time());
    }

    // Метод для отправки уведомления администратору
    // Метод для отправки уведомления администратору
private function sendAdminNotification($total_blocked, $threshold) {
    // Проверяем наличие email администратора
    if (!defined('AUTO_HARD_BLOCK_ADMIN_EMAIL') || empty(AUTO_HARD_BLOCK_ADMIN_EMAIL)) {
        $this->log("ОШИБКА: Не указан email администратора для отправки уведомлений.");
        return false;
    }
    
    // Получаем email администратора
    $admin_email = AUTO_HARD_BLOCK_ADMIN_EMAIL;
    
    // Формируем тему письма (используем простую тему без специальных символов)
    $raw_subject = defined('AUTO_HARD_BLOCK_EMAIL_SUBJECT') ? 
               AUTO_HARD_BLOCK_EMAIL_SUBJECT : 
               'ВНИМАНИЕ: Автоматическая жесткая блокировка';
    
    // Правильно кодируем тему письма в формате MIME для поддержки UTF-8
    $subject = '=?UTF-8?B?'.base64_encode($raw_subject).'?=';
    
    // Получаем имя сайта для отображения в письме
    $site_name = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'вашем сайте';
    
    // Формируем текст письма
    $message = "Внимание! На сайте $site_name активирована автоматическая жесткая блокировка.\n\n";
    $message .= "Порог активации: $threshold IP-адресов\n";
    $message .= "Текущее количество блокировок: $total_blocked IP-адресов\n";
    $message .= "Метод блокировки: " . (defined('AUTO_HARD_BLOCK_ACTION') ? strtoupper(AUTO_HARD_BLOCK_ACTION) : 'ALL') . "\n\n";
    $message .= "Проверьте панель администратора для получения подробной информации.\n";
    $message .= "URL админки: http://$site_name/dos/admin.php\n\n";
    $message .= "Сообщение сгенерировано автоматически " . date('Y-m-d H:i:s') . "\n";
    
    // Формируем корректные заголовки письма
    $from_email = defined('AUTO_HARD_BLOCK_EMAIL_FROM') ? 
                 AUTO_HARD_BLOCK_EMAIL_FROM : 
                 "security@$site_name";
    
    // Кодируем имя отправителя для корректного отображения кириллицы
    $from_name = '=?UTF-8?B?'.base64_encode('DoS Protection').'?=';
    
    $headers = "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $headers .= "Content-Transfer-Encoding: 8bit\r\n";
    $headers .= "From: $from_name <$from_email>\r\n";
    $headers .= "Reply-To: $from_email\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion() . "\r\n";
    $headers .= "X-Priority: 1\r\n"; // Высокий приоритет
    
    // Отправляем письмо
    $mail_sent = @mail($admin_email, $subject, $message, $headers);
    
    if ($mail_sent) {
        $this->log("Уведомление о жесткой блокировке успешно отправлено на email: $admin_email");
        return true;
    } else {
        $this->log("ОШИБКА: Не удалось отправить уведомление о жесткой блокировке на email: $admin_email");
        return false;
    }
}

    // Проверка необходимости отправки уведомления о жесткой блокировке
    private function checkAndNotifyAboutHardBlock() {
        // Инициализируем таблицы в базе данных
        $this->initializeTables();
        
        // Проверяем, включена ли жесткая блокировка
        if (!defined('AUTO_HARD_BLOCK_ENABLED') || !AUTO_HARD_BLOCK_ENABLED) {
            return false;
        }
        
        // Получаем порог блокировки
        $threshold = defined('AUTO_HARD_BLOCK_THRESHOLD') ? AUTO_HARD_BLOCK_THRESHOLD : 22;
        
        // Получаем текущее количество блокировок
        $total_blocked = $this->getBlockedIPsCount();
        
        // Проверяем, превышен ли порог
        if ($total_blocked <= $threshold) {
            return false;
        }
        
        // Записываем информацию о срабатывании жесткой блокировки в базу данных
        $this->logHardBlockEvent($total_blocked, $threshold);
        
        // Если уведомления отключены, завершаем
        if (!defined('AUTO_HARD_BLOCK_NOTIFY_ADMIN') || !AUTO_HARD_BLOCK_NOTIFY_ADMIN) {
            return true;
        }
        
        // Проверяем, нужно ли отправлять уведомление (не чаще чем раз в X часов)
        if (!$this->shouldSendNotification()) {
            $this->log("Уведомление о жесткой блокировке уже было отправлено недавно. Пропускаем отправку.");
            return false;
        }
        
        $this->log("Превышен порог автоматической жесткой блокировки: $total_blocked IP > $threshold. Отправляем уведомление администратору.");
        
        // Отправляем уведомление
        $result = $this->sendAdminNotification($total_blocked, $threshold);
        
        // Если уведомление успешно отправлено, обновляем время последнего уведомления
        if ($result) {
            $this->updateLastNotificationTime();
        }
        
        return $result;
    }

    // Метод для получения истории событий жесткой блокировки
    public function getHardBlockHistory($limit = 100) {
        if (!$this->db) {
            $this->connectDB();
            if (!$this->db) {
                return array();
            }
        }
        
        try {
            $stmt = $this->db->prepare("
                SELECT * FROM hard_block_events
                ORDER BY event_time DESC
                LIMIT ?
            ");
            $stmt->bindParam(1, $limit, PDO::PARAM_INT);
            $stmt->execute();
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch(PDOException $e) {
            $this->log("Ошибка при получении истории жесткой блокировки: " . $e->getMessage());
            return array();
        }
    }
    
    // Запуск всех задач обслуживания
public function runAll() {
    // Проверка и создание структуры базы данных если необходимо
    $this->ensureDatabaseStructure();
    
    // Очистка устаревших записей
    $this->cleanupOldRecords();
    
    // Проверка согласованности данных
    $this->checkDataConsistency();
    
    // Очистка дублирующихся правил iptables
    $this->cleanupDuplicateIptablesRules();
    
    // Очистка кеш-файлов
    $this->cleanupCacheFiles();
    
    // Оптимизация таблиц БД
    $this->optimizeTables();
    
    // Оптимизация использования памяти Redis
    if ($this->useRedis && $this->redis) {
        $this->optimizeRedisMemory();
    }
    
    // Очистка лог-файлов
    $this->cleanupLogFiles();
    
    // Обновление кеша блокировок
    $this->updateBlockedIPsCache();
    
    // Проверка и запись информации о жесткой блокировке
    // Этот метод также отправит уведомление, если настройки позволяют
    $this->checkAndNotifyAboutHardBlock();
    
    // Синхронизация iptables с активными блокировками
    $this->syncIptablesWithActiveBlocks();
    
    // Экспорт заблокированных IP в текстовые файлы
    $this->exportBlockedIPsToFiles();
    
    $this->log("Все задачи обслуживания выполнены успешно");
}
	}

// Выполнение очистки
try {
    // Создаем экземпляр класса обслуживания
    $cleanup = new SecurityCleanup();
    
    // Запускаем все задачи обслуживания
    $cleanup->runAll();
    
} catch (Exception $e) {
    error_log("Error in cleanup script: " . $e->getMessage());
    echo "Error: " . $e->getMessage();
}

echo "Cleanup completed successfully at " . date('Y-m-d H:i:s');