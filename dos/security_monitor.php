<?php
require_once 'settings.php';
// /dos/security_monitor.php
// Оптимизированный класс для мониторинга с поддержкой Redis для высокой нагрузки
// Совместимость с PHP версий 5.6-8.3

class LightSecurityMonitor {
    private $db = null;          // Соединение с MariaDB
    private $redis = null;       // Соединение с Redis
    private $ip = '';            // IP-адрес клиента
    private $cache = array();    // Используем array() для PHP 5.6
    private $dos_dir = '';       // Путь к директории /dos/
    private $whitelisted_ips = array(); // Белый список IP
    private $htaccessPath = '';  // Путь к .htaccess
    private $ipConfFile = '';    // Путь к ip.conf
    private $useRedis = false;   // Использовать Redis или MariaDB
    private $prefix = '';        // Префикс для ключей Redis

/**
 * Анализ паттернов запросов для обнаружения ботов и автоматизированных атак
 * @return bool Возвращает true, если обнаружены подозрительные паттерны
 */
private function analyzeRequestPatterns() {
    // Пропускаем, если функция отключена
    if (!defined('ENABLE_PATTERN_ANALYSIS') || !ENABLE_PATTERN_ANALYSIS) {
        return false;
    }
    
    // Если IP в белом списке, пропускаем анализ
    if ($this->isIpInWhitelist($this->ip)) {
        return false;
    }
    
    $suspicious_score = 0;
    $reasons = array();
    
    // 1. Анализ последовательности URL
    if ($this->analyzeURLSequence()) {
        $suspicious_score += 30;
        $reasons[] = 'Подозрительная последовательность URL';
    }
    
    // 2. Анализ паттерна заголовков
    if ($this->analyzeHeaderPatterns()) {
        $suspicious_score += 25;
        $reasons[] = 'Подозрительные HTTP заголовки';
    }
    
    // 3. Анализ поведения рефереров
    if ($this->analyzeReferrerPattern()) {
        $suspicious_score += 20;
        $reasons[] = 'Аномальный паттерн рефереров';
    }
    
    // 4. Анализ размера запросов
    if ($this->analyzeRequestSizePattern()) {
        $suspicious_score += 15;
        $reasons[] = 'Подозрительный размер запросов';
    }
    
    // 5. Анализ паттерна методов HTTP
    if ($this->analyzeHTTPMethodPattern()) {
        $suspicious_score += 20;
        $reasons[] = 'Подозрительные HTTP методы';
    }
    
    // 6. Анализ геолокационных аномалий
    if ($this->analyzeGeolocationPattern()) {
        $suspicious_score += 10;
        $reasons[] = 'Геолокационные аномалии';
    }
    
    // Порог подозрительности
    $threshold = defined('PATTERN_ANALYSIS_THRESHOLD') ? PATTERN_ANALYSIS_THRESHOLD : 50;
    
    if ($suspicious_score >= $threshold) {
        $reason_text = implode(', ', $reasons);
        error_log("Паттерн-анализ: IP {$this->ip} набрал {$suspicious_score} баллов подозрительности: {$reason_text}");
        
        // Блокируем IP
        if ($this->useRedis && $this->redis) {
            $this->logRequestRedis();
            $this->blockIPRedis(BLOCK_TIME_SECOND, "Обнаружены подозрительные паттерны ({$suspicious_score} баллов): {$reason_text}");
        } else {
            $this->connectDB();
            $this->initializeTables();
            $this->logRequest();
            $this->blockIP(BLOCK_TIME_SECOND, "Обнаружены подозрительные паттерны ({$suspicious_score} баллов): {$reason_text}");
        }
        
        return true;
    }
    
    return false;
}

/**
 * Анализ последовательности запрашиваемых URL
 */
private function analyzeURLSequence() {
    // Безопасно запускаем сессию
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    
    // Инициализируем массив URL, если не существует
    if (!isset($_SESSION['url_sequence']) || !is_array($_SESSION['url_sequence'])) {
        $_SESSION['url_sequence'] = array();
    }
    
    $current_url = $_SERVER['REQUEST_URI'];
    $_SESSION['url_sequence'][] = array(
        'url' => $current_url,
        'time' => microtime(true)
    );
    
    // Оставляем только последние 20 URL
    if (count($_SESSION['url_sequence']) > 20) {
        $_SESSION['url_sequence'] = array_slice($_SESSION['url_sequence'], -20);
    }
    
    // Нужно минимум 5 URL для анализа
    if (count($_SESSION['url_sequence']) < 5) {
        return false;
    }
    
    // Проверяем на слишком правильную последовательность (признак бота)
    $sequential_count = 0;
    $duplicate_count = 0;
    $too_fast_count = 0;
    
    for ($i = 1; $i < count($_SESSION['url_sequence']); $i++) {
        $prev_url = $_SESSION['url_sequence'][$i-1]['url'];
        $curr_url = $_SESSION['url_sequence'][$i]['url'];
        $time_diff = $_SESSION['url_sequence'][$i]['time'] - $_SESSION['url_sequence'][$i-1]['time'];
        
        // Проверяем на последовательные URL (страницы подряд)
        if (preg_match('/page[\/=](\d+)/', $prev_url, $prev_matches) && 
            preg_match('/page[\/=](\d+)/', $curr_url, $curr_matches)) {
            if ((int)$curr_matches[1] == (int)$prev_matches[1] + 1) {
                $sequential_count++;
            }
        }
        
        // Проверяем на дубликаты URL
        if ($prev_url === $curr_url) {
            $duplicate_count++;
        }
        
        // Проверяем на слишком быстрые запросы
        if ($time_diff < 0.5) { // Менее 0.5 секунды между запросами
            $too_fast_count++;
        }
    }
    
    // Если более 70% запросов последовательные или более 50% дубликатов
    $sequence_ratio = $sequential_count / (count($_SESSION['url_sequence']) - 1);
    $duplicate_ratio = $duplicate_count / (count($_SESSION['url_sequence']) - 1);
    $fast_ratio = $too_fast_count / (count($_SESSION['url_sequence']) - 1);
    
    return ($sequence_ratio > 0.7 || $duplicate_ratio > 0.5 || $fast_ratio > 0.8);
}

/**
 * Анализ паттернов HTTP заголовков
 */
private function analyzeHeaderPatterns() {
    $suspicious_indicators = 0;
    
    // Проверяем User-Agent
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    
    // Слишком короткий или слишком длинный User-Agent
    if (strlen($user_agent) < 10 || strlen($user_agent) > 500) {
        $suspicious_indicators++;
    }
    
    // Отсутствие Accept заголовков (типично для ботов)
    if (!isset($_SERVER['HTTP_ACCEPT']) || empty($_SERVER['HTTP_ACCEPT'])) {
        $suspicious_indicators++;
    }
    
    // Отсутствие Accept-Language
    if (!isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) || empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
        $suspicious_indicators++;
    }
    
    // Отсутствие Accept-Encoding
    if (!isset($_SERVER['HTTP_ACCEPT_ENCODING']) || empty($_SERVER['HTTP_ACCEPT_ENCODING'])) {
        $suspicious_indicators++;
    }
    
    // Проверяем на подозрительные User-Agent паттерны
    $suspicious_ua_patterns = array(
        '/curl/i', '/wget/i', '/python/i', '/perl/i', '/ruby/i', '/java/i',
        '/scanner/i', '/test/i', '/check/i', '/monitor/i', '/probe/i'
    );
    
    foreach ($suspicious_ua_patterns as $pattern) {
        if (preg_match($pattern, $user_agent)) {
            $suspicious_indicators += 2;
            break;
        }
    }
    
    // Проверяем порядок заголовков (боты часто отправляют заголовки в алфавитном порядке)
    $headers = array();
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $headers[] = $key;
        }
    }
    
    $sorted_headers = $headers;
    sort($sorted_headers);
    
    // Если заголовки в алфавитном порядке, это подозрительно
    if ($headers === $sorted_headers && count($headers) > 5) {
        $suspicious_indicators++;
    }
    
    return $suspicious_indicators >= 3;
}

/**
 * Анализ паттерна рефереров
 */
private function analyzeReferrerPattern() {
    // Безопасно запускаем сессию
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    
    $current_referrer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
    
    // Инициализируем массив рефереров
    if (!isset($_SESSION['referrer_history']) || !is_array($_SESSION['referrer_history'])) {
        $_SESSION['referrer_history'] = array();
    }
    
    $_SESSION['referrer_history'][] = $current_referrer;
    
    // Оставляем только последние 10 рефереров
    if (count($_SESSION['referrer_history']) > 10) {
        $_SESSION['referrer_history'] = array_slice($_SESSION['referrer_history'], -10);
    }
    
    // Нужно минимум 5 запросов для анализа
    if (count($_SESSION['referrer_history']) < 5) {
        return false;
    }
    
    // Подсчитываем пустые рефереры
    $empty_referrers = 0;
    $external_referrers = 0;
    $current_domain = $_SERVER['HTTP_HOST'];
    
    foreach ($_SESSION['referrer_history'] as $ref) {
        if (empty($ref)) {
            $empty_referrers++;
        } elseif (strpos($ref, $current_domain) === false) {
            $external_referrers++;
        }
    }
    
    $empty_ratio = $empty_referrers / count($_SESSION['referrer_history']);
    $external_ratio = $external_referrers / count($_SESSION['referrer_history']);
    
    // Подозрительно, если более 80% запросов без рефереров или все внешние
    return ($empty_ratio > 0.8 || $external_ratio > 0.9);
}

/**
 * Анализ размеров запросов
 */
private function analyzeRequestSizePattern() {
    // Безопасно запускаем сессию
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    
    // Получаем размер текущего запроса
    $content_length = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;
    $query_length = strlen($_SERVER['QUERY_STRING']);
    $uri_length = strlen($_SERVER['REQUEST_URI']);
    
    $total_size = $content_length + $query_length + $uri_length;
    
    // Инициализируем массив размеров
    if (!isset($_SESSION['request_sizes']) || !is_array($_SESSION['request_sizes'])) {
        $_SESSION['request_sizes'] = array();
    }
    
    $_SESSION['request_sizes'][] = $total_size;
    
    // Оставляем только последние 10 размеров
    if (count($_SESSION['request_sizes']) > 10) {
        $_SESSION['request_sizes'] = array_slice($_SESSION['request_sizes'], -10);
    }
    
    // Нужно минимум 5 запросов для анализа
    if (count($_SESSION['request_sizes']) < 5) {
        return false;
    }
    
    // Проверяем на одинаковые размеры (признак автоматизации)
    $unique_sizes = array_unique($_SESSION['request_sizes']);
    $size_variety = count($unique_sizes) / count($_SESSION['request_sizes']);
    
    // Проверяем на слишком большие запросы
    $large_requests = 0;
    foreach ($_SESSION['request_sizes'] as $size) {
        if ($size > 8192) { // Больше 8KB
            $large_requests++;
        }
    }
    
    $large_ratio = $large_requests / count($_SESSION['request_sizes']);
    
    // Подозрительно, если мало разнообразия в размерах или много больших запросов
    return ($size_variety < 0.3 || $large_ratio > 0.6);
}

/**
 * Анализ паттерна HTTP методов
 */
private function analyzeHTTPMethodPattern() {
    // Безопасно запускаем сессию
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    
    $current_method = $_SERVER['REQUEST_METHOD'];
    
    // Инициализируем массив методов
    if (!isset($_SESSION['http_methods']) || !is_array($_SESSION['http_methods'])) {
        $_SESSION['http_methods'] = array();
    }
    
    $_SESSION['http_methods'][] = $current_method;
    
    // Оставляем только последние 10 методов
    if (count($_SESSION['http_methods']) > 10) {
        $_SESSION['http_methods'] = array_slice($_SESSION['http_methods'], -10);
    }
    
    // Подсчитываем использование методов
    $method_counts = array_count_values($_SESSION['http_methods']);
    
    // Подозрительные методы для обычного браузинга
    $suspicious_methods = array('PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'CONNECT');
    $suspicious_count = 0;
    
    foreach ($suspicious_methods as $method) {
        if (isset($method_counts[$method])) {
            $suspicious_count += $method_counts[$method];
        }
    }
    
    // Если более 30% запросов используют подозрительные методы
    $suspicious_ratio = $suspicious_count / count($_SESSION['http_methods']);
    
    return $suspicious_ratio > 0.3;
}

/**
 * Анализ геолокационных паттернов (базовая проверка)
 */
private function analyzeGeolocationPattern() {
    // Эта функция требует дополнительных данных о геолокации
    // Для простой реализации проверяем на подозрительные IP диапазоны
    
    // Проверяем на принадлежность к известным VPN/Proxy провайдерам
    $suspicious_ranges = array(
        // Примеры диапазонов, которые часто используются ботами
        '10.0.0.0/8',     // Приватные сети
        '172.16.0.0/12',  // Приватные сети
        '192.168.0.0/16', // Приватные сети
        // Добавьте другие подозрительные диапазоны
    );
    
    foreach ($suspicious_ranges as $range) {
        if ($this->ipInCIDR($this->ip, $range)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Анализ энтропии запросов (хаотичность vs упорядоченность)
 */
private function analyzeRequestEntropy() {
    // Безопасно запускаем сессию
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    
    // Инициализируем массив интервалов
    if (!isset($_SESSION['request_intervals']) || !is_array($_SESSION['request_intervals'])) {
        $_SESSION['request_intervals'] = array();
        $_SESSION['last_request_time'] = microtime(true);
        return false;
    }
    
    $current_time = microtime(true);
    $interval = $current_time - $_SESSION['last_request_time'];
    $_SESSION['request_intervals'][] = $interval;
    $_SESSION['last_request_time'] = $current_time;
    
    // Оставляем только последние 15 интервалов
    if (count($_SESSION['request_intervals']) > 15) {
        $_SESSION['request_intervals'] = array_slice($_SESSION['request_intervals'], -15);
    }
    
    // Нужно минимум 10 интервалов для анализа
    if (count($_SESSION['request_intervals']) < 10) {
        return false;
    }
    
    // Вычисляем энтропию интервалов
    $intervals = $_SESSION['request_intervals'];
    
    // Округляем интервалы до десятых долей секунды для группировки
    $rounded_intervals = array_map(function($interval) {
        return round($interval, 1);
    }, $intervals);
    
    // Подсчитываем частоты
    $frequencies = array_count_values($rounded_intervals);
    $total = count($rounded_intervals);
    
    // Вычисляем энтропию Шеннона
    $entropy = 0;
    foreach ($frequencies as $freq) {
        $probability = $freq / $total;
        $entropy -= $probability * log($probability, 2);
    }
    
    // Низкая энтропия указывает на регулярность (признак бота)
    $max_entropy = log(count($frequencies), 2);
    $normalized_entropy = $max_entropy > 0 ? $entropy / $max_entropy : 0;
    
    // Если энтропия слишком низкая (слишком регулярные запросы)
    return $normalized_entropy < 0.4;
}

/**
 * Проверка, обращается ли запрос к Honeypot URL
 * @return bool Возвращает true, если обнаружен Honeypot URL
 */
private function checkHoneypotUrl() {
    // Список URL, которые обычные пользователи никогда не посещают, но боты часто сканируют
    $honeypot_urls = array(
        '/wp-login.php',
        '/administrator/',
        '/admin.php',
        '/wp-admin/',
        '/xmlrpc.php',
        '/.env',
        '/config.php',
        '/api/login',
        '/robots.txt.php',
        '/sitemap.xml.php',
        '/index.php/login/',
        '/administrator/index.php',
        '/.git/',
        '/server-status',
        '/admin/login',
        '/.well-known/security.txt',
        '/wp-config.php',
        '/laravel/.env',
        '/phpinfo.php',
        '/wp-json/',
        
        // Добавляем новые паттерны сканирования
        '/admin/',
        '/administrator/',
        '/phpmyadmin/',
        '/setup/',
        '/install/',
        '/backup/',
        '/db/',
        '/database/',
        '/config/',
        '/.htaccess',
        '/.sql',
        '/zabbix/',
        '/1.git',
        '/2.git',
        '/3.git',
        '/4.git',
        '/5.git',
        '/admin/1.git',
        '/admin/2.git',
        '/admin/3.git',
        '/bitrix/',
        '/manager/',
        '/joomla/',
        '/cms/',
        '/panel/',
        '/cpanel/',
        '/webshell.php',
        '/shell.php',
        '/cmd.php',
        '/c99.php',
        '/r57.php',
        '/webroot/',
        '/includes/',
        '/old/',
        '/backup.sql',
        '/dump.sql',
        '/website.sql',
        '/myadmin/',
        '/mysql/',
        '/sql/'
    );
    
    // Проверяем текущий URL
    $current_url = $_SERVER['REQUEST_URI'];
    
    foreach ($honeypot_urls as $honeypot) {
        if (strpos($current_url, $honeypot) !== false) {
            // Дополнительная проверка на отсутствие cookies/referer, чтобы убедиться, что это не обычный пользователь
            if (empty($_COOKIE) || empty($_SERVER['HTTP_REFERER'])) {
                error_log("Обнаружен доступ к Honeypot URL: {$current_url} с IP {$this->ip}");
                return true;
            }
        }
    }
    
    // Кроме того, проверяем URL с помощью регулярных выражений для более сложных паттернов
    $regex_patterns = array(
        '#/\.git#i',
        '#\.git$#i',
        '#\d+\.git#i',
        '#/\.env#i',
        '#/\.config#i',
        '#/\.settings#i',
        '#\.bak$#i',
        '#\.old$#i',
        '#\.backup$#i',
        '#/\.svn#i',
        '#/node_modules#i',
        '#/vendor/#i',
        '#/\.webpack#i',
        '#/\.npm#i'
    );
    
    foreach ($regex_patterns as $pattern) {
        if (preg_match($pattern, $current_url)) {
            error_log("Обнаружен доступ к Honeypot URL (regex): {$current_url} с IP {$this->ip}");
            return true;
        }
    }
    
    return false;
}

/**
 * Проверка, использует ли IP слишком много разных User Agent
 * @return bool Возвращает true, если обнаружено слишком много разных UA
 */
private function checkUAConsistency() {
    // Пропускаем, если функция отключена
    if (!defined('ENABLE_UA_CONSISTENCY_CHECK') || !ENABLE_UA_CONSISTENCY_CHECK) {
        return false;
    }
    
    // Получаем текущий User-Agent
    $current_ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown';
    
    // Игнорируем пустые User-Agent
    if (empty($current_ua) || $current_ua === 'Unknown') {
        return false;
    }
    
    // Если используем Redis
    if ($this->useRedis && $this->redis) {
        $key = $this->prefix . "ip_ua_list:{$this->ip}";
        
        // Добавляем текущий UA в множество
        $this->redis->sAdd($key, $current_ua);
        
        // Устанавливаем TTL, если еще не установлен
        $ttl = defined('UA_CHECK_WINDOW') ? UA_CHECK_WINDOW : 3600;
        if ($this->redis->ttl($key) < 0) {
            $this->redis->expire($key, $ttl);
        }
        
        // Получаем количество разных UA
        $ua_count = $this->redis->sCard($key);
        
        // Проверяем на превышение порога
        $max_different = defined('UA_MAX_DIFFERENT') ? UA_MAX_DIFFERENT : 5;
        if ($ua_count > $max_different) {
            // Получаем все UA для логирования
            $ua_list = $this->redis->sMembers($key);
            error_log("Нарушение согласованности UA: IP {$this->ip} использовал $ua_count разных UA: " . implode(", ", $ua_list));
            return true;
        }
    }
    // Запасной вариант с файловым отслеживанием, если Redis недоступен
    else {
        $ua_file = $this->dos_dir . 'ua_tracking/' . str_replace([':', '.'], '_', $this->ip) . '.txt';
        $ua_dir = dirname($ua_file);
        
        // Создаем директорию, если она не существует
        if (!is_dir($ua_dir)) {
            @mkdir($ua_dir, 0755, true);
        }
        
        // Загружаем существующие UA
        $ua_list = array();
        if (file_exists($ua_file)) {
            $content = file_get_contents($ua_file);
            if ($content !== false) {
                $ua_list = explode("\n", trim($content));
            }
        }
        
        // Добавляем текущий UA, если его еще нет в списке
        if (!in_array($current_ua, $ua_list)) {
            $ua_list[] = $current_ua;
            file_put_contents($ua_file, implode("\n", $ua_list));
        }
        
        // Проверяем на превышение порога
        $max_different = defined('UA_MAX_DIFFERENT') ? UA_MAX_DIFFERENT : 5;
        if (count($ua_list) > $max_different) {
            error_log("Нарушение согласованности UA: IP {$this->ip} использовал " . count($ua_list) . " разных UA");
            return true;
        }
    }
    
    return false;
}

/**
 * Проверка, указывает ли таймирование запросов на активность бота
 * @return bool Возвращает true, если обнаружен подозрительный шаблон таймирования
 */
private function checkTimingDispersion() {
    // Пропускаем, если функция отключена
    if (!defined('ENABLE_TIMING_CHECK') || !ENABLE_TIMING_CHECK) {
        return false;
    }
    
    // Безопасно запускаем сессию, если необходимо
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    
    // Текущее время с микросекундами
    $current_time = microtime(true);
    
    // Инициализируем массив таймингов, если не существует
    if (!isset($_SESSION['request_timings']) || !is_array($_SESSION['request_timings'])) {
        $_SESSION['request_timings'] = array();
    }
    
    // Добавляем текущее время
    $_SESSION['request_timings'][] = $current_time;
    
    // Ограничиваем размер массива до последних 20 запросов
    if (count($_SESSION['request_timings']) > 20) {
        $_SESSION['request_timings'] = array_slice($_SESSION['request_timings'], -20);
    }
    
    // Вычисляем интервалы между запросами
    $intervals = array();
    $timings = $_SESSION['request_timings'];
    $count = count($timings);
    
    // Пропускаем, если недостаточно данных
    $min_requests = defined('TIMING_MIN_REQUESTS') ? TIMING_MIN_REQUESTS : 5;
    if ($count < $min_requests) {
        return false;
    }
    
    // Вычисляем интервалы
    for ($i = 1; $i < $count; $i++) {
        $intervals[] = $timings[$i] - $timings[$i-1];
    }
    
    // Вычисляем средний интервал
    $avg = array_sum($intervals) / count($intervals);
    
    // Вычисляем дисперсию
    $variance = 0;
    foreach ($intervals as $interval) {
        $variance += pow($interval - $avg, 2);
    }
    $variance /= count($intervals);
    
    // Минимальная ожидаемая дисперсия для трафика человека
    $min_variance = defined('TIMING_DISPERSION_MIN') ? TIMING_DISPERSION_MIN : 0.2;
    
    // Если очень низкая дисперсия и не слишком большой интервал, вероятно, это бот
    if ($variance < $min_variance && $avg < 5) {
        error_log("Подозрительный шаблон таймирования: IP {$this->ip}, дисперсия {$variance}, средний интервал {$avg}с");
        return true;
    }
    
    return false;
}

/**
 * Проверка и применение автоматической жесткой блокировки при превышении порогового значения
 */
private function checkAndApplyAutoHardBlock() {
    // Пропускаем, если функционал отключен
    if (!defined('AUTO_HARD_BLOCK_ENABLED') || !AUTO_HARD_BLOCK_ENABLED) {
        return false;
    }
    
    // Статическая переменная для предотвращения многократных проверок в рамках одного запроса
    static $already_checked = false;
    if ($already_checked) {
        return false;
    }
    $already_checked = true;
    
    // Проверка выполняется только с некоторой вероятностью для снижения нагрузки
    // (например, 1% запросов будут проверять необходимость жесткой блокировки)
    if (mt_rand(1, 100) > 1) {
        return false;
    }
    
    // Определяем порог количества блокировок
    $threshold = defined('AUTO_HARD_BLOCK_THRESHOLD') ? AUTO_HARD_BLOCK_THRESHOLD : 100;
    
    // Получаем текущее количество заблокированных IP
    $blocked_count = $this->getBlockedIPsCount();
    
    // Если количество блокировок не превышает порог, выходим
    if ($blocked_count <= $threshold) {
        return false;
    }
    
    // Логируем событие
    error_log("Превышен порог количества заблокированных IP ($blocked_count > $threshold). Применяем жесткую блокировку.");
    
    // Получаем только наиболее активные заблокированные IP (не все сразу)
    $blocked_ips = $this->getMostActiveBlockedIPs(50); // Блокируем по 50 IP за раз
    
    // Применяем жесткую блокировку для ограниченного числа IP
    $this->applyHardBlockToAll($blocked_ips);
    
    return true;
}

/**
 * Функция для получения наиболее активных заблокированных IP
 */
private function getMostActiveBlockedIPs($limit = 50) {
    // Реализуйте эту функцию для получения наиболее активных IP
    $active_ips = array();
    
    // Если используем Redis
    if ($this->useRedis && $this->redis) {
        try {
            $now = time();
            $blockedIpsKey = $this->prefix . "blocked_ips";
            
            // Получаем все заблокированные IP
            $blocked_ips = $this->redis->zRangeByScore($blockedIpsKey, $now, '+inf', array('WITHSCORES' => true));
            
            if (!is_array($blocked_ips)) {
                return array();
            }
            
            // Сортируем по count (если доступно) или по времени блокировки
            $ip_data = array();
            foreach ($blocked_ips as $ip => $block_until) {
                $blockKey = $this->prefix . "blocked_ip:$ip";
                $count = 1;
                
                if ($this->redis->exists($blockKey)) {
                    $count = (int)$this->redis->hGet($blockKey, 'block_count');
                }
                
                $ip_data[$ip] = array('count' => $count, 'until' => $block_until);
            }
            
            // Сортируем по count (в порядке убывания)
            uasort($ip_data, function($a, $b) {
                return $b['count'] - $a['count'];
            });
            
            // Берем только $limit IP
            $i = 0;
            foreach ($ip_data as $ip => $data) {
                if ($i >= $limit) break;
                $active_ips[] = $ip;
                $i++;
            }
        } catch (Exception $e) {
            error_log("Ошибка при получении активных заблокированных IP из Redis: " . $e->getMessage());
        }
    } else {
        // Используем файловый кеш как резервный вариант
        $cache_file = $this->dos_dir . 'blocked_ips.php';
        $info_file = $this->dos_dir . 'blocked_info.php';
        
        if (file_exists($cache_file) && file_exists($info_file)) {
            include $cache_file;  // Загружает $blocked_ips
            include $info_file;   // Загружает $blocked_info
            
            if (isset($blocked_ips) && is_array($blocked_ips) && isset($blocked_info) && is_array($blocked_info)) {
                $current_time = time();
                $ip_data = array();
                
                foreach ($blocked_ips as $ip => $block_until) {
                    if ($block_until > $current_time) {
                        $count = 1;
                        if (isset($blocked_info[$ip]) && isset($blocked_info[$ip]['count'])) {
                            $count = $blocked_info[$ip]['count'];
                        }
                        $ip_data[$ip] = array('count' => $count, 'until' => $block_until);
                    }
                }
                
                // Сортируем по count (в порядке убывания)
                uasort($ip_data, function($a, $b) {
                    return $b['count'] - $a['count'];
                });
                
                // Берем только $limit IP
                $i = 0;
                foreach ($ip_data as $ip => $data) {
                    if ($i >= $limit) break;
                    $active_ips[] = $ip;
                    $i++;
                }
            }
        }
    }
    
    return $active_ips;
}

/**
 * Подсчет общего количества заблокированных IP
 */
private function getBlockedIPsCount() {
    // Если используем Redis
    if ($this->useRedis && $this->redis) {
        try {
            // Используем быстрый подсчет через Redis
            $now = time();
            $blockedIpsKey = $this->prefix . "blocked_ips";
            
            // Подсчитываем IP с временем блокировки больше текущего времени
            $count = $this->redis->zCount($blockedIpsKey, $now, '+inf');
            
            return $count;
        } catch (Exception $e) {
            error_log("Ошибка при подсчете блокировок в Redis: " . $e->getMessage());
        }
    }
    
    // Если Redis недоступен или произошла ошибка, используем файловый кеш
    $cache_file = $this->dos_dir . 'blocked_ips.php';
    if (file_exists($cache_file)) {
        include $cache_file;
        if (isset($blocked_ips) && is_array($blocked_ips)) {
            $current_time = time();
            $active_count = 0;
            
            foreach ($blocked_ips as $ip => $block_until) {
                if ($block_until > $current_time) {
                    $active_count++;
                }
            }
            
            return $active_count;
        }
    }
    
    // Если все методы не сработали, возвращаем 0
    return 0;
}

/**
 * Получение всех заблокированных IP
 */
private function getAllBlockedIPs() {
    $blocked_ips = array();
    
    // Если используем Redis
    if ($this->useRedis && $this->redis) {
        try {
            $now = time();
            $blockedIpsKey = $this->prefix . "blocked_ips";
            
            // Получаем все IP с временем блокировки больше текущего времени
            $blocked_list = $this->redis->zRangeByScore($blockedIpsKey, $now, '+inf');
            
            return $blocked_list;
        } catch (Exception $e) {
            error_log("Ошибка при получении заблокированных IP из Redis: " . $e->getMessage());
        }
    }
    
    // Если Redis недоступен или произошла ошибка, используем файловый кеш
    $cache_file = $this->dos_dir . 'blocked_ips.php';
    if (file_exists($cache_file)) {
        include $cache_file;
        if (isset($blocked_ips) && is_array($blocked_ips)) {
            $current_time = time();
            $active_ips = array();
            
            foreach ($blocked_ips as $ip => $block_until) {
                if ($block_until > $current_time) {
                    $active_ips[] = $ip;
                }
            }
            
            return $active_ips;
        }
    }
    
    return array();
}

/**
 * Применение жесткой блокировки для всех указанных IP
 */
private function applyHardBlockToAll($ip_list) {
    if (empty($ip_list)) {
        return false;
    }
    
    // Определяем метод жесткой блокировки
    $block_method = defined('AUTO_HARD_BLOCK_ACTION') ? AUTO_HARD_BLOCK_ACTION : 'all';
    
    $blocked_count = 0;
    
    foreach ($ip_list as $ip) {
        // Проверяем, находится ли IP в белом списке
        if ($this->isIpInWhitelist($ip)) {
            continue; // Пропускаем IP из белого списка
        }
        
        switch ($block_method) {
            case 'iptables':
                // Применяем только блокировку через iptables
                $this->blockIPWithIptables($ip);
                break;
                
            case 'nginx':
                // Применяем только блокировку через Nginx
                $this->logIPToConf($ip);
                break;
                
            case 'all':
            default:
                // Применяем все доступные методы жесткой блокировки
                $this->applyExternalBlockings($ip);
                break;
        }
        
        $blocked_count++;
    }
    
    error_log("Применена жесткая блокировка для $blocked_count IP-адресов методом '$block_method'");
    
    return $blocked_count;
}    
    /**
     * Конструктор класса - выполняет основные инициализации и проверки
     */
    public function __construct() {
    // Правильное вызов метода setupErrorHandling()
    $this->setupErrorHandling();
    
    // Get the client IP address with IPv6 support
    $this->ip = $this->getClientIP();
    
    // Set correct path to the /dos/ directory
    $this->dos_dir = dirname(__FILE__) . '/'; 
    
    // Set paths to .htaccess and ip.conf
    $this->htaccessPath = dirname($this->dos_dir) . '/.htaccess';
    $this->ipConfFile = $this->dos_dir . 'ip.conf';
    
    // Determine whether to use Redis
    $this->useRedis = defined('USE_REDIS') ? USE_REDIS : false;
    $this->prefix = defined('REDIS_PREFIX') ? REDIS_PREFIX : 'dos:';
    
    // Check for security monitor disable mode
    if (defined('DISABLE_SECURITY_MONITOR') && DISABLE_SECURITY_MONITOR) {
        return;
    }
    
    // Enhanced session security
    // Фрагмент кода для блока настройки сессии в конструкторе

// Enhanced session security
if (session_status() == PHP_SESSION_NONE) {
    // Set stronger session security options if PHP version supports it
    if (version_compare(PHP_VERSION, '7.1.0', '>=')) {
        ini_set('session.use_strict_mode', 1);
        ini_set('session.use_cookies', 1);
        ini_set('session.use_only_cookies', 1);
        ini_set('session.cookie_httponly', 1);
    } else {
        // Compatibility with older PHP versions
        ini_set('session.use_cookies', 1);
        ini_set('session.use_only_cookies', 1);
    }
    
    // Protection against very short session IDs
    // Проверяем только очевидно короткие ID (< 10 символов)
    if (isset($_COOKIE['PHPSESSID']) && strlen($_COOKIE['PHPSESSID']) < 10) {
        // If PHPSESSID is suspiciously short, reset it
        setcookie('PHPSESSID', '', time() - 3600, '/');
        error_log("Обнаружен подозрительно короткий ID сессии от IP: {$this->ip}");
    }
    
    session_start();
}

// Проверяем Cookie только если функция включена и IP не в белом списке
if ((!defined('DISABLE_COOKIE_SECURITY_CHECK') || !DISABLE_COOKIE_SECURITY_CHECK) && 
    !$this->isIpInWhitelist($this->ip)) {
    // Проверка безопасности Cookie
    if (method_exists($this, 'checkCookieSecurity') && $this->checkCookieSecurity()) {
        // Блокируем только если блокировка по Cookie включена
        if (!defined('DISABLE_COOKIE_SECURITY_BLOCKING') || !DISABLE_COOKIE_SECURITY_BLOCKING) {
            $this->blockIPForCookieIssue();
        }
    }
}
    
    // Load IP whitelist
    $this->loadWhitelist();
    
    // If IP is whitelisted, skip all checks
    if ($this->isIpInWhitelist($this->ip)) {
        return;
    }
    
    // Initialize Redis connection
    if ($this->useRedis) {
        $redis_success = $this->connectRedis();
        if (!$redis_success) {
            error_log("Redis connection failed for IP {$this->ip}, using database fallback");
            $this->useRedis = false;
            $this->redis = null; // Добавить эту строку для сброса неудачного соединения
        }
    }
    
    // Check if IP is blocked - first through Redis if available
    if ($this->useRedis && $this->redis) {
        try {
            // Check if Redis is actually working
            $ping_result = $this->redis->ping();
            if ($ping_result === false) {
                error_log("Redis ping failed for IP {$this->ip}, using database fallback");
                $this->useRedis = false;
                $this->redis = null;
            } else {
                // Check if IP is blocked
                if ($this->isIPBlockedRedis($this->ip)) {
                    error_log("IP {$this->ip} is blocked in Redis, redirecting to unlock page");
                    $this->redirectToUnlockPage();
                    exit;
                }
            }
        } catch (Exception $e) {
            error_log("Redis error in constructor: " . $e->getMessage());
            $this->useRedis = false;
            $this->redis = null;
        }
    } 
    // If Redis is not used or not available, check through file cache
    else {
        if ($this->isBlockedFileCheck()) {
            // Handling is done inside the method
        }
    }
}
    
    /**
     * Основной метод мониторинга запросов
     */
    /**
 * Основной метод мониторинга запросов
 */
/**
 * Основной метод мониторинга запросов
 */
public function monitorRequest() {
    // Если IP в белом списке, пропускаем всё
    if ($this->isIpInWhitelist($this->ip)) {
        return;
    }
	
	// ДОБАВЛЯЕМ ЗДЕСЬ: Новые проверки
// 1. Проверка количества запросов в минуту
if ($this->checkRequestsPerMinute()) {
    // Если превышен лимит запросов в минуту
    if ($this->useRedis && $this->redis) {
        // Добавляем логирование
        $this->logRequestRedis();
        $this->blockIPRedis(BLOCK_TIME_FIRST, 'Превышен лимит запросов в минуту');
    } else {
        $this->connectDB();
        // Добавляем логирование
        $this->initializeTables();
        $this->logRequest();
        $this->blockIP(BLOCK_TIME_FIRST, 'Превышен лимит запросов в минуту');
    }
    $this->redirectToUnlockPage();
    exit;
}
    
// 2. Проверка общего количества запросов с IP
if ($this->checkTotalRequestsPerIP()) {
    // Если превышен общий лимит запросов
    if ($this->useRedis && $this->redis) {
        // Добавляем логирование
        $this->logRequestRedis();
        $this->blockIPRedis(BLOCK_TIME_FIRST, 'Превышен общий лимит запросов с IP');
    } else {
        $this->connectDB();
        // Добавляем логирование
        $this->initializeTables();
        $this->logRequest();
        $this->blockIP(BLOCK_TIME_FIRST, 'Превышен общий лимит запросов с IP');
    }
    $this->redirectToUnlockPage();
    exit;
}
	
	// Проверка на Honeypot URL
if ($this->checkHoneypotUrl()) {
    // Логируем запрос перед блокировкой
    if ($this->useRedis && $this->redis) {
        $this->logRequestRedis(); // Добавили логирование
        $this->blockIPRedis(BLOCK_TIME_THIRD, 'Обнаружен доступ к Honeypot URL');
    } else {
        $this->connectDB();
        $this->initializeTables(); // Убедимся, что таблицы созданы
        $this->logRequest(); // Добавили логирование
        $this->blockIP(BLOCK_TIME_THIRD, 'Обнаружен доступ к Honeypot URL');
    }
    // Добавляем в список жестких блокировок
    $this->addToHardBlockList($this->ip, 'Honeypot URL');
    $this->applyExternalBlockings($this->ip);
    $this->redirectToUnlockPage();
    exit;
}
	
	// Проверка согласованности UA
if ($this->checkUAConsistency()) {
    if ($this->useRedis && $this->redis) {
        // Добавляем логирование
        $this->logRequestRedis();
        $this->blockIPRedis(BLOCK_TIME_SECOND, 'Использование множества разных User-Agent');
    } else {
        $this->connectDB();
        // Добавляем логирование
        $this->initializeTables();
        $this->logRequest();
        $this->blockIP(BLOCK_TIME_SECOND, 'Использование множества разных User-Agent');
    }
    $this->redirectToUnlockPage();
    exit;
}

// НОВЫЙ КОД: Проверка на подозрительные шаблоны таймирования
if (method_exists($this, 'checkTimingDispersion') && $this->checkTimingDispersion()) {
    if ($this->useRedis && $this->redis) {
        // Добавляем логирование
        $this->logRequestRedis();
        $this->blockIPRedis(BLOCK_TIME_SECOND, 'Подозрительный шаблон таймирования запросов');
    } else {
        $this->connectDB();
        // Добавляем логирование
        $this->initializeTables();
        $this->logRequest();
        $this->blockIP(BLOCK_TIME_SECOND, 'Подозрительный шаблон таймирования запросов');
    }
    $this->redirectToUnlockPage();
    exit;
}	
	
    // Проверка Cookie только если функция включена
    if (!defined('DISABLE_COOKIE_SECURITY_CHECK') || !DISABLE_COOKIE_SECURITY_CHECK) {
        // Проверка безопасности Cookie
        if (method_exists($this, 'checkCookieSecurity') && $this->checkCookieSecurity()) {
            // Если обнаружены проблемы с Cookie и блокировка включена
if (!defined('DISABLE_COOKIE_SECURITY_BLOCKING') || !DISABLE_COOKIE_SECURITY_BLOCKING) {
    // Добавляем логирование перед вызовом blockIPForCookieIssue
    if ($this->useRedis && $this->redis) {
        $this->logRequestRedis();
    } else {
        $this->connectDB();
        $this->initializeTables();
        $this->logRequest();
    }
    $this->blockIPForCookieIssue();
    // После blockIPForCookieIssue() происходит exit
}
        }
    }	
	
    
    // Применяем троттлинг для всех запросов
    if (method_exists($this, 'applyThrottling')) {
        $throttleResult = $this->applyThrottling('default');
        if ($throttleResult['throttled']) {
            // Логируем применение троттлинга
            error_log("Throttling applied for IP {$this->ip}: delay {$throttleResult['delay']}ms, remaining {$throttleResult['remaining']} requests");
            
            // Если наступил жесткий лимит, блокируем IP
if ($throttleResult['remaining'] <= -10 && defined('THROTTLING_BLOCK_ON_HARD_LIMIT') && THROTTLING_BLOCK_ON_HARD_LIMIT) {
    // Блокируем через Redis или базу данных в зависимости от настроек
    if ($this->useRedis && $this->redis) {
        // Добавляем логирование
        $this->logRequestRedis();
        $this->blockIPRedis(BLOCK_TIME_FIRST, 'Превышен жесткий лимит запросов (троттлинг)');
    } else {
        $this->connectDB();
        // Добавляем логирование
        $this->initializeTables();
        $this->logRequest();
        $this->blockIP(BLOCK_TIME_FIRST, 'Превышен жесткий лимит запросов (троттлинг)');
    }
    $this->redirectToUnlockPage();
    exit;
}
        }
    }
    
    // Проверка и применение автоматической жесткой блокировки
    if (method_exists($this, 'checkAndApplyAutoHardBlock')) {
        $this->checkAndApplyAutoHardBlock();
    }
    
// Проверяем, не заблокирован ли уже IP и нужно ли повысить уровень блокировки
// Подключаем модуль повышения уровня блокировки
if (file_exists($this->dos_dir . 'block_escalation.php')) {
    include_once $this->dos_dir . 'block_escalation.php';
    
    // Проверяем текущие блокировки
    $is_blocked = false;
    
    // Проверяем через Redis, если доступен
    if ($this->useRedis && $this->redis) {
        $is_blocked = $this->isIPBlockedRedis($this->ip);
    } 
    // Также проверяем через файловый кеш
    else {
        $cache_file = $this->dos_dir . 'blocked_ips.php';
        if (file_exists($cache_file)) {
            include $cache_file;
            if (isset($blocked_ips) && isset($blocked_ips[$this->ip]) && $blocked_ips[$this->ip] > time()) {
                $is_blocked = true;
            }
        }
    }
    
    // Если IP заблокирован и функция эскалации определена, повышаем уровень и редиректим
    if ($is_blocked && function_exists('escalateBlockLevel')) {
        error_log("IP {$this->ip} уже заблокирован, повышаем уровень блокировки");
        escalateBlockLevel($this->ip);
        $this->redirectToUnlockPage();
        exit;
    }
}
    
    // Если Redis используется и доступен - используем его
    if ($this->useRedis && $this->redis) {
        // Проверяем и обновляем частоту запросов IP через Redis
if ($this->checkIPRateLimitRedis()) {
    // Добавляем логирование
    $this->logRequestRedis();
    $this->blockIPRedis(BLOCK_TIME_FIRST, 'Превышен лимит запросов (защита от подмены сессии)');
    $this->redirectToUnlockPage();
    exit;
}
        
        // Проверка на слишком частые запросы страниц
if ($this->checkPageRateLimitRedis()) {
    // Добавляем логирование
    $this->logRequestRedis();
    $this->blockIPRedis(BLOCK_TIME_FIRST, 'Превышен лимит запросов страниц в секунду');
    $this->redirectToUnlockPage();
    exit;
}
        
// Вызываем метод и сохраняем его результат в переменную
$is_suspicious = $this->isRequestSuspicious();

// Если запрос подозрительный и функция не блокировала бота, логируем
if ($is_suspicious === true) {
    $this->logRequestRedis(); // Логируем только подозрительные запросы
    $this->checkSuspiciousActivityRedis();
}
        
        // Проверка состояния памяти Redis и очистка при необходимости
        if (method_exists($this, 'checkRedisMemory')) {
            $this->checkRedisMemory();
        }
    }
    // Если Redis не используется или недоступен, пробуем MariaDB
    else {
        // Пытаемся подключиться к БД
        $this->connectDB();
        $db_available = $this->db ? true : false;
        
        // Если БД доступна, используем её
        if ($db_available) {
            // Проверка через БД, независимая от сессии
if ($this->checkIPRateLimitInDatabase()) {
    // Добавляем логирование
    $this->logRequest();
    $this->blockIP(3600, 'Превышен лимит запросов (защита от подмены сессии)');
    
    $this->redirectToUnlockPage();
    exit;
}
            
            // Проверка на слишком частые запросы страниц
if ($this->checkPageRateLimit()) {
    // Если лимит превышен, блокируем IP
    // Добавляем логирование
    $this->logRequest();
    $this->blockIP(3600, 'Превышен лимит запросов страниц (>3 в секунду)');
    
    $this->redirectToUnlockPage();
    exit;
}
            
// Вызываем метод и сохраняем его результат в переменную
$is_suspicious = $this->isRequestSuspicious();

// Если запрос подозрительный и функция не блокировала бота, логируем
if ($is_suspicious === true) {
    $this->initializeTables();
    $this->logRequest(); // Логируем только подозрительные запросы
    $this->checkSuspiciousActivity();
}
        }
        // Если и база недоступна, используем файловый режим с прямыми блокировками
        else if (method_exists($this, 'checkIPRateLimitFile') && $this->checkIPRateLimitFile()) {
            error_log("EMERGENCY MODE: Redis and DB unavailable. File tracking detected high request rate: " . $this->ip);
            if (method_exists($this, 'applyDirectBlockings')) {
                $this->applyDirectBlockings($this->ip);
            } else {
                // Запасной вариант - файловая блокировка
                if (method_exists($this, 'blockIPFallback')) {
                    $this->blockIPFallback(3600, 'Превышен лимит запросов (аварийный режим)');
                }
            }
            $this->redirectToUnlockPage();
            exit;
        }
    }
// Анализ паттернов запросов
if (method_exists($this, 'analyzeRequestPatterns') && $this->analyzeRequestPatterns()) {
    $this->redirectToUnlockPage();
    exit;
}

// Анализ энтропии запросов
if (method_exists($this, 'analyzeRequestEntropy') && $this->analyzeRequestEntropy()) {
    $reason = 'Обнаружены регулярные паттерны запросов (низкая энтропия)';
    if ($this->useRedis && $this->redis) {
        $this->logRequestRedis();
        $this->blockIPRedis(BLOCK_TIME_SECOND, $reason);
    } else {
        $this->connectDB();
        $this->initializeTables();
        $this->logRequest();
        $this->blockIP(BLOCK_TIME_SECOND, $reason);
    }
    $this->redirectToUnlockPage();
    exit;
}
}
    
    /**
     * Получение IP-адреса клиента с поддержкой IPv6
     */
    private function getClientIP() {
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
        
        // Добавляем таймаут подключения
        $connectResult = $this->redis->connect($host, $port, 2.0); // 2 seconds timeout
        if ($connectResult === false) {
            error_log("Failed to connect to Redis at $host:$port. Using MariaDB fallback.");
            $this->useRedis = false;
            return false;
        }
        
        // Правильное расположение проверки после создания переменной $connectResult
        if ($connectResult) {
            try {
                $info = $this->redis->info();
                if (isset($info['redis_version'])) {
                    $version = $info['redis_version'];
                    if (version_compare($version, '2.6.0', '<')) {
                        error_log("Redis version $version may not support all required features. Version 2.6.0+ recommended.");
                    }
                }
            } catch (Exception $e) {
                // Игнорируем ошибки при проверке версии
            }
        }
        
        // Аутентификация, если пароль настроен
        if (defined('REDIS_PASSWORD') && REDIS_PASSWORD) {
            $authResult = $this->redis->auth(REDIS_PASSWORD);
            if ($authResult === false) {
                error_log("Redis authentication failed. Using MariaDB fallback.");
                $this->useRedis = false;
                return false;
            }
        }
        
        // Выбор базы данных
        $database = defined('REDIS_DATABASE') ? REDIS_DATABASE : 0;
        $selectResult = $this->redis->select($database);
        if ($selectResult === false) {
            error_log("Failed to select Redis database $database. Using MariaDB fallback.");
            $this->useRedis = false;
            return false;
        }
        
        // Проверяем, работает ли Redis через ping
        $ping = false;
        try {
            $ping = $this->redis->ping();
        } catch (Exception $e) {
            error_log("Redis ping exception: " . $e->getMessage());
            $this->useRedis = false;
            return false;
        }

        // Исправленная проверка на ping (может вернуть строку "PONG")
        if (!$ping) {
            error_log("Redis ping failed");
            $this->useRedis = false;
            return false;
        }
        
        //error_log("Successfully connected to Redis at $host:$port database $database");
        return true;
    } catch (Exception $e) {
        error_log("Redis connection error: " . $e->getMessage());
        $this->useRedis = false;
        return false;
    }
}
    
    /**
     * Проверка IP на блокировку через Redis - O(1) операция
     */
    private function isIPBlockedRedis($ip) {
    if (!$this->redis) return false;
    
    try {
        // Сначала проверяем в sorted set для более быстрого поиска
        $blockUntil = $this->redis->zScore($this->prefix . "blocked_ips", $ip);
        
        // Если нашли в sorted set и блокировка активна
        if ($blockUntil !== false && $blockUntil > time()) {
            // Проверяем с данными hash
            $blockKey = $this->prefix . "blocked_ip:$ip";
            
            // Если hash существует, подтверждаем флаг is_blocked
            if ($this->redis->exists($blockKey)) {
                $isBlocked = $this->redis->hGet($blockKey, 'is_blocked');
                
                // Повторная проверка block_until
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
                $this->redis->expire($blockKey, (int)$blockUntil - time() + 86400); // TTL = block time + 1 day
                return true;
            }
        }
        
        // Проверяем hash напрямую (медленнее, но с более подробной информацией)
        $blockKey = $this->prefix . "blocked_ip:$ip";
        
        if ($this->redis->exists($blockKey)) {
            // Проверяем статус блокировки
            $isBlocked = $this->redis->hGet($blockKey, 'is_blocked');
            $blockUntil = (int)$this->redis->hGet($blockKey, 'block_until');
            
            // Активная блокировка
            if ($isBlocked === '1' && $blockUntil > time()) {
                // Убеждаемся, что IP в sorted set
                $this->redis->zAdd($this->prefix . "blocked_ips", $blockUntil, $ip);
                return true;
            }
            
            // Истекшая блокировка - обновляем статус
            if ($blockUntil <= time()) {
                $this->redis->hSet($blockKey, 'is_blocked', 0);
                $this->redis->zRem($this->prefix . "blocked_ips", $ip);
            }
        }
        
        return false;
    } catch (Exception $e) {
        error_log("Ошибка проверки блокировки IP в Redis: " . $e->getMessage());
        return false;
    }
}
    
    /**
     * Соединение с базой данных MariaDB
     */
    private function connectDB() {
        if ($this->db) return;
        
        try {
            $this->db = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
            // Используем версионно-безопасные настройки атрибутов
            if (defined('PDO::ATTR_ERRMODE')) {
                $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            }
            $this->db->exec("SET NAMES utf8mb4");
        } catch(PDOException $e) {
            error_log("DB Error: " . $e->getMessage());
        }
    }
    
    /**
     * Загрузка белого списка IP-адресов
     */
    private function loadWhitelist() {
        $whitelist_file = $this->dos_dir . 'whitelist_ips.php';
        
        if (file_exists($whitelist_file)) {
            @include $whitelist_file;
            if (isset($whitelist_ips) && is_array($whitelist_ips)) {
                $this->whitelisted_ips = $whitelist_ips;
            }
        }
    }
    
    /**
     * Проверка, находится ли IP в белом списке
     */
    private function isIpInWhitelist($ip) {
        // Нормализуем IPv6-адреса для сравнения
        $normalized_ip = $this->normalizeIP($ip);
        
        foreach ($this->whitelisted_ips as $white_ip) {
            // Проверяем точное совпадение
            if ($normalized_ip === $this->normalizeIP($white_ip)) {
                return true;
            }
            
            // Проверяем диапазоны CIDR
            if (strpos($white_ip, '/') !== false) {
                if ($this->ipInCIDR($normalized_ip, $white_ip)) {
                    return true;
                }
            }
        }
        
        return false;
    }
	

/**
 * Добавление IP-адреса в белый список
 * 
 * @param string $ip IP-адрес для добавления
 * @param string $reason Причина добавления (необязательно)
 * @return bool Результат операции
 */
private function addIPToWhitelist($ip, $reason = 'Автоматическое добавление') {
    // Проверяем валидность IP-адреса
    if (!$this->isValidIP($ip)) {
        error_log("Ошибка: Попытка добавить невалидный IP {$ip} в белый список");
        return false;
    }
    
    // Проверяем, не находится ли IP уже в белом списке
    if ($this->isIpInWhitelist($ip)) {
        return true; // IP уже в белом списке
    }
    
    // Путь к файлу белого списка
    $whitelist_file = $this->dos_dir . 'whitelist_ips.php';
    
    // Загружаем текущий белый список
    $whitelist_ips = array();
    if (file_exists($whitelist_file)) {
        include $whitelist_file;
        if (isset($whitelist_ips) && is_array($whitelist_ips)) {
            // Используем уже загруженный массив
        }
    }
    
    // Добавляем IP в белый список, если его там еще нет
    if (!in_array($ip, $whitelist_ips)) {
        $whitelist_ips[] = $ip;
        
        // Обновляем массив в памяти
        $this->whitelisted_ips = $whitelist_ips;
        
        // Формируем содержимое файла
        $content = "<?php\n// Автоматически обновлено: " . date('Y-m-d H:i:s') . "\n";
        $content .= "// Последнее обновление: {$ip} - {$reason}\n";
        $content .= "\$whitelist_ips = " . var_export($whitelist_ips, true) . ";\n";
        
        // Сохраняем файл
        $tmp_file = $whitelist_file . '.tmp';
        if (file_put_contents($tmp_file, $content) !== false) {
            if (rename($tmp_file, $whitelist_file)) {
                error_log("IP {$ip} успешно добавлен в белый список: {$reason}");
                return true;
            }
        }
        
        // Прямая запись, если временный файл не удалось создать или переименовать
        if (file_put_contents($whitelist_file, $content) !== false) {
            error_log("IP {$ip} успешно добавлен в белый список (прямая запись): {$reason}");
            return true;
        }
        
        error_log("Ошибка: Не удалось добавить IP {$ip} в белый список");
        return false;
    }
    
    return true; // IP уже был в белом списке
}

/**
 * Удаление IP-адреса из белого списка
 * 
 * @param string $ip IP-адрес для удаления
 * @return bool Результат операции
 */
private function removeIPFromWhitelist($ip) {
    // Проверяем валидность IP-адреса
    if (!$this->isValidIP($ip)) {
        error_log("Ошибка: Попытка удалить невалидный IP {$ip} из белого списка");
        return false;
    }
    
    // Проверяем, находится ли IP в белом списке
    if (!$this->isIpInWhitelist($ip)) {
        return true; // IP и так нет в белом списке
    }
    
    // Путь к файлу белого списка
    $whitelist_file = $this->dos_dir . 'whitelist_ips.php';
    
    // Загружаем текущий белый список
    $whitelist_ips = array();
    if (file_exists($whitelist_file)) {
        include $whitelist_file;
        if (isset($whitelist_ips) && is_array($whitelist_ips)) {
            // Используем уже загруженный массив
        }
    }
    
    // Удаляем IP из белого списка
    $new_whitelist = array();
    foreach ($whitelist_ips as $white_ip) {
        if ($this->normalizeIP($white_ip) !== $this->normalizeIP($ip)) {
            $new_whitelist[] = $white_ip;
        }
    }
    
    // Если IP был найден и удален
    if (count($new_whitelist) < count($whitelist_ips)) {
        // Обновляем массив в памяти
        $this->whitelisted_ips = $new_whitelist;
        
        // Формируем содержимое файла
        $content = "<?php\n// Автоматически обновлено: " . date('Y-m-d H:i:s') . "\n";
        $content .= "// Последнее обновление: удален {$ip}\n";
        $content .= "\$whitelist_ips = " . var_export($new_whitelist, true) . ";\n";
        
        // Сохраняем файл
        $tmp_file = $whitelist_file . '.tmp';
        if (file_put_contents($tmp_file, $content) !== false) {
            if (rename($tmp_file, $whitelist_file)) {
                error_log("IP {$ip} успешно удален из белого списка");
                return true;
            }
        }
        
        // Прямая запись, если временный файл не удалось создать или переименовать
        if (file_put_contents($whitelist_file, $content) !== false) {
            error_log("IP {$ip} успешно удален из белого списка (прямая запись)");
            return true;
        }
        
        error_log("Ошибка: Не удалось удалить IP {$ip} из белого списка");
        return false;
    }
    
    return true; // IP не был найден в белом списке
}
    
    /**
     * Нормализация IP-адреса (для IPv6 приводим к полному формату)
     */
    private function normalizeIP($ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // Преобразуем IPv6 в полную форму для точного сравнения
            $packed = inet_pton($ip);
            if ($packed !== false) {
                return inet_ntop($packed);
            }
        }
        return $ip;
    }
    
    /**
     * Проверка, входит ли IP в CIDR-диапазон
     */
    private function ipInCIDR($ip, $cidr) {
    // Using temp variables instead of list() for PHP 5.6 compatibility
    $cidr_parts = explode('/', $cidr);
    $subnet = $cidr_parts[0];
    $mask = isset($cidr_parts[1]) ? $cidr_parts[1] : '';
    
    // Обрабатываем IPv4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && 
        filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ip_decimal = ip2long($ip);
        $subnet_decimal = ip2long($subnet);
        $mask_decimal = ~((1 << (32 - (int)$mask)) - 1);
        return ($ip_decimal & $mask_decimal) === ($subnet_decimal & $mask_decimal);
    }
    
    // Обрабатываем IPv6
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && 
        filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $ip_binary = $this->ipv6ToBinary($ip);
        $subnet_binary = $this->ipv6ToBinary($subnet);
        
        if ($ip_binary !== false && $subnet_binary !== false) {
            // Преобразуем mask в int для корректного сравнения
            $mask_int = (int)$mask;
            // Используем mask_int вместо mask
            $bits_to_compare = min(strlen($ip_binary), $mask_int);
            $ip_network_bits = substr($ip_binary, 0, $bits_to_compare);
            $subnet_network_bits = substr($subnet_binary, 0, $bits_to_compare);
            return $ip_network_bits === $subnet_network_bits;
        }
    }
    
    return false;
}

/**
 * Функция для проверки наличия нескольких PHPSESSIONID
 * @return bool Возвращает true, если найдено несколько PHPSESSIONID
 */
private function hasMultiplePHPSESSIONID() {
    // Проверяем cookies
    if (isset($_COOKIE)) {
        $sessionIds = array();
        $currentSessionName = session_name(); // Обычно "PHPSESSID"
        
        foreach ($_COOKIE as $name => $value) {
            // Проверяем только точное совпадение с именем текущей сессии
            // Некоторые скрипты могут создавать cookie с похожими именами
            if ($name === $currentSessionName) {
                $sessionIds[] = $value;
            }
        }
        
        // Только если есть более одной cookie с точным именем PHPSESSID
        if (count($sessionIds) > 1) {
            error_log("Обнаружено несколько идентификаторов сессии: " . implode(", ", $sessionIds) . " у IP: {$this->ip}");
            return true;
        }
    }
    return false;
}

/**
 * Функция для проверки валидности значения PHPSESSID
 * @param string $sessionID Идентификатор сессии для проверки
 * @return bool Возвращает true, если идентификатор валидный
 */
private function isValidSessionID($sessionID) {
    // Минимальная длина для безопасных сессий
    // Изменено с 32 на 20, т.к. не все конфигурации используют длинные ID
    $minLength = defined('MIN_SESSION_ID_LENGTH') ? MIN_SESSION_ID_LENGTH : 20;
    
    // Только очевидно короткие сессии блокируем
    if (strlen($sessionID) < 10) {
        error_log("Обнаружен слишком короткий ID сессии: {$sessionID} (длина: " . strlen($sessionID) . "), IP: {$this->ip}");
        return false;
    }
    
    // Более мягкая проверка формата ID сессии
    // Разрешаем буквы, цифры и некоторые специальные символы
    if (!preg_match('/^[a-zA-Z0-9_,\-]{10,}$/', $sessionID)) {
        error_log("Обнаружен ID сессии с недопустимыми символами: {$sessionID}, IP: {$this->ip}");
        return false;
    }
    
    // Предупреждение, если ID короче рекомендуемой длины, но не блокируем
    if (strlen($sessionID) < $minLength) {
        error_log("Предупреждение: ID сессии короче рекомендуемой длины ({$minLength}): {$sessionID}, IP: {$this->ip}");
    }
    
    return true;
}

/**
 * Проверяем все куки PHPSESSID на валидность
 * @return bool Возвращает true, если найдены невалидные куки
 */
private function validateSessionCookies() {
    $invalidFound = false;
    $currentSessionName = session_name(); // Обычно "PHPSESSID"
    
    if (isset($_COOKIE)) {
        foreach ($_COOKIE as $name => $value) {
            // Проверяем только точное имя текущей сессии
            if ($name === $currentSessionName && !$this->isValidSessionID($value)) {
                // Удаляем невалидные куки сессий
                setcookie($name, '', time() - 3600, '/');
                $invalidFound = true;
                
                // Логируем попытку манипуляции с Cookie
                error_log("Обнаружена невалидная Cookie сессии: {$name}={$value} от IP: {$this->ip}");
            }
        }
    }
    
    return $invalidFound;
}

/**
 * Комплексная проверка безопасности Cookie
 * @return bool Возвращает true, если обнаружены проблемы с куками
 */
private function checkCookieSecurity() {
    // Проверяем, включена ли функция проверки Cookie
    if (defined('DISABLE_COOKIE_SECURITY_CHECK') && DISABLE_COOKIE_SECURITY_CHECK) {
        return false;
    }
    
    // Проверка наличия нескольких PHPSESSIONID
    $multipleSessions = $this->hasMultiplePHPSESSIONID();
    
    // Проверка валидности Cookie сессии
    $invalidSession = $this->validateSessionCookies();
    
    // Если обнаружены проблемы
    $cookieError = $multipleSessions || $invalidSession;
    
    if ($cookieError) {
        // Удаляем все существующие cookies сессии
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time() - 3600, '/');
        }
        
        // Инициализируем сессию, если она еще не инициализирована
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        
        // Устанавливаем флаг в сессии
        $_SESSION['cookie_problem'] = true;
        
        // Логирование попытки манипуляции с куками
        error_log("Обнаружена проблема с Cookie от IP: {$this->ip} - multiple: " . 
                 ($multipleSessions ? "yes" : "no") . ", invalid: " . ($invalidSession ? "yes" : "no"));
    }
    
    return $cookieError;
}

/**
 * Блокировка IP по причине проблем с Cookie
 */
private function blockIPForCookieIssue() {
    // Проверяем, включена ли функция блокировки по Cookie
    if (defined('DISABLE_COOKIE_SECURITY_BLOCKING') && DISABLE_COOKIE_SECURITY_BLOCKING) {
        // Только логируем, но не блокируем
        error_log("Блокировка по Cookie отключена в настройках, не блокируем IP: {$this->ip}");
        return;
    }
    
    // Определяем время блокировки на основе настроек
    $block_time = defined('BLOCK_TIME_FIRST') ? BLOCK_TIME_FIRST : 3600; // По умолчанию 1 час
    $reason = 'Манипуляция с Cookie сессии';
    
    // Логируем действие 
    error_log("Блокировка IP {$this->ip} на {$block_time} секунд по причине: {$reason}");
    
    // Блокируем через Redis или базу данных в зависимости от настроек
    if ($this->useRedis && $this->redis) {
        $this->blockIPRedis($block_time, $reason);
    } else {
        $this->connectDB();
        $this->blockIP($block_time, $reason);
    }
    
    // Применяем жесткую блокировку если требуется
    if (defined('HARD_BLOCK_ON_FIRST_VIOLATION') && HARD_BLOCK_ON_FIRST_VIOLATION) {
        $this->applyExternalBlockings($this->ip);
    }
    
    // Перенаправляем на страницу разблокировки
    $this->redirectToUnlockPage();
    exit;
}
    
/**
 * Проверка легитимности поисковых ботов с поддержкой PHP 5.6-8.3
 * Поддерживает массив разрешенных ботов из settings.php
 * 
 * @param string $ip IP-адрес для проверки
 * @param string $user_agent User-Agent строка
 * @return bool Результат проверки
 */
private function verifySearchBot($ip, $user_agent) {
    // Проверяем, что массив разрешенных ботов определен глобально
    global $ALLOWED_SEARCH_BOTS;
    
    // Если массив не определен, используем старую логику
    if (!isset($ALLOWED_SEARCH_BOTS) || !is_array($ALLOWED_SEARCH_BOTS)) {
        // Возвращаемся к старой реализации проверки
        $ua = strtolower($user_agent);
        $is_google = strpos($ua, 'googlebot') !== false;
        $is_yandex = strpos($ua, 'yandexbot') !== false;
        $is_bing = strpos($ua, 'bingbot') !== false;
        
        // Если не похож на поисковый бот, сразу возвращаем false
        if (!$is_google && !$is_yandex && !$is_bing) {
            return false;
        }
        
        // Проверяем отключена ли DNS проверка полностью
        if (defined('DISABLE_BOT_DNS_CHECK') && DISABLE_BOT_DNS_CHECK) {
            return true; // Доверяем User-Agent без DNS проверки
        }
        
        // Проверяем кэш, чтобы не делать DNS-запрос каждый раз
        $cache_key = 'verified_bot_' . md5($ip);
        
        // Если используем Redis и он доступен
        if ($this->useRedis && $this->redis) {
            try {
                // Пробуем получить результат из кэша
                $cached = $this->redis->get($cache_key);
                if ($cached !== false) {
                    return (bool)$cached;
                }
            } catch (Exception $e) {
                error_log("Redis error in bot verification: " . $e->getMessage());
            }
        }
        
        // Проверяем, доступна ли функция gethostbyaddr
        if (!function_exists('gethostbyaddr') || 
            in_array('gethostbyaddr', array_map('trim', explode(',', ini_get('disable_functions'))))) {
            return true; // При невозможности проверки считаем ботом по User-Agent
        }
        
        // Сохраняем оригинальный таймаут
        $original_timeout = ini_get('default_socket_timeout');
        
        // Устанавливаем таймаут для DNS-запроса, если это возможно
        if (function_exists('ini_set')) {
            @ini_set('default_socket_timeout', 2); // 2-секундный таймаут
        }
        
        $verified = false;
        $host = $ip; // По умолчанию - тот же IP
        
        // Безопасный DNS-запрос с подавлением ошибок
        try {
            $host = @gethostbyaddr($ip);
            
            // Если DNS-запрос успешен и вернул имя хоста (не IP)
            if ($host && $host !== $ip) {
                if ($is_google && preg_match('/\.googlebot\.com$/i', $host)) {
                    $verified = true;
                } elseif ($is_yandex && preg_match('/\.yandex\.(ru|com|net)$/i', $host)) {
                    $verified = true;
                } elseif ($is_bing && preg_match('/\.msn\.com$/i', $host)) {
                    $verified = true;
                }
            }
        } catch (Exception $e) {
            error_log("DNS lookup error for bot verification: " . $e->getMessage());
        }
        
        // Восстанавливаем оригинальный таймаут
        if (function_exists('ini_set')) {
            @ini_set('default_socket_timeout', $original_timeout);
        }
        
        // Сохраняем результат в кэш
        $cache_ttl = defined('BOT_VERIFICATION_CACHE_TTL') ? BOT_VERIFICATION_CACHE_TTL : 43200;
        if ($this->useRedis && $this->redis) {
            try {
                $this->redis->setex($cache_key, $cache_ttl, (int)$verified);
            } catch (Exception $e) {
                error_log("Redis caching error: " . $e->getMessage());
            }
        }
        
        return $verified;
    }
    
    // НОВЫЙ КОД: проверка по массиву разрешенных ботов
    $ua = strtolower($user_agent);
    $detected_bot = null;
    
    // Проходим по всем определенным ботам
    foreach ($ALLOWED_SEARCH_BOTS as $bot_name => $bot_data) {
        if (!isset($bot_data['user_agents']) || !is_array($bot_data['user_agents'])) {
            continue;
        }
        
        // Проверяем все возможные User-Agent для данного бота
        foreach ($bot_data['user_agents'] as $bot_ua) {
            if (strpos($ua, strtolower($bot_ua)) !== false) {
                $detected_bot = $bot_name;
                break 2; // Выход из обоих циклов
            }
        }
    }
    
    // Если бот не обнаружен по User-Agent, возвращаем false
    if ($detected_bot === null) {
        return false;
    }
    
    // Проверяем отключена ли DNS проверка полностью
    if (defined('DISABLE_BOT_DNS_CHECK') && DISABLE_BOT_DNS_CHECK) {
        // Если нужно автоматическое добавление в белый список
        if (isset($ALLOWED_SEARCH_BOTS[$detected_bot]['auto_whitelist']) && 
            $ALLOWED_SEARCH_BOTS[$detected_bot]['auto_whitelist']) {
            $this->addIPToWhitelist($ip, "Подтвержденный бот: " . $detected_bot);
        }
        
        return true; // Доверяем User-Agent без DNS проверки
    }
    
    // Проверяем кэш, чтобы не делать DNS-запрос каждый раз
    $cache_key = 'verified_bot_' . md5($ip);
    
    // Если используем Redis и он доступен
    if ($this->useRedis && $this->redis) {
        try {
            // Пробуем получить результат из кэша
            $cached = $this->redis->get($cache_key);
            if ($cached !== false) {
                $is_verified = (bool)$cached;
                
                // Если бот верифицирован и нужно автоматическое добавление в белый список
                if ($is_verified && isset($ALLOWED_SEARCH_BOTS[$detected_bot]['auto_whitelist']) && 
                    $ALLOWED_SEARCH_BOTS[$detected_bot]['auto_whitelist']) {
                    $this->addIPToWhitelist($ip, "Подтвержденный бот: " . $detected_bot);
                }
                
                return $is_verified;
            }
        } catch (Exception $e) {
            error_log("Redis error in bot verification: " . $e->getMessage());
        }
    }
    
    // Проверяем, доступна ли функция gethostbyaddr
    if (!function_exists('gethostbyaddr') || 
        in_array('gethostbyaddr', array_map('trim', explode(',', ini_get('disable_functions'))))) {
        return true; // При невозможности проверки считаем ботом по User-Agent
    }
    
    // Сохраняем оригинальный таймаут
    $original_timeout = ini_get('default_socket_timeout');
    
    // Устанавливаем таймаут для DNS-запроса, если это возможно
    if (function_exists('ini_set')) {
        @ini_set('default_socket_timeout', 2); // 2-секундный таймаут
    }
    
    $verified = false;
    $host = $ip; // По умолчанию - тот же IP
    
    // Получаем список доменов для обнаруженного бота
    $bot_domains = isset($ALLOWED_SEARCH_BOTS[$detected_bot]['domains']) ? 
                   $ALLOWED_SEARCH_BOTS[$detected_bot]['domains'] : array();
    
    // Если домены не определены, возвращаем false
    if (empty($bot_domains)) {
        return false;
    }
    
    // Безопасный DNS-запрос с подавлением ошибок
    try {
        $host = @gethostbyaddr($ip);
        
        // Если DNS-запрос успешен и вернул имя хоста (не IP)
        if ($host && $host !== $ip) {
            // Проверяем домен по списку разрешенных для данного бота
            foreach ($bot_domains as $domain) {
                if (preg_match('/' . preg_quote($domain, '/') . '$/i', $host)) {
                    $verified = true;
                    break;
                }
            }
        }
    } catch (Exception $e) {
        error_log("DNS lookup error for bot verification: " . $e->getMessage());
    }
    
    // Восстанавливаем оригинальный таймаут
    if (function_exists('ini_set')) {
        @ini_set('default_socket_timeout', $original_timeout);
    }
    
    // Если бот подтвержден и нужно автоматически добавить его в белый список
    if ($verified && isset($ALLOWED_SEARCH_BOTS[$detected_bot]['auto_whitelist']) && 
        $ALLOWED_SEARCH_BOTS[$detected_bot]['auto_whitelist']) {
        $this->addIPToWhitelist($ip, "Подтвержденный бот: " . $detected_bot);
    }
    
    // Логируем информацию о подтвержденном боте, если включено
    if ($verified && defined('LOG_SEARCH_BOT_ACTIVITY') && LOG_SEARCH_BOT_ACTIVITY) {
        error_log("Подтвержден поисковый бот {$detected_bot}: {$ip} ({$host}) - {$user_agent}");
    }
    
    // Сохраняем результат в кэш
    $cache_ttl = defined('BOT_VERIFICATION_CACHE_TTL') ? BOT_VERIFICATION_CACHE_TTL : 43200;
    if ($this->useRedis && $this->redis) {
        try {
            $this->redis->setex($cache_key, $cache_ttl, (int)$verified);
        } catch (Exception $e) {
            error_log("Redis caching error: " . $e->getMessage());
        }
    }
    
    return $verified;
}
	
    /**
     * Преобразование IPv6 в двоичное представление
     */
    private function ipv6ToBinary($ip) {
        $binary = '';
        $packed = inet_pton($ip);
        if ($packed === false) {
            return false;
        }
        
        for ($i = 0; $i < strlen($packed); $i++) {
            $binary .= str_pad(decbin(ord($packed[$i])), 8, '0', STR_PAD_LEFT);
        }
        
        return $binary;
    }
    
    /**
     * Проверка блокировки через файловый кеш (очень быстрая)
     */
    private function isBlockedFileCheck() {
    // Если отключена проверка файлового кеша, сразу возвращаем false
    if (defined('DISABLE_FILE_FALLBACK') && DISABLE_FILE_FALLBACK) {
        return false;
    }
    
    $cache_file = $this->dos_dir . 'blocked_ips.php';
    
    // Проверяем, не запрашивается ли доступ к админке или странице разблокировки
    if (strpos($_SERVER['REQUEST_URI'], '/dos/admin.php') !== false || 
        strpos($_SERVER['REQUEST_URI'], '/dos/recaptcha_unlock.php') !== false) {
        return false; // Для админки и страницы разблокировки всегда пропускаем
    }
    
    try {
        if (file_exists($cache_file)) {
            @include $cache_file;
            if (isset($blocked_ips) && isset($blocked_ips[$this->ip]) && $blocked_ips[$this->ip] > time()) {
                $this->redirectToUnlockPage();
                exit;
            }
        }
    } catch (Exception $e) {
        error_log("Ошибка при проверке файловой блокировки: " . $e->getMessage());
    }
    
    return false;
}
    
    /**
     * Перенаправление на страницу разблокировки
     */
    private function redirectToUnlockPage() {
    // Получаем текущий URL для возврата после разблокировки
    $scheme = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http";
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
    $current_url = "$scheme://$host$uri";
    
    // Перенаправляем на страницу разблокировки с указанием страницы возврата
    header('Location: /dos/recaptcha_unlock.php?return_to=' . urlencode($current_url));
}
    
    /**
     * Проверка частоты запросов IP через Redis
     */
    private function checkIPRateLimitRedis() {
    if (!$this->redis) return false;
    
    try {
        $key = $this->prefix . "ip_request_rate:{$this->ip}";
        $now = time();
        
        // Если ключ не существует, создаем его с TTL
        if (!$this->redis->exists($key)) {
            $ttl = defined('REDIS_TTL_IP_REQUEST_RATE') ? REDIS_TTL_IP_REQUEST_RATE : 600;
            
            // Используем отдельные операции вместо транзакции для лучшей совместимости
            $hashData = array(
                'request_count' => 1,
                'first_request_time' => $now,
                'last_request_time' => $now
            );
            
            $this->redis->hMSet($key, $hashData);
            $this->redis->expire($key, $ttl); // TTL для 10 минут
            
            return false; // Первый запрос, лимит не превышен
        }
        
        // Убедимся, что у ключа есть TTL
        $keyTtl = $this->redis->ttl($key);
        if ($keyTtl < 0) {
            $ttl = defined('REDIS_TTL_IP_REQUEST_RATE') ? REDIS_TTL_IP_REQUEST_RATE : 600;
            $this->redis->expire($key, $ttl);
        }
        
        // Увеличиваем счетчик запросов и обновляем время последнего запроса
        $this->redis->hIncrBy($key, 'request_count', 1);
        $this->redis->hSet($key, 'last_request_time', $now);
        
        // Проверяем превышение лимита
        $request_count = (int)$this->redis->hGet($key, 'request_count');
        $first_time = (int)$this->redis->hGet($key, 'first_request_time');
        $time_diff = $now - $first_time;
        
        // Если first_time в будущем (clock skew) или отрицательное, сбрасываем его
        if ($first_time > $now || $first_time <= 0) {
            $this->redis->hSet($key, 'first_request_time', $now);
            $time_diff = 0;
        }
        
        $window = defined('RATE_CHECK_WINDOW') ? RATE_CHECK_WINDOW : 30;
        $threshold = defined('RATE_THRESHOLD') ? RATE_THRESHOLD : 20;
        
        // Если лимит запросов превышен во временном окне
        if ($time_diff <= $window && $request_count > $threshold) {
            // Логируем событие
            error_log("Rate limit exceeded for IP {$this->ip}: $request_count requests in $time_diff seconds (threshold: $threshold)");
            return true;
        }
        
        // Если временное окно прошло, сбрасываем счетчик, если частота запросов не подозрительна
        if ($time_diff > $window && ($request_count / $time_diff) < ($threshold / $window)) {
            // Сбрасываем счетчик для нового окна, если скорость нормальная
            $resetData = array(
                'request_count' => 1,
                'first_request_time' => $now
            );
            $this->redis->hMSet($key, $resetData);
        }
        
        return false;
    } catch (Exception $e) {
        error_log("Ошибка проверки лимита IP: " . $e->getMessage());
        return false;
    }
}
    
    /**
     * Проверка слишком частых запросов страниц через Redis
     */
    private function checkPageRateLimitRedis() {
        // Инициализация сессии для отслеживания запросов
        if (session_status() == PHP_SESSION_NONE) {
            if (version_compare(PHP_VERSION, '7.1.0', '>=')) {
                ini_set('session.use_strict_mode', 1);
            }
            session_start();
        }
        
        $current_time = microtime(true);
        
        // Инициализируем массив времени запросов
        if (!isset($_SESSION['page_requests']) || !is_array($_SESSION['page_requests'])) {
            $_SESSION['page_requests'] = array();
        }
        
        // Добавляем текущее время запроса
        $_SESSION['page_requests'][] = $current_time;
        
        // Удаляем запросы старше 1 секунды
        $recent_requests = array();
        foreach ($_SESSION['page_requests'] as $time) {
            if ($current_time - $time <= 1) {
                $recent_requests[] = $time;
            }
        }
        
        // Обновляем массив, оставляя только недавние запросы
        $_SESSION['page_requests'] = $recent_requests;
        
        $rate_limit = defined('MAX_REQUESTS_PER_SECOND') ? MAX_REQUESTS_PER_SECOND : 8;
        
        // Проверяем, не превышен ли лимит запросов в секунду
        if (count($recent_requests) > $rate_limit) {
            // Логируем превышение лимита
            if ($this->redis) {
                $this->redis->incr($this->prefix . "rate_limit_exceeded:{$this->ip}");
                $this->redis->expire($this->prefix . "rate_limit_exceeded:{$this->ip}", 3600);
            }
            
            error_log("Page rate limit exceeded: " . $this->ip . " - " . count($recent_requests) . " requests per second");
            return true; // Лимит превышен
        }
        
        return false; // Лимит не превышен
    }
    
    /**
     * Метод для отслеживания запросов по IP независимо от сессии (через MariaDB)
     */
    private function checkIPRateLimitInDatabase() {
        // Подключаемся к БД, если еще не подключены
        $this->connectDB();
        if (!$this->db) return false;
        
        try {
            // Создаем таблицу для отслеживания запросов по IP, если она еще не существует
            $this->db->exec("
                CREATE TABLE IF NOT EXISTS `ip_request_rate` (
                    `ip` VARCHAR(45) PRIMARY KEY,
                    `request_count` INT UNSIGNED NOT NULL DEFAULT 1,
                    `first_request_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    `last_request_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX (`last_request_time`)
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            ");
            
            // Удаляем старые записи (старше 5 минут)
            $this->db->exec("DELETE FROM `ip_request_rate` WHERE last_request_time < DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
            
            // Проверяем, есть ли уже запись для этого IP
            $stmt = $this->db->prepare("SELECT request_count, first_request_time FROM `ip_request_rate` WHERE ip = ?");
            $stmt->execute(array($this->ip));
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $current_time = time();
            
            if ($result) {
                // Обновляем счетчик запросов
                $request_count = $result['request_count'] + 1;
                $first_time = strtotime($result['first_request_time']);
                $time_diff = $current_time - $first_time;
                
                // Вычисляем частоту запросов в секунду
                $request_rate = ($time_diff > 0) ? $request_count / $time_diff : $request_count;
                
                // Обновляем запись
                $stmt = $this->db->prepare("UPDATE `ip_request_rate` SET request_count = request_count + 1 WHERE ip = ?");
                $stmt->execute(array($this->ip));
                
                // Возвращаем true, если частота запросов превышает лимит
                // Например, более 5 запросов в секунду за последние 30 секунд
                if ($time_diff <= 30 && $request_count > 20 && $request_rate > 0.66) {
                    return true;
                }
            } else {
                // Создаем новую запись для этого IP
                $stmt = $this->db->prepare("INSERT INTO `ip_request_rate` (ip) VALUES (?)");
                $stmt->execute(array($this->ip));
            }
            
            return false;
        } catch(PDOException $e) {
            error_log("Error checking IP rate limit: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Проверка лимита страниц в секунду (через MemCache)
     */
    private function checkPageRateLimit() {
        // Используем memory-based сессии для отслеживания частоты
        if (session_status() == PHP_SESSION_NONE) {
            // Устанавливаем session.use_strict_mode для безопасности
            if (version_compare(PHP_VERSION, '7.1.0', '>=')) {
                ini_set('session.use_strict_mode', 1);
            }
            session_start();
        }
        
        $current_time = microtime(true);
        
        // Инициализируем массив времени запросов, если это первый запрос
        if (!isset($_SESSION['page_requests']) || !is_array($_SESSION['page_requests'])) {
            $_SESSION['page_requests'] = array();
        }
        
        // Добавляем текущее время запроса
        $_SESSION['page_requests'][] = $current_time;
        
        // Удаляем запросы старше 1 секунды
        $recent_requests = array();
        foreach ($_SESSION['page_requests'] as $time) {
            if ($current_time - $time <= 1) {
                $recent_requests[] = $time;
            }
        }
        
        // Обновляем массив, оставляя только недавние запросы
        $_SESSION['page_requests'] = $recent_requests;
        
        // Проверяем, не превышен ли лимит запросов в секунду
        $rate_limit = defined('MAX_REQUESTS_PER_SECOND') ? MAX_REQUESTS_PER_SECOND : 4; // 4 - значение по умолчанию
		if (count($recent_requests) > $rate_limit) {
            error_log("Rate limit exceeded: " . $this->ip . " - " . count($recent_requests) . " requests per second");
            return true; // Лимит превышен
        }
        
        return false; // Лимит не превышен
    }

/**
 * Проверка количества запросов за минуту
 */
private function checkRequestsPerMinute() {
    if (!$this->useRedis || !$this->redis) {
        // Без Redis используем файловый кеш
        return $this->checkRequestsPerMinuteFile();
    }
    
    try {
        $key = $this->prefix . "minute_requests:{$this->ip}";
        $now = time();
        $minuteAgo = $now - 60;
        
        // Добавляем текущий запрос со значением текущего времени
        $this->redis->zAdd($key, $now, $now . ':' . mt_rand(1000, 9999));
        
        // Устанавливаем TTL для ключа, если его еще нет
        if ($this->redis->ttl($key) < 0) {
            $this->redis->expire($key, 120); // 2 минуты TTL
        }
        
        // Удаляем старые записи (старше 1 минуты)
        $this->redis->zRemRangeByScore($key, 0, $minuteAgo);
        
        // Подсчитываем количество запросов за последнюю минуту
        $count = $this->redis->zCard($key);
        
        // Логируем, если превышен порог
        if ($count > MAX_REQUESTS_PER_MINUTE) {
            error_log("IP {$this->ip} превысил лимит запросов в минуту: $count запросов");
            return true; // Лимит превышен
        }
        
        return false;
    } catch (Exception $e) {
        error_log("Ошибка проверки запросов в минуту через Redis: " . $e->getMessage());
        // Фоллбек на файловый метод
        return $this->checkRequestsPerMinuteFile();
    }
}

/**
 * Файловый вариант проверки запросов в минуту
 */
private function checkRequestsPerMinuteFile() {
    try {
        $file = $this->dos_dir . 'minute_requests/' . str_replace([':', '.'], '_', $this->ip) . '.txt';
        
        // Создаем директорию, если не существует
        $dir = dirname($file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        
        $now = time();
        $minuteAgo = $now - 60;
        $requests = [];
        
        // Читаем существующие записи
        if (file_exists($file)) {
            $content = file_get_contents($file);
            if ($content) {
                $requests = json_decode($content, true) ?: [];
            }
        }
        
        // Фильтруем старые записи
        $requests = array_filter($requests, function($time) use ($minuteAgo) {
            return $time >= $minuteAgo;
        });
        
        // Добавляем текущий запрос
        $requests[] = $now;
        
        // Записываем обновленный список
        file_put_contents($file, json_encode($requests));
        
        // Проверяем лимит
        $count = count($requests);
        if ($count > MAX_REQUESTS_PER_MINUTE) {
            error_log("IP {$this->ip} превысил лимит запросов в минуту: $count запросов (файловый режим)");
            return true; // Лимит превышен
        }
        
        return false;
    } catch (Exception $e) {
        error_log("Ошибка файловой проверки запросов в минуту: " . $e->getMessage());
        return false;
    }
}

private function checkTotalRequestsPerIP() {
    // Получаем User-Agent
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    
    // Проверяем, является ли запрос от легитимного поискового бота
    $is_bot = $user_agent && $this->verifySearchBot($this->ip, $user_agent);
    
    // Определяем лимит в зависимости от того, бот это или нет
    $limit = $is_bot ? 
        (defined('BOT_MAX_REQUESTS_PER_IP') ? BOT_MAX_REQUESTS_PER_IP : 1000) : 
        MAX_REQUESTS_PER_IP;
    
    if (!$this->useRedis || !$this->redis) {
        // Без Redis используем файловый кеш
        return $this->checkTotalRequestsPerIPFile($limit);
    }
    
    try {
        $key = $this->prefix . "total_requests:{$this->ip}";
        
        // Увеличиваем счетчик для текущего IP
        $count = $this->redis->incr($key);
        
        // Устанавливаем TTL для ключа, если его еще нет
        if ($this->redis->ttl($key) < 0) {
            // Сохраняем счетчик на сутки
            $this->redis->expire($key, 86400);
        }
        
        // Проверяем, не превышен ли лимит
        if ($count > $limit) {
            error_log("IP {$this->ip} превысил общий лимит запросов: $count запросов" . 
                     ($is_bot ? " (поисковый бот)" : ""));
            return true; // Лимит превышен
        }
        
        return false;
    } catch (Exception $e) {
        error_log("Ошибка проверки общего количества запросов через Redis: " . $e->getMessage());
        // Фоллбек на файловый метод
        return $this->checkTotalRequestsPerIPFile($limit);
    }
}

/**
 * Файловый вариант проверки общего количества запросов с IP
 * @param int $limit Лимит запросов
 * @return bool
 */
private function checkTotalRequestsPerIPFile($limit = null) {
    try {
        if ($limit === null) {
            // Получаем User-Agent
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
            
            // Проверяем, является ли запрос от легитимного поискового бота
            $is_bot = $user_agent && $this->verifySearchBot($this->ip, $user_agent);
            
            // Определяем лимит в зависимости от того, бот это или нет
            $limit = $is_bot ? 
                (defined('BOT_MAX_REQUESTS_PER_IP') ? BOT_MAX_REQUESTS_PER_IP : 1000) : 
                MAX_REQUESTS_PER_IP;
        }
        
        $file = $this->dos_dir . 'total_requests/' . str_replace([':', '.'], '_', $this->ip) . '.txt';
        
        // Создаем директорию, если не существует
        $dir = dirname($file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        
        // Проверяем время создания файла - сбрасываем счетчик раз в сутки
        $resetCounter = false;
        if (file_exists($file)) {
            $fileTime = filemtime($file);
            if (time() - $fileTime > 86400) {
                $resetCounter = true;
            }
        }
        
        // Получаем текущее значение счетчика
        $count = 0;
        if (!$resetCounter && file_exists($file)) {
            $count = (int)file_get_contents($file);
        }
        
        // Увеличиваем счетчик
        $count++;
        
        // Записываем обновленное значение
        file_put_contents($file, (string)$count);
        
        // Проверяем лимит
        if ($count > $limit) {
            error_log("IP {$this->ip} превысил общий лимит запросов: $count запросов (файловый режим)");
            return true; // Лимит превышен
        }
        
        return false;
    } catch (Exception $e) {
        error_log("Ошибка файловой проверки общего количества запросов: " . $e->getMessage());
        return false;
    }
}
    
    /**
     * Быстрая предварительная проверка подозрительности запроса
     */
    /**
 * Быстрая предварительная проверка подозрительности запроса
 */
private function isRequestSuspicious() {
    // Если запрос направлен в админку или на страницу разблокировки, не считаем его подозрительным
    if (strpos($_SERVER['REQUEST_URI'], '/dos/admin.php') !== false ||
        strpos($_SERVER['REQUEST_URI'], '/dos/recaptcha_unlock.php') !== false) {
        return false;
    }
    
    // Если IP в белом списке, всегда возвращаем false (не подозрительный)
    if ($this->isIpInWhitelist($this->ip)) {
        return false;
    }
    
    // Получаем User-Agent
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    
    // Проверяем, не является ли запрос от легитимного поискового бота
    if ($user_agent && $this->verifySearchBot($this->ip, $user_agent)) {
        // Если это бот, проверяем применять ли к нему особые лимиты
        if (defined('SEARCH_BOT_SPECIAL_LIMITS') && SEARCH_BOT_SPECIAL_LIMITS) {
            // Можно здесь реализовать особую логику для ботов
            // Например, логирование активности ботов
            if (defined('LOG_SEARCH_BOT_ACTIVITY') && LOG_SEARCH_BOT_ACTIVITY) {
                error_log("Verified search bot: " . $this->ip . " - " . $user_agent);
            }
        }
        return false; // Легитимный бот, не считаем подозрительным
    }
    
    // Проверка empty User-Agent
    if (empty($user_agent)) {
        // НОВЫЙ КОД: Блокируем на третьем уровне вместо возврата true
        $reason = "Пустой User-Agent";
        error_log("Блокировка IP {$this->ip} с {$reason}");
        
        if ($this->useRedis && $this->redis) {
			$this->logRequestRedis();
            $this->blockIPRedis(BLOCK_TIME_THIRD, $reason);
        } else {
            $this->connectDB();
			$this->initializeTables(); // Убеждаемся, что таблицы созданы
			$this->logRequest(); // Добавляем логирование
            $this->blockIP(BLOCK_TIME_THIRD, $reason);
        }
        $this->redirectToUnlockPage();
        exit;
    }
	
if (ENABLE_BOT_DETECTION) {    
    // Проверка на типичные признаки бота
    $ua = strtolower($user_agent);
    $bot_terms = array('bot', 'crawler', 'spider', 'grab', 'download', 'fetch', 'parser');
    foreach ($bot_terms as $term) {
        if (strpos($ua, $term) !== false) {
            // НОВЫЙ КОД: Блокируем на третьем уровне вместо возврата true
            $reason = "Неподтвержденный бот: {$term}";
            error_log("Блокировка IP {$this->ip} с {$reason}: {$ua}");
            
            if ($this->useRedis && $this->redis) {
				$this->logRequestRedis();
                $this->blockIPRedis(BLOCK_TIME_THIRD, $reason);
            } else {
                $this->connectDB();
				$this->initializeTables(); // Убеждаемся, что таблицы созданы
				$this->logRequest(); // Добавляем логирование
                $this->blockIP(BLOCK_TIME_THIRD, $reason);
            }
            
            // Добавляем в список жестких блокировок для дополнительной защиты
            $this->addToHardBlockList($this->ip, $reason);
            
            // Применяем все доступные методы блокировки
            $this->applyExternalBlockings($this->ip);
            
            $this->redirectToUnlockPage();
            exit;
        }
    }
}        
    // Инициализируем сессию
    if (session_status() == PHP_SESSION_NONE) {
        if (version_compare(PHP_VERSION, '7.1.0', '>=')) {
            ini_set('session.use_strict_mode', 1);
        }
        session_start();
    }
    
    // Инициализируем счетчики запросов
    if (!isset($_SESSION['last_request_time'])) {
        $_SESSION['last_request_time'] = microtime(true);
        $_SESSION['request_count'] = 1;
        $_SESSION['requests_log'] = array();
        return false;
    }
    
    // Логируем время запроса
    $current_time = microtime(true);
    $_SESSION['requests_log'][] = $current_time;
    
    // Оставляем только последние 20 запросов
    if (count($_SESSION['requests_log']) > 20) {
        $_SESSION['requests_log'] = array_slice($_SESSION['requests_log'], -20);
    }
    
    // Увеличиваем счетчик запросов
    $_SESSION['request_count']++;
    
    // Проверка частоты запросов за последнюю секунду
    $requests_last_second = 0;
    foreach ($_SESSION['requests_log'] as $time) {
        if ($current_time - $time <= 1) {
            $requests_last_second++;
        }
    }
    
    // Если более N запросов за секунду - подозрительно
    $threshold = defined('MAX_REQUESTS_PER_SECOND') ? MAX_REQUESTS_PER_SECOND * 1.5 : 12;
    if ($requests_last_second >= $threshold) {
        return true;
    }
    
    // Обновляем время последнего запроса
    $_SESSION['last_request_time'] = $current_time;
    
    return false;
}
    
    /**
     * Логирование подозрительных запросов в Redis
     */
    private function logRequestRedis() {
        if (!$this->redis) return false;
        
        try {
            // Генерируем уникальный ID запроса
            $requestId = $this->redis->incr($this->prefix . "next_request_id");
            
            // Создаем запись о запросе с TTL
            $ttl = defined('REDIS_TTL_SUSPICIOUS_REQUEST') ? REDIS_TTL_SUSPICIOUS_REQUEST : 86400;
            
            // Получаем данные о запросе
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Empty';
            $request_uri = $_SERVER['REQUEST_URI'];
            $now = time();
            
            // Сохраняем данные о запросе
            $key = $this->prefix . "request:$requestId";
            $this->redis->multi();
            $this->redis->hMSet($key, array(
                'ip' => $this->ip,
                'user_agent' => $user_agent,
                'request_uri' => $request_uri,
                'request_time' => $now
            ));
            $this->redis->expire($key, $ttl);
            
            // Добавляем ID запроса в список запросов IP
            $ipRequestsKey = $this->prefix . "suspicious_requests:{$this->ip}";
            $this->redis->lPush($ipRequestsKey, $requestId);
            $this->redis->ltrim($ipRequestsKey, 0, 99); // Храним только последние 100 запросов
            $this->redis->expire($ipRequestsKey, $ttl);
            
            // Увеличиваем счетчик подозрительности IP
            $this->redis->zIncrBy($this->prefix . "suspicious_ips", 1, $this->ip);
            
            $this->redis->exec();
            
            return true;
        } catch (Exception $e) {
            error_log("Error logging request to Redis: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Проверка подозрительной активности через Redis
     */
    private function checkSuspiciousActivityRedis() {
        if (!$this->redis) return false;
        
        try {
            // Если IP уже заблокирован, нет смысла проверять
            $blockedKey = $this->prefix . "blocked_ip:{$this->ip}";
            if ($this->redis->exists($blockedKey)) {
                return true;
            }
            
            // Получаем количество подозрительных запросов за последние 30 секунд
            $ipRequestsKey = $this->prefix . "suspicious_requests:{$this->ip}";
            $requestCount = $this->redis->lLen($ipRequestsKey);
            
            // Если много подозрительных запросов, блокируем IP
            if ($requestCount > 10) {
                $this->blockIPRedis(BLOCK_TIME_FIRST, 'Слишком много подозрительных запросов');
                
                // Перенаправляем на страницу разблокировки
                $this->redirectToUnlockPage();
                exit;
            }
            
            return false;
        } catch (Exception $e) {
            error_log("Error checking suspicious activity in Redis: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Блокировка IP в Redis с прогрессивной логикой
     */
    private function blockIPRedis($seconds, $reason) {
    if (!$this->redis) return false;
    
    try {
        // Используем текущий IP, не пытаясь его нормализовать
        $blockKey = $this->prefix . "blocked_ip:{$this->ip}";
        $now = time();
        $blockUntil = $now + $seconds;
        $block_count = 1;
        
        // Проверяем, был ли этот IP уже заблокирован
        if ($this->redis->exists($blockKey)) {
            // Увеличиваем счетчик блокировок
            $block_count = $this->redis->hIncrBy($blockKey, 'block_count', 1);
            
            // Получаем время первой блокировки
            $first_blocked_at = $this->redis->hGet($blockKey, 'first_blocked_at');
            
            // Прогрессивное увеличение времени блокировки
            switch ($block_count) {
                case 2:
                    $seconds = defined('BLOCK_TIME_SECOND') ? BLOCK_TIME_SECOND : 10800; // 3 hours
                    break;
                case 3:
                    $seconds = defined('BLOCK_TIME_THIRD') ? BLOCK_TIME_THIRD : 21600; // 6 hours
                    break;
                case 4:
                    $seconds = defined('BLOCK_TIME_FOURTH') ? BLOCK_TIME_FOURTH : 43200; // 12 hours
                    break;
                case 5:
                    $seconds = defined('BLOCK_TIME_FIFTH') ? BLOCK_TIME_FIFTH : 86400; // 1 day
                    break;
                case 6:
                    $seconds = defined('BLOCK_TIME_SIXTH') ? BLOCK_TIME_SIXTH : 259200; // 3 days
                    break;
                default:
                    $seconds = defined('BLOCK_TIME_SEVENTH_PLUS') ? BLOCK_TIME_SEVENTH_PLUS : 604800; // 7 days
                    break;
            }
            
            $blockUntil = $now + $seconds;
        } else {
            // Первая блокировка
            $first_blocked_at = $now;
        }
        
        error_log("Blocking IP {$this->ip} for " . $this->formatBlockTime($seconds) . ". Reason: $reason. Block count: $block_count");
        
        // Обновляем информацию о блокировке в Redis с транзакцией
        try {
            $this->redis->multi();
            
            // Устанавливаем хеш со всеми данными блокировки
            $blockData = array(
                'block_until' => $blockUntil,
                'reason' => $reason . ($block_count > 1 ? " (блокировка #$block_count)" : ""),
                'created_at' => $now,
                'block_count' => $block_count,
                'first_blocked_at' => $first_blocked_at,
                'is_blocked' => 1  // Флаг, указывающий, что IP заблокирован
            );
            
            $this->redis->hMSet($blockKey, $blockData);
            
            // Важно: установить TTL для ключа блока (2x продолжительность блокировки для сохранения истории)
            $ttl = max($seconds * 2, 86400); // Минимум 1 день
            $this->redis->expire($blockKey, $ttl);
            
            // Добавить IP в сортированный набор заблокированных IP для более быстрого поиска
            $this->redis->zAdd($this->prefix . "blocked_ips", $blockUntil, $this->ip);
            
            // Добавить в журнал блокировок
            $logEntry = array(
                'ip' => $this->ip,
                'reason' => $reason,
                'block_until' => $blockUntil,
                'block_count' => $block_count,
                'time' => $now
            );
            $logEntryJson = json_encode($logEntry);
            
            $this->redis->lPush($this->prefix . "block_log", $logEntryJson);
            $this->redis->ltrim($this->prefix . "block_log", 0, 999);
            
            // Выполняем транзакцию
            $this->redis->exec();
        } catch (Exception $e) {
            error_log("Ошибка транзакции Redis при блокировке IP: " . $e->getMessage());
            // Пробуем без транзакции
            try {
                $this->redis->hMSet($blockKey, $blockData);
                $this->redis->expire($blockKey, $ttl);
                $this->redis->zAdd($this->prefix . "blocked_ips", $blockUntil, $this->ip);
            } catch (Exception $e2) {
                error_log("Ошибка при резервном способе блокировки IP: " . $e2->getMessage());
            }
        }
        
        // Записать в файл журнала
        $time_description = $this->formatBlockTime($seconds);
        $log_message = date('Y-m-d H:i:s') . " - " . $this->ip . " заблокирован на $time_description: " . 
                       $reason . ($block_count > 1 ? " (повторная блокировка #$block_count)" : "") . "\n";
        @file_put_contents($this->dos_dir . 'blocked_ips.log', $log_message, FILE_APPEND);
        
        // Применить внешние блокировки при необходимости
        if ((defined('HARD_BLOCK_ON_FIRST_VIOLATION') && HARD_BLOCK_ON_FIRST_VIOLATION) || 
            $block_count > 1 || 
            strpos(strtolower($reason), 'слишком много') !== false) {
                $this->applyExternalBlockings($this->ip);
        }
        
        // Обновить файловый кеш
        $this->updateBlockedIPsCache();
        
        return array(
            'ip' => $this->ip,
            'block_until' => $blockUntil,
            'seconds' => $seconds,
            'block_count' => $block_count
        );
    } catch (Exception $e) {
        error_log("Ошибка блокировки IP в Redis: " . $e->getMessage());
        return false;
    }
}
    
    /**
     * Применение блокировок через внешние механизмы
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
     * Форматирование времени блокировки для логирования
     */
    private function formatBlockTime($seconds) {
        if ($seconds < 3600) {
            return floor($seconds / 60) . " минут";
        } else if ($seconds < 86400) {
            return floor($seconds / 3600) . " часов";
        } else {
            return floor($seconds / 86400) . " дней";
        }
    }
    
    /**
     * Проверка и контроль использования памяти Redis
     */
    private function checkRedisMemory() {
        if (!$this->redis) return false;
        
        try {
            // Получаем информацию о памяти Redis
            $info = $this->redis->info('memory');
            
            // Если maxmemory не установлен, нет смысла проверять
            if (!isset($info['maxmemory']) || $info['maxmemory'] == 0) {
                return false;
            }
            
            // Вычисляем процент использования памяти
            $used_memory = $info['used_memory'];
            $max_memory = $info['maxmemory'];
            $memory_percent = ($used_memory / $max_memory) * 100;
            
            // Пороги использования памяти
            $warning_threshold = defined('REDIS_MEMORY_LIMIT_PERCENT') ? REDIS_MEMORY_LIMIT_PERCENT : 80;
            $emergency_threshold = defined('REDIS_EMERGENCY_MEMORY_PERCENT') ? REDIS_EMERGENCY_MEMORY_PERCENT : 95;
            
            // Логирование при приближении к лимиту
            if ($memory_percent > $warning_threshold) {
                error_log("Warning: Redis memory usage at {$memory_percent}% ({$used_memory} of {$max_memory} bytes)");
                
                // Экстренная очистка при критическом использовании памяти
                if ($memory_percent > $emergency_threshold) {
                    error_log("Emergency: Performing Redis memory cleanup");
                    $this->emergencyRedisCleanup();
                }
            }
            
            return true;
        } catch (Exception $e) {
            error_log("Error checking Redis memory: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Экстренная очистка памяти Redis при критическом использовании
     */
    private function emergencyRedisCleanup() {
        if (!$this->redis) return false;
        
        try {
            // 1. Очистка старых записей о частоте запросов
            // Используем LUA-скрипт для безопасного удаления ключей
            $script = "
                local prefix = ARGV[1]
                local keys = redis.call('keys', prefix .. 'ip_request_rate:*')
                local count = 0
                if #keys > 500 then
                    for i=1,#keys/2 do
                        redis.call('del', keys[i])
                        count = count + 1
                    end
                end
                return count
            ";
            
            $deleted_keys = $this->redis->eval($script, array($this->prefix), 0);
            error_log("Redis emergency cleanup: Deleted $deleted_keys ip_request_rate keys");
            
            // 2. Очистка старых подозрительных запросов
            $script = "
                local prefix = ARGV[1]
                local keys = redis.call('keys', prefix .. 'request:*')
                local count = 0
                if #keys > 1000 then
                    for i=1,#keys/2 do
                        redis.call('del', keys[i])
                        count = count + 1
                    end
                end
                return count
            ";
            
            $deleted_keys = $this->redis->eval($script, array($this->prefix), 0);
            error_log("Redis emergency cleanup: Deleted $deleted_keys request keys");
            
            // 3. Очистка списков подозрительных запросов
            $script = "
                local prefix = ARGV[1]
                local keys = redis.call('keys', prefix .. 'suspicious_requests:*')
                local count = 0
                if #keys > 0 then
                    for i=1,#keys do
                        redis.call('ltrim', keys[i], 0, 19) -- оставляем только 20 последних запросов
                        count = count + 1
                    end
                end
                return count
            ";
            
            $trimmed_keys = $this->redis->eval($script, array($this->prefix), 0);
            error_log("Redis emergency cleanup: Trimmed $trimmed_keys suspicious_requests lists");
            
            return true;
        } catch (Exception $e) {
            error_log("Error during Redis emergency cleanup: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Очистка Redis - удаление истекших ключей (вызывается через cron)
     */
    private function cleanupRedisRecords() {
        if (!$this->redis) return false;
        
        try {
            // 1. Очистка устаревших блокировок в Redis
            $now = time();
            $blockedIpsKey = $this->prefix . 'blocked_ips';
            
            // Удаляем все IP с истекшим сроком блокировки из sorted set
            $expired_count = $this->redis->zRemRangeByScore($blockedIpsKey, 0, $now);
            
            error_log("Redis cleanup: Removed $expired_count expired IP blocks");
            
            // 2. Очистка устаревших записей о частоте запросов (если не установлен TTL)
            $script = "
                local prefix = ARGV[1]
                local now = tonumber(ARGV[2])
                local cutoff = now - 600 -- 10 минут
                local keys = redis.call('keys', prefix .. 'ip_request_rate:*')
                local count = 0
                
                for i=1,#keys do
                    local last_time = tonumber(redis.call('hget', keys[i], 'last_request_time') or 0)
                    if last_time < cutoff then
                        redis.call('del', keys[i])
                        count = count + 1
                    end
                end
                
                return count
            ";
            
            $deleted = $this->redis->eval($script, array($this->prefix, $now), 0);
            error_log("Redis cleanup: Removed $deleted old request rate entries");
            
            // 3. Очистка устаревших подозрительных запросов (если не установлен TTL)
            $script = "
                local prefix = ARGV[1]
                local now = tonumber(ARGV[2])
                local cutoff = now - 86400 -- 24 часа
                local keys = redis.call('keys', prefix .. 'request:*')
                local count = 0
                
                for i=1,#keys do
                    local request_time = tonumber(redis.call('hget', keys[i], 'request_time') or 0)
                    if request_time < cutoff then
                        redis.call('del', keys[i])
                        count = count + 1
                    end
                end
                
                return count
            ";
            
            $deleted = $this->redis->eval($script, array($this->prefix, $now), 0);
            error_log("Redis cleanup: Removed $deleted old suspicious requests");
            
            return true;
        } catch (Exception $e) {
            error_log("Redis cleanup error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Метод создания таблиц в MariaDB - вызывается только при необходимости
     */
    private function initializeTables() {
        // Проверяем кэш
        static $tables_initialized = false;
        if ($tables_initialized) {
            return;
        }
        
        $queries = array(
            // Упрощенная таблица логов - храним только подозрительные запросы
            "CREATE TABLE IF NOT EXISTS `suspicious_requests` (
                `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                `ip` VARCHAR(45) NOT NULL,
                `user_agent` VARCHAR(255) NOT NULL,
                `request_uri` VARCHAR(255) NOT NULL,
                `request_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX (`ip`),
                INDEX (`request_time`)
            ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
            
            // Таблица для хранения заблокированных IP с полями для прогрессивной блокировки
            "CREATE TABLE IF NOT EXISTS `blocked_ips` (
                `ip` VARCHAR(45) PRIMARY KEY,
                `block_until` TIMESTAMP NOT NULL,
                `reason` VARCHAR(255) NOT NULL,
                `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                `block_count` INT UNSIGNED NOT NULL DEFAULT 1,
                `first_blocked_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP
            ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        );
        
        try {
            foreach ($queries as $query) {
                $this->db->exec($query);
            }
            $tables_initialized = true;
        } catch(PDOException $e) {
            error_log("Table Creation Error: " . $e->getMessage());
        }
    }
    
    /**
     * Логирование запроса в MariaDB
     */
    private function logRequest() {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO suspicious_requests (ip, user_agent, request_uri) 
                VALUES (?, ?, ?)
            ");
            
            // Replacing null coalescing operator with isset check for PHP 5.6 compatibility
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Empty';
            
            $stmt->execute(array(
                $this->ip, 
                $user_agent,
                $_SERVER['REQUEST_URI']
            ));
        } catch(PDOException $e) {
            error_log("Error logging request: " . $e->getMessage());
        }
    }
    
    /**
     * Проверка активности с оптимизированными запросами (MariaDB)
     */
    private function checkSuspiciousActivity() {
        try {
            // Если запрос направлен в админку или на страницу разблокировки, пропускаем проверку
            if (strpos($_SERVER['REQUEST_URI'], '/dos/admin.php') !== false || 
                strpos($_SERVER['REQUEST_URI'], '/dos/recaptcha_unlock.php') !== false) {
                return;
            }
            
            // Проверяем блокировку в базе данных
            $stmt = $this->db->prepare("SELECT block_until FROM blocked_ips WHERE ip = ? AND block_until > NOW()");
            $stmt->execute(array($this->ip));
            $block_result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($block_result) {
                // Если IP уже заблокирован, обновляем файловый кеш и выходим
                $this->updateBlockedIPsCache();
                
                // Перенаправляем на страницу разблокировки
                $this->redirectToUnlockPage();
                exit;
            }
            
            // Получаем количество запросов за последние 20 секунд
            $stmt = $this->db->prepare("
                SELECT COUNT(*) FROM suspicious_requests 
                WHERE ip = ? AND request_time > DATE_SUB(NOW(), INTERVAL 30 SECOND)
            ");
            $stmt->execute(array($this->ip));
            $recent_requests_count = $stmt->fetchColumn();
            
            // Если много подозрительных запросов, блокируем IP
            if ($recent_requests_count > 10) {
                $this->blockIP(3600, 'Слишком много запросов');
                
                // Перенаправляем на страницу разблокировки
                $this->redirectToUnlockPage();
                exit;
            }
        } catch(PDOException $e) {
            error_log("Error checking activity: " . $e->getMessage());
        }
    }
    
/**
 * Реализация механизма троттлинга для плавного ограничения доступа
 * 
 * @param string $requestType Тип запроса для отдельных лимитов ('page', 'api', и др.)
 * @param bool $increase Увеличивать ли счетчик (true) или только проверять (false)
 * @return array Результат троттлинга [throttled => bool, delay => int, remaining => int]
 */
/**
 * Реализация механизма троттлинга для плавного ограничения доступа
 * с отключением при большом количестве блокировок
 * 
 * @param string $requestType Тип запроса для отдельных лимитов ('page', 'api', и др.)
 * @param bool $increase Увеличивать ли счетчик (true) или только проверять (false)
 * @return array Результат троттлинга [throttled => bool, delay => int, remaining => int]
 */
public function applyThrottling($requestType = 'default', $increase = true) {
    $result = [
        'throttled' => false,  // Нужно ли применять задержку
        'delay' => 0,          // Время задержки в миллисекундах
        'remaining' => 0,      // Оставшееся количество запросов
        'window' => 0,         // Оставшееся время окна в секундах
        'limit' => 0           // Установленный лимит
    ];
    
    // Пропускаем троттлинг для IP из белого списка
    if ($this->isIpInWhitelist($this->ip)) {
        return $result;
    }
    
    // НОВЫЙ КОД: Проверяем, не достигнут ли порог автоматической блокировки
    // и включена ли функция отключения троттлинга при достижении порога
    if ((defined('DISABLE_THROTTLING_ON_THRESHOLD') && DISABLE_THROTTLING_ON_THRESHOLD) && 
        (defined('AUTO_HARD_BLOCK_ENABLED') && AUTO_HARD_BLOCK_ENABLED)) {
        $blocked_count = $this->getBlockedIPsCount();
        $threshold = defined('AUTO_HARD_BLOCK_THRESHOLD') ? AUTO_HARD_BLOCK_THRESHOLD : 100;
        
        // Если количество блокировок превышает порог, пропускаем троттлинг полностью
        if ($blocked_count >= $threshold) {
            // Логируем отключение троттлинга, но редко (5% случаев), чтобы не забивать логи
            if (mt_rand(1, 100) <= 5) {
                error_log("Троттлинг отключен из-за превышения порога жесткой блокировки: заблокировано $blocked_count IP, порог $threshold");
            }
            return $result; // Возвращаем результат без троттлинга
        }
    }
    
    // Получаем настройки троттлинга для указанного типа запроса
    $throttleSettings = $this->getThrottleSettings($requestType);
    if (!$throttleSettings) {
        return $result; // Если настройки не найдены, не применяем троттлинг
    }
    
    $limit = $throttleSettings['limit'];         // Лимит запросов в окне
    $window = $throttleSettings['window'];       // Размер окна в секундах
    $maxDelay = $throttleSettings['max_delay'];  // Максимальная задержка в мс
    
    // Проверяем и применяем троттлинг через Redis или файловый кеш
    if ($this->useRedis && $this->redis) {
        return $this->applyThrottlingRedis($requestType, $limit, $window, $maxDelay, $increase);
    } else {
        return $this->applyThrottlingSession($requestType, $limit, $window, $maxDelay, $increase);
    }
}

/**
 * Применение троттлинга через Redis
 */
private function applyThrottlingRedis($requestType, $limit, $window, $maxDelay, $increase) {
    $result = [
        'throttled' => false,
        'delay' => 0,
        'remaining' => $limit,
        'window' => $window,
        'limit' => $limit
    ];
    
    try {
        $key = $this->prefix . "throttle:{$this->ip}:{$requestType}";
        $now = time();
        
        // Если ключ не существует, создаем его
        if (!$this->redis->exists($key)) {
            if ($increase) {
                $this->redis->hMSet($key, [
                    'count' => 1,
                    'first_request' => $now,
                    'last_request' => $now
                ]);
                $this->redis->expire($key, $window);
            }
            
            $result['remaining'] = $limit - 1;
            return $result; // Первый запрос, не применяем троттлинг
        }
        
        // Получаем текущие данные
        $data = $this->redis->hGetAll($key);
        $count = (int)$data['count'];
        $firstRequest = (int)$data['first_request'];
        $lastRequest = (int)$data['last_request'];
        
        // Проверяем, не истекло ли окно
        $elapsed = $now - $firstRequest;
        if ($elapsed >= $window) {
            // Окно истекло, сбрасываем счетчик
            if ($increase) {
                $this->redis->hMSet($key, [
                    'count' => 1,
                    'first_request' => $now,
                    'last_request' => $now
                ]);
                $this->redis->expire($key, $window);
            }
            
            $result['remaining'] = $limit - 1;
            return $result;
        }
        
        // Обновляем данные, если нужно увеличить счетчик
        if ($increase) {
            $this->redis->hIncrBy($key, 'count', 1);
            $this->redis->hSet($key, 'last_request', $now);
            $count++;
        }
        
        // Вычисляем оставшееся количество запросов
        $remaining = $limit - $count;
        $result['remaining'] = max(0, $remaining);
        
        // Вычисляем оставшееся время окна
        $result['window'] = $window - $elapsed;
        
        // Если превышен лимит, применяем троттлинг
        if ($count > $limit) {
            $result['throttled'] = true;
            
            // Вычисляем задержку: чем больше превышение, тем дольше задержка
            $overLimit = $count - $limit;
            $delayFactor = min(1, $overLimit / $limit); // От 0 до 1
            $result['delay'] = (int)($maxDelay * $delayFactor);
            
            // Добавляем соответствующие заголовки
            $this->addThrottlingHeaders($result);
            
            // Если настроено, применяем задержку
            if (defined('THROTTLING_APPLY_DELAY') && THROTTLING_APPLY_DELAY) {
                $this->applyDelay($result['delay']);
            }
        }
        
        return $result;
    } catch (Exception $e) {
        error_log("Redis throttling error: " . $e->getMessage());
        return $result; // В случае ошибки не применяем троттлинг
    }
}

/**
 * Применение троттлинга через сессию (резервный вариант)
 */
private function applyThrottlingSession($requestType, $limit, $window, $maxDelay, $increase) {
    $result = [
        'throttled' => false,
        'delay' => 0,
        'remaining' => $limit,
        'window' => $window,
        'limit' => $limit
    ];
    
    // Проверяем, доступна ли сессия
    if (session_status() == PHP_SESSION_NONE) {
        if (version_compare(PHP_VERSION, '7.1.0', '>=')) {
            ini_set('session.use_strict_mode', 1);
        }
        session_start();
    }
    
    $key = "throttle_{$requestType}";
    $now = time();
    
    // Инициализируем данные троттлинга, если они отсутствуют
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = [
            'count' => 0,
            'first_request' => $now,
            'last_request' => $now
        ];
    }
    
    // Получаем текущие данные
    $data = &$_SESSION[$key];
    $count = $data['count'];
    $firstRequest = $data['first_request'];
    $lastRequest = $data['last_request'];
    
    // Проверяем, не истекло ли окно
    $elapsed = $now - $firstRequest;
    if ($elapsed >= $window) {
        // Окно истекло, сбрасываем счетчик
        $data['count'] = $increase ? 1 : 0;
        $data['first_request'] = $now;
        $data['last_request'] = $now;
        
        $result['remaining'] = $limit - ($increase ? 1 : 0);
        return $result;
    }
    
    // Обновляем данные, если нужно увеличить счетчик
    if ($increase) {
        $data['count']++;
        $data['last_request'] = $now;
        $count++;
    }
    
    // Вычисляем оставшееся количество запросов
    $remaining = $limit - $count;
    $result['remaining'] = max(0, $remaining);
    
    // Вычисляем оставшееся время окна
    $result['window'] = $window - $elapsed;
    
    // Если превышен лимит, применяем троттлинг
    if ($count > $limit) {
        $result['throttled'] = true;
        
        // Вычисляем задержку: чем больше превышение, тем дольше задержка
        $overLimit = $count - $limit;
        $delayFactor = min(1, $overLimit / $limit); // От 0 до 1
        $result['delay'] = (int)($maxDelay * $delayFactor);
        
        // Добавляем соответствующие заголовки
        $this->addThrottlingHeaders($result);
        
        // Если настроено, применяем задержку
        if (defined('THROTTLING_APPLY_DELAY') && THROTTLING_APPLY_DELAY) {
            $this->applyDelay($result['delay']);
        }
    }
    
    return $result;
}

/**
 * Получение настроек троттлинга для указанного типа запроса
 */
private function getThrottleSettings($requestType) {
    $settings = [
        'default' => [
            'limit' => defined('RATE_THRESHOLD') ? RATE_THRESHOLD : 30,
            'window' => defined('RATE_CHECK_WINDOW') ? RATE_CHECK_WINDOW : 10,
            'max_delay' => defined('THROTTLING_DEFAULT_MAX_DELAY') ? THROTTLING_DEFAULT_MAX_DELAY : 1000
        ],
        'api' => [
            'limit' => defined('THROTTLING_API_LIMIT') ? THROTTLING_API_LIMIT : 20,
            'window' => defined('THROTTLING_API_WINDOW') ? THROTTLING_API_WINDOW : 60,
            'max_delay' => defined('THROTTLING_API_MAX_DELAY') ? THROTTLING_API_MAX_DELAY : 2000
        ],
        'login' => [
            'limit' => defined('THROTTLING_LOGIN_LIMIT') ? THROTTLING_LOGIN_LIMIT : 5,
            'window' => defined('THROTTLING_LOGIN_WINDOW') ? THROTTLING_LOGIN_WINDOW : 300,
            'max_delay' => defined('THROTTLING_LOGIN_MAX_DELAY') ? THROTTLING_LOGIN_MAX_DELAY : 5000
        ],
        'search' => [
            'limit' => defined('THROTTLING_SEARCH_LIMIT') ? THROTTLING_SEARCH_LIMIT : 10,
            'window' => defined('THROTTLING_SEARCH_WINDOW') ? THROTTLING_SEARCH_WINDOW : 60,
            'max_delay' => defined('THROTTLING_SEARCH_MAX_DELAY') ? THROTTLING_SEARCH_MAX_DELAY : 1500
        ]
    ];
    
    // Возвращаем настройки для указанного типа или настройки по умолчанию
    return isset($settings[$requestType]) ? $settings[$requestType] : $settings['default'];
}

/**
 * Добавление заголовков для троттлинга
 */
private function addThrottlingHeaders($result) {
    if (!headers_sent()) {
        header('X-RateLimit-Limit: ' . $result['limit']);
        header('X-RateLimit-Remaining: ' . $result['remaining']);
        header('X-RateLimit-Reset: ' . (time() + $result['window']));
        
        if ($result['throttled']) {
            header('Retry-After: ' . ceil($result['delay'] / 1000));
        }
    }
}

/**
 * Применение задержки в миллисекундах
 */
private function applyDelay($milliseconds) {
    // Ограничиваем максимальное время задержки для безопасности
    $milliseconds = min($milliseconds, 2000); // Максимум 2 секунды задержки
    
    // Проверяем, разрешены ли функции сна
    if (!in_array('usleep', array_map('trim', explode(',', ini_get('disable_functions'))))) {
        // Применяем задержку (1 миллисекунда = 1000 микросекунд)
        usleep($milliseconds * 1000);
    } else {
        // Альтернативный метод задержки через цикл с микропаузами
        $start = microtime(true);
        $end = $start + ($milliseconds / 1000);
        
        while (microtime(true) < $end) {
            // Добавляем микропаузу для снижения нагрузки на CPU
            if (function_exists('time_nanosleep') && 
                !in_array('time_nanosleep', array_map('trim', explode(',', ini_get('disable_functions'))))) {
                time_nanosleep(0, 1000000); // 1 миллисекунда
            }
        }
    }
}	
	
    /**
     * Блокировка IP через MariaDB с прогрессивной логикой
     */
    private function blockIP($seconds, $reason) {
        try {
            // Сначала проверяем, был ли этот IP заблокирован ранее
            $stmt = $this->db->prepare("
                SELECT block_count, first_blocked_at
                FROM blocked_ips 
                WHERE ip = ?
            ");
            $stmt->execute(array($this->ip));
            $existing_block = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Рассчитываем прогрессивное время блокировки и счетчик
            $block_count = 1;
            $progressive_seconds = $seconds;
            $first_blocked_at = 'CURRENT_TIMESTAMP';
            
            if ($existing_block) {
                // Увеличиваем счетчик блокировок
                $block_count = $existing_block['block_count'] + 1;
                $first_blocked_at = "'" . $existing_block['first_blocked_at'] . "'";
                
                // Рассчитываем прогрессивное время блокировки
                // Например: 1 час -> 3 часа -> 6 часов -> 12 часов -> 24 часа -> 3 дня -> 7 дней
                switch ($block_count) {
                    case 2:
                        $progressive_seconds = defined('BLOCK_TIME_SECOND') ? BLOCK_TIME_SECOND : 10800; // 3 часа
                        break;
                    case 3:
                        $progressive_seconds = defined('BLOCK_TIME_THIRD') ? BLOCK_TIME_THIRD : 21600; // 6 часов
                        break;
                    case 4:
                        $progressive_seconds = defined('BLOCK_TIME_FOURTH') ? BLOCK_TIME_FOURTH : 43200; // 12 часов
                        break;
                    case 5:
                        $progressive_seconds = defined('BLOCK_TIME_FIFTH') ? BLOCK_TIME_FIFTH : 86400; // 1 день
                        break;
                    case 6:
                        $progressive_seconds = defined('BLOCK_TIME_SIXTH') ? BLOCK_TIME_SIXTH : 259200; // 3 дня
                        break;
                    default:
                        if ($block_count >= 7) {
                            $progressive_seconds = defined('BLOCK_TIME_SEVENTH_PLUS') ? BLOCK_TIME_SEVENTH_PLUS : 604800; // 7 дней
                        }
                        break;
                }
            }
            
            // Время блокировки для лога
            $time_description = $this->formatBlockTime($progressive_seconds);
            
            // Обновляем или вставляем запись блокировки с учетом счетчика
            $stmt = $this->db->prepare("
                INSERT INTO blocked_ips (ip, block_until, reason, block_count, first_blocked_at) 
                VALUES (?, DATE_ADD(NOW(), INTERVAL ? SECOND), ?, ?, $first_blocked_at)
                ON DUPLICATE KEY UPDATE 
                    block_until = DATE_ADD(NOW(), INTERVAL ? SECOND),
                    reason = ?,
                    block_count = ?
            ");
            $stmt->execute(array(
                $this->ip, 
                $progressive_seconds, 
                $reason . ($block_count > 1 ? " (блокировка #$block_count)" : ""), 
                $block_count,
                $progressive_seconds,
                $reason . ($block_count > 1 ? " (блокировка #$block_count)" : ""),
                $block_count
            ));
            
            // Определяем, нужно ли применять жесткую блокировку
            $apply_hard_blocking = false;
            
            // Применяем жесткую блокировку, если:
            // 1. Это не первая блокировка (счетчик больше 1)
            // 2. Или причина блокировки указывает на агрессивную активность
            if ((defined('HARD_BLOCK_ON_FIRST_VIOLATION') && HARD_BLOCK_ON_FIRST_VIOLATION) || $block_count > 1 || $reason == 'Слишком много запросов') {
    $apply_hard_blocking = true;
}
            
            // Также применяем жесткую блокировку, если IP находится в списке "жестких" блокировок
            if ($this->checkForHardBlockNeeded($this->ip)) {
                $apply_hard_blocking = true;
            }
            
            // Применяем все доступные методы блокировки только если это необходимо
            if ($apply_hard_blocking) {
                // Применяем все внешние блокировки
                $this->applyExternalBlockings($this->ip);
                
                // Для особо злостных нарушителей добавляем в лог жестких блокировок
                if ($reason == 'Слишком много запросов' || $block_count > 3) {
                    $hard_block_reason = $reason . ' (блокировка #' . $block_count . ')';
                    $this->addToHardBlockList($this->ip, $hard_block_reason);
                }
            }
            
            // Обновляем файловый кеш блокировок
            $this->updateBlockedIPsCache();
            
            // Логируем блокировку
            $log_message = date('Y-m-d H:i:s') . " - " . $this->ip . " заблокирован на $time_description: " . 
                          $reason . ($block_count > 1 ? " (повторная блокировка #$block_count)" : "") . "\n";
            @file_put_contents($this->dos_dir . 'blocked_ips.log', $log_message, FILE_APPEND);
        } catch(PDOException $e) {
            error_log("Error blocking IP: " . $e->getMessage());
        }
    }
    
    /**
     * Обновление файлового кеша блокировок
     */
    private function updateBlockedIPsCache() {
		// Если использование файлового кеша полностью отключено, пропускаем обновление
    if (defined('DISABLE_FILE_FALLBACK') && DISABLE_FILE_FALLBACK) {
        return true;
    }
    try {
        $blocked_ips = array();
        $blocked_info = array();
        
        // Если используем Redis
        if ($this->useRedis && $this->redis) {
            try {
                // Получаем все активные блокировки из Redis
                $blockedIpsKey = $this->prefix . 'blocked_ips';
                $now = time();
                
                // Получаем все IP с временем блокировки больше текущего времени
                $blocked_list = $this->redis->zRangeByScore($blockedIpsKey, $now, '+inf', array('WITHSCORES' => true));
                
                if (is_array($blocked_list)) {
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
                } else {
                    error_log("Предупреждение: Redis вернул неожиданный результат при получении заблокированных IP");
                }
            } catch (Exception $e) {
                error_log("Ошибка при получении данных блокировки из Redis: " . $e->getMessage());
            }
        }
        // Если используем MariaDB
        else if ($this->db) {
            // Получаем все активные блокировки
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
            if (rename($tmp_file, $cache_file)) {
                // Успешно обновили кеш блокировок
            } else {
                error_log("Ошибка при переименовании временного файла кеша блокировок");
                // Запасной вариант - прямая запись
                @file_put_contents($cache_file, $content);
            }
        } else {
            error_log("Ошибка при записи во временный файл кеша блокировок");
            // Запасной вариант - прямая запись
            @file_put_contents($cache_file, $content);
        }
        
        $tmp_info_file = $info_file . '.tmp';
        if (file_put_contents($tmp_info_file, $info_content) !== false) {
            if (rename($tmp_info_file, $info_file)) {
                // Успешно обновили информацию о блокировках
            } else {
                error_log("Ошибка при переименовании временного файла информации о блокировках");
                // Запасной вариант - прямая запись
                @file_put_contents($info_file, $info_content);
            }
        } else {
            error_log("Ошибка при записи во временный файл информации о блокировках");
            // Запасной вариант - прямая запись
            @file_put_contents($info_file, $info_content);
        }
        
        return true;
    } catch(Exception $e) {
        error_log("Ошибка при обновлении кеша заблокированных IP: " . $e->getMessage());
        return false;
    }
}
    
    /**
     * Проверка, заблокирован ли IP в .htaccess
     */
    private function isIPBlockedInHtaccess($ip) {
        // Если файл не существует, IP точно не заблокирован
        if (!file_exists($this->htaccessPath)) {
            return false;
        }
        
        // Чтение содержимого файла
        $htaccessContent = file_get_contents($this->htaccessPath);
        
        // Если файл пуст или ошибка чтения
        if ($htaccessContent === false || empty($htaccessContent)) {
            return false;
        }
        
        // Проверка наличия правила блокировки
        return strpos($htaccessContent, "Deny from $ip") !== false;
    }
    
    /**
     * Блокировка IP в .htaccess
     */
    private function blockIPInHtaccess($ip) {
        // Пропускаем, если блокировка через .htaccess отключена
        if (defined('ENABLE_HTACCESS_BLOCKING') && !ENABLE_HTACCESS_BLOCKING) {
            return false;
        }
        
        // Проверяем, не заблокирован ли IP уже
        if ($this->isIPBlockedInHtaccess($ip)) {
            return true;
        }
        
        // Проверка существования файла
        if (!file_exists($this->htaccessPath)) {
            $result = file_put_contents($this->htaccessPath, "");
            
            if ($result === false) {
                error_log("Ошибка при создании файла .htaccess");
                return false;
            }
        }
        
        // Проверка разрешений на запись
        if (!is_writable($this->htaccessPath)) {
            error_log("Файл .htaccess не доступен для записи");
            return false;
        }
        
        // Подготовка правила блокировки
        $rule = "Deny from $ip\n";
        
        // Проверяем содержимое файла
        $currentContent = file_get_contents($this->htaccessPath);
        
        // Если в файле уже что-то есть и последний символ не перенос строки,
        // добавляем перенос строки перед правилом
        if (!empty($currentContent) && substr($currentContent, -1) !== "\n") {
            $rule = "\n" . $rule;
        }
        
        // Попытка записи в файл
        $success = file_put_contents($this->htaccessPath, $rule, FILE_APPEND);
        
        if (!$success) {
            error_log("Ошибка при записи в .htaccess");
            
            // Пробуем другой метод (чтение и запись всего файла)
            $htaccessContent = file_exists($this->htaccessPath) ? file_get_contents($this->htaccessPath) : "";
            
            // Проверяем, нужно ли добавить перенос строки
            if (!empty($htaccessContent) && substr($htaccessContent, -1) !== "\n") {
                $htaccessContent .= "\n";
            }
            
            $htaccessContent .= $rule;
            
            $result = file_put_contents($this->htaccessPath, $htaccessContent);
            
            if ($result !== false && $this->isIPBlockedInHtaccess($ip)) {
                return true;
            } else {
                error_log("Все методы блокировки не удались");
                return false;
            }
        }
        
        // Проверяем, что запись действительно произошла
        if ($this->isIPBlockedInHtaccess($ip)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Функция для проверки валидности IP-адреса (IPv4 или IPv6)
     */
    private function isValidIP($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP);
    }
    
    /**
     * Функция для записи IP в ip.conf в формате "IP 1;" и перезагрузки Nginx
     */
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
            // Перезагрузка Nginx
            $this->reloadNginx();            
            return true;
        }
        
        return false;
    }
    
    /**
     * Перезагрузка Nginx
     */
    private function reloadNginx() {
        // Создаем файл-флаг для внешнего скрипта перезагрузки
        $reload_flag_file = $this->dos_dir . 'nginx_reload_needed';
        file_put_contents($reload_flag_file, date('Y-m-d H:i:s'));
        
        // Попытка использовать exec, если доступно
        if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))))) {
            $output = array();
            $return_var = 0;
            exec('sudo /usr/sbin/nginx -s reload 2>&1', $output, $return_var);
            
            // Логируем результат перезагрузки
            if ($return_var !== 0) {
                error_log("Ошибка при перезагрузке Nginx: " . implode("\n", $output));
            } else {
                error_log("Nginx успешно перезагружен после обновления ip.conf");
            }
        }
    }
    
    /**
     * Функция для блокирования IP через iptables/ip6tables
     */
    /**
 * Функция для блокирования IP через iptables/ip6tables с защитой от дубликатов
 * Оптимизирована для совместимости с PHP 5.6-8.3
 * 
 * @param string $ip IP-адрес для блокировки
 * @return bool Результат операции
 */
public function blockIPWithIptables($ip) {
    // Правильное расположение проверки в начале метода
    if (!function_exists('exec') || in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))))) {
        error_log("Unable to block IP with iptables: exec function is disabled");
        return false;
    }
    
    // Пропускаем, если блокировка через брандмауэр отключена
    if (defined('ENABLE_FIREWALL_BLOCKING') && !ENABLE_FIREWALL_BLOCKING) {
        return false;
    }
    
    // Проверяем, является ли IP валидным
    if (!$this->isValidIP($ip)) {
        error_log("Ошибка: IP $ip не является валидным для блокировки");
        return false;
    }
    
    // Определяем версию IP
    $isIPv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    
    // Массив для хранения результатов
    $results = array();
    $success = true;
    
    // Блокируем порты 80 и 443
    $ports = array(80, 443);
    
    // Записываем в лог исходный IP для отладки
    error_log("Проверка блокировки IP в iptables: $ip, IPv6: " . ($isIPv6 ? "да" : "нет"));
    
    // Проверяем, не находится ли IP в белом списке
    if ($this->isIpInWhitelist($ip)) {
        error_log("IP $ip находится в белом списке. Блокировка пропущена.");
        return false;
    }
    
    // Проверяем, не был ли IP недавно заблокирован (используем кэш объектов)
    $cache_key = 'iptables_' . str_replace(array(':', '.'), '_', $ip);
    if (isset($this->cache[$cache_key]) && $this->cache[$cache_key] > time() - 3600) {
        error_log("IP $ip уже был заблокирован в течение последнего часа. Пропускаем.");
        return true;
    }
    
    foreach ($ports as $port) {
        // Формируем команду для проверки существующего правила
        if ($isIPv6) {
            $commandCheck = "sudo ip6tables -C INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
        } else {
            $commandCheck = "sudo iptables -C INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
        }
        
        // Проверяем, не блокирован ли уже IP для этого порта
        $returnVar = 0;
        $output = array();
        exec($commandCheck, $output, $returnVar);
        
        // Если команда проверки вернула 0, значит правило уже существует
        if ($returnVar === 0) {
            $results[] = "Порт $port: IP уже заблокирован, пропускаем";
            continue;
        }
        
        // Формируем команду для добавления правила
        if ($isIPv6) {
            // Для IPv6 используем ip6tables
            $command = "sudo ip6tables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
        } else {
            // Для IPv4 используем iptables
            $command = "sudo iptables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
        }
        
        // Упрощенное выполнение команды, совместимое с PHP 5.6-8.3
        $output = array();
        $returnVar = 0;
        
        // Устанавливаем лимит времени выполнения (только если функция доступна)
        $original_timeout = ini_get('max_execution_time');
        if (function_exists('set_time_limit') && 
            !in_array('set_time_limit', array_map('trim', explode(',', ini_get('disable_functions'))))) {
            @set_time_limit(30); // 30 секунд для выполнения
        }
        
        // Выполняем команду блокировки
        exec($command . " 2>&1", $output, $returnVar);
        
        // Восстанавливаем исходный тайм-аут
        if (function_exists('set_time_limit') && 
            !in_array('set_time_limit', array_map('trim', explode(',', ini_get('disable_functions'))))) {
            @set_time_limit($original_timeout);
        }
        
        // Проверяем результат выполнения
        if ($returnVar !== 0) {
            $success = false;
            $results[] = "Порт $port: Ошибка блокировки";
            error_log("Ошибка блокировки IP $ip для порта $port: " . implode(", ", $output));
        } else {
            $results[] = "Порт $port: Блокировка успешна";
            error_log("IP $ip успешно заблокирован для порта $port");
        }
    }
    
    // Кэшируем блокировку IP (используем внутренний массив, не сессию)
    $this->cache[$cache_key] = time();
    
    // Если блокировка прошла успешно, добавляем запись в лог
    if ($success) {
        $log_file = $this->dos_dir . 'iptables_blocked.log';
        $log_entry = date('Y-m-d H:i:s') . " - " . $ip . " заблокирован через iptables\n";
        @file_put_contents($log_file, $log_entry, FILE_APPEND);
        
        // Сохраняем правила с 10% вероятностью для снижения нагрузки
        if (mt_rand(1, 10) === 1) {
            $this->saveIptablesRules($isIPv6);
        }
    }
    
    // Периодически запускаем очистку дубликатов (с вероятностью 5%)
    if (defined('CLEANUP_IPTABLES_DUPLICATES') && CLEANUP_IPTABLES_DUPLICATES && mt_rand(1, 20) === 1) {
        $this->cleanupIptablesDuplicates($isIPv6);
    }
    
    return $success;
}
    
    /**
     * Функция для сохранения правил iptables
     */
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
	
private function cleanupIptablesDuplicates($isIPv6) {
    error_log("Starting iptables duplicates cleanup");
    
    // Получаем список всех правил
    $command = $isIPv6 ? 
        "sudo ip6tables -L INPUT -n --line-numbers | grep DROP" : 
        "sudo iptables -L INPUT -n --line-numbers | grep DROP";
    
    $output = array();
    $returnVar = 0;
    exec($command, $output, $returnVar);
    
    if ($returnVar !== 0) {
        error_log("Ошибка при получении списка правил iptables");
        return false;
    }
    
    // Анализируем вывод для поиска дубликатов
    $rules = array();
    foreach ($output as $line) {
        // Извлекаем номер правила и IP-адрес
        if (preg_match('/^(\d+).*?DROP\s+tcp\s+--\s+\*\s+\*\s+([0-9a-f:.]+)/', $line, $matches)) {
            $ruleNum = $matches[1];
            $ipAddr = $matches[2];
            
            if (!isset($rules[$ipAddr])) {
                $rules[$ipAddr] = array();
            }
            
            $rules[$ipAddr][] = $ruleNum;
        }
    }
    
    // Удаляем дублирующиеся правила, оставляя MAX_DUPLICATES_TO_KEEP
    $maxToKeep = defined('MAX_DUPLICATES_TO_KEEP') ? MAX_DUPLICATES_TO_KEEP : 1;
    $removed = 0;
    
    foreach ($rules as $ip => $ruleNums) {
        if (count($ruleNums) > $maxToKeep) {
            // Сортируем по убыванию, чтобы удалять сначала правила с большими номерами
            rsort($ruleNums, SORT_NUMERIC);
            
            // Оставляем только $maxToKeep правил
            $ruleNums = array_slice($ruleNums, $maxToKeep);
            
            // Удаляем лишние правила
            foreach ($ruleNums as $ruleNum) {
                $deleteCommand = $isIPv6 ? 
                    "sudo ip6tables -D INPUT $ruleNum" : 
                    "sudo iptables -D INPUT $ruleNum";
                
                exec($deleteCommand, $delOutput, $delReturnVar);
                
                if ($delReturnVar === 0) {
                    $removed++;
                    error_log("Удалено дублирующееся правило #$ruleNum для IP $ip");
                }
            }
        }
    }
    
    if ($removed > 0) {
        error_log("Очистка дубликатов iptables завершена: удалено $removed правил");
        $this->saveIptablesRules($isIPv6);
    } else {
        error_log("Дублирующихся правил iptables не найдено");
    }
    
    return true;
}	
    
    /**
     * Функция для определения дистрибутива Linux
     */
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
    
    /**
     * Функция для блокировки IP через внешний API
     */
    public function blockIPWithAPI($ip) {
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
    
    /**
     * Функция для проверки, нужно ли применять жесткую блокировку через iptables
     */
    public function checkForHardBlockNeeded($ip) {
        $hard_block_log_file = $this->dos_dir . 'hard_blocked_ips.log';
        
        if (file_exists($hard_block_log_file)) {
            $content = file_get_contents($hard_block_log_file);
            if (strpos($content, $ip) !== false) {
                // Проверяем, что IP еще не заблокирован в iptables
                $isIPv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
                
                $checkCommand = $isIPv6 ? 
                    "sudo ip6tables -C INPUT -s " . escapeshellarg($ip) . " -p tcp --dport 80 -j DROP 2>/dev/null" : 
                    "sudo iptables -C INPUT -s " . escapeshellarg($ip) . " -p tcp --dport 80 -j DROP 2>/dev/null";
                
                $returnVar = 0;
                $output = array();
                exec($checkCommand, $output, $returnVar);
                
                // Если IP еще не заблокирован через iptables (команда вернула не 0)
                if ($returnVar !== 0) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Функция для добавления IP в список для жесткой блокировки
     */
    public function addToHardBlockList($ip, $reason = 'Злостное нарушение') {
        $hard_block_log_file = $this->dos_dir . 'hard_blocked_ips.log';
        $entry = date('Y-m-d H:i:s') . " - " . $ip . " - " . $reason . "\n";
        return file_put_contents($hard_block_log_file, $entry, FILE_APPEND) !== false;
    }
    
    /**
     * Метод периодической очистки (запускать через cron)
     */
    public static function cleanupOldRecords() {
        $monitor = new self();
        
        // Если используем Redis, очищаем записи с истекшим TTL
        if ($monitor->useRedis && $monitor->redis) {
            $monitor->cleanupRedisRecords();
        }
        // Иначе очищаем базу данных
        else {
            $monitor->connectDB();
            
            if (!$monitor->db) return;
            
            try {
                // Удаляем старые записи
                $monitor->db->exec("DELETE FROM suspicious_requests WHERE request_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
                $monitor->db->exec("DELETE FROM blocked_ips WHERE block_until < NOW()");
                $monitor->db->exec("DELETE FROM ip_request_rate WHERE last_request_time < DATE_SUB(NOW(), INTERVAL 10 MINUTE)");
                
                // Обновляем кеш блокировок
                $monitor->updateBlockedIPsCache();
            } catch(PDOException $e) {
                error_log("Error cleaning up records: " . $e->getMessage());
            }
        }
    }
/**
 * Method to check Redis status and diagnose issues
 */
public function diagnoseRedis() {
    if (!$this->redis) {
        error_log("Redis not initialized");
        return false;
    }
    
    try {
        // Test basic Redis functionality
        $test_key = $this->prefix . "test_key";
        $test_value = "test_" . time();
        
        // Try setting a key
        $set_result = $this->redis->set($test_key, $test_value);
        error_log("Redis SET test: " . ($set_result ? "Success" : "Failed"));
        
        // Try getting a key
        $get_result = $this->redis->get($test_key);
        error_log("Redis GET test: " . ($get_result === $test_value ? "Success" : "Failed: $get_result"));
        
        // Try deleting the test key
        $this->redis->del($test_key);
        
        // Check memory usage
        $info = $this->redis->info("memory");
        error_log("Redis memory used: " . (isset($info['used_memory_human']) ? $info['used_memory_human'] : 'unknown'));
        
        // Check active keys
        $total_keys = $this->redis->dbSize();
        error_log("Redis total keys: $total_keys");
        
        // Check blocklist keys
        $blocked_keys = $this->redis->zCard($this->prefix . "blocked_ips");
        error_log("Redis blocked IPs: $blocked_keys");
        
        // Get some sample blocked IPs
        $sample_blocked = $this->redis->zRange($this->prefix . "blocked_ips", 0, 5);
        // Проверка на пустой массив перед использованием implode
        if (!empty($sample_blocked)) {
            error_log("Redis sample blocked IPs: " . implode(", ", $sample_blocked));
        } else {
            error_log("Redis sample blocked IPs: нет заблокированных IP");
        }
        
        return true;
    } catch (Exception $e) {
        error_log("Redis diagnosis error: " . $e->getMessage());
        return false;
    }
}

/**
 * Method to check block status of specific IP
 */
public function checkBlockStatus($ip) {
    error_log("Checking block status for IP: $ip");
    
    // First check file cache
    $cache_file = $this->dos_dir . 'blocked_ips.php';
    $in_file_cache = false;
    
    if (file_exists($cache_file)) {
        include $cache_file;
        if (isset($blocked_ips) && isset($blocked_ips[$ip])) {
            $until = date('Y-m-d H:i:s', $blocked_ips[$ip]);
            error_log("IP $ip found in file cache, blocked until: $until");
            $in_file_cache = true;
        } else {
            error_log("IP $ip not found in file cache");
        }
    }
    
    // Check Redis if available
    if ($this->useRedis && $this->redis) {
        // Check in sorted set
        $score = $this->redis->zScore($this->prefix . "blocked_ips", $ip);
        if ($score !== false) {
            $until_date = date('Y-m-d H:i:s', $score);
            error_log("IP $ip found in Redis sorted set, blocked until: $until_date");
        } else {
            error_log("IP $ip not found in Redis sorted set");
        }
        
        // Check in hash
        $blockKey = $this->prefix . "blocked_ip:$ip";
        if ($this->redis->exists($blockKey)) {
            $blockData = $this->redis->hGetAll($blockKey);
            error_log("IP $ip block data in Redis: " . print_r($blockData, true));
        } else {
            error_log("IP $ip block hash does not exist in Redis");
        }
    }
    
    // Check database if needed
    if (!$this->useRedis || !$this->redis) {
        $this->connectDB();
        if ($this->db) {
            $stmt = $this->db->prepare("SELECT * FROM blocked_ips WHERE ip = ?");
            $stmt->execute(array($ip));
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($result) {
                error_log("IP $ip found in database: " . print_r($result, true));
            } else {
                error_log("IP $ip not found in database");
            }
        }
    }
    
    return $in_file_cache || ($this->useRedis && $this->redis && $this->isIPBlockedRedis($ip));
}

/**
 * Rebuild the Redis block cache from the database and file cache
 */
public function rebuildRedisBlockCache() {
    if (!$this->useRedis || !$this->redis) {
        error_log("Redis not available for rebuilding cache");
        return false;
    }
    
    try {
        $rebuilt = 0;
        $now = time();
        
        // Clear existing Redis block data
        $this->redis->del($this->prefix . "blocked_ips");
        
        // First try to load from the database
        $this->connectDB();
        if ($this->db) {
            $stmt = $this->db->query("
                SELECT ip, UNIX_TIMESTAMP(block_until) as block_until, 
                       reason, block_count, UNIX_TIMESTAMP(first_blocked_at) as first_blocked_at,
                       UNIX_TIMESTAMP(created_at) as created_at
                FROM blocked_ips 
                WHERE block_until > NOW()
            ");
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $blockKey = $this->prefix . "blocked_ip:{$row['ip']}";
                
                // Set hash with all block data
                $this->redis->hMSet($blockKey, array(
                    'block_until' => $row['block_until'],
                    'reason' => $row['reason'],
                    'created_at' => $row['created_at'],
                    'block_count' => $row['block_count'],
                    'first_blocked_at' => $row['first_blocked_at'],
                    'is_blocked' => 1
                ));
                
                // Set TTL
                $ttl = max($row['block_until'] - $now, 86400);
                $this->redis->expire($blockKey, $ttl);
                
                // Add to sorted set
                $this->redis->zAdd($this->prefix . "blocked_ips", $row['block_until'], $row['ip']);
                
                $rebuilt++;
            }
        }
        
        // Then try to load from file cache as fallback
        $cache_file = $this->dos_dir . 'blocked_ips.php';
        if (file_exists($cache_file)) {
            include $cache_file;
            
            if (isset($blocked_ips) && is_array($blocked_ips)) {
                $info_file = $this->dos_dir . 'blocked_info.php';
                $blocked_info = array();
                
                if (file_exists($info_file)) {
                    include $info_file;
                }
                
                foreach ($blocked_ips as $ip => $block_until) {
                    // Skip if already added from database
                    $blockKey = $this->prefix . "blocked_ip:$ip";
                    if ($this->redis->exists($blockKey)) {
                        continue;
                    }
                    
                    // Skip expired blocks
                    if ($block_until <= $now) {
                        continue;
                    }
                    
                    // Get block count from info file if available
                    $block_count = 1;
                    if (isset($blocked_info[$ip]) && isset($blocked_info[$ip]['count'])) {
                        $block_count = $blocked_info[$ip]['count'];
                    }
                    
                    // Set hash with all block data
                    $this->redis->hMSet($blockKey, array(
                        'block_until' => $block_until,
                        'reason' => 'Recovered from file cache',
                        'created_at' => $now - 3600, // Approximate 1 hour ago
                        'block_count' => $block_count,
                        'first_blocked_at' => $now - 86400, // Approximate 1 day ago
                        'is_blocked' => 1
                    ));
                    
                    // Set TTL
                    $ttl = max($block_until - $now, 86400);
                    $this->redis->expire($blockKey, $ttl);
                    
                    // Add to sorted set
                    $this->redis->zAdd($this->prefix . "blocked_ips", $block_until, $ip);
                    
                    $rebuilt++;
                }
            }
        }
        
        error_log("Rebuilt Redis block cache with $rebuilt entries");
        return $rebuilt;
    } catch (Exception $e) {
        error_log("Error rebuilding Redis block cache: " . $e->getMessage());
        return false;
    }
}
/**
 * Надежное подключение к БД
 * Может быть вызвано как альтернатива стандартному connectDB()
 */
private function connectDBSafe() {
    if ($this->db) return true;
    
    // Если Redis работает нормально и флаг USE_REDIS включен,
    // пропускаем подключение к БД
    if ($this->useRedis && $this->redis) {
        try {
            $pingResult = $this->redis->ping();
            if ($pingResult !== false) {
                // Redis доступен, БД не нужна
                return false;
            }
        } catch (Exception $e) {
            error_log("Redis ping error in connectDBSafe(): " . $e->getMessage());
        }
    }
    
    try {
        // Проверка, определены ли константы подключения к БД
        if (!defined('DB_HOST') || !defined('DB_NAME') || !defined('DB_USER') || !defined('DB_PASS')) {
            error_log("DB connection constants not defined");
            return false;
        }
        
        // Пробуем подключиться с таймаутом
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4;connect_timeout=5";
        $this->db = new PDO($dsn, DB_USER, DB_PASS);
        
        // Используем версионно-безопасные настройки атрибутов
        if (defined('PDO::ATTR_ERRMODE')) {
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        }
        $this->db->exec("SET NAMES utf8mb4");
        return true;
    } catch(PDOException $e) {
        error_log("DB Connection Error: " . $e->getMessage());
        $this->db = null; // Убедимся, что объект соединения сброшен
        return false;
    }
}

/**
 * Улучшенное получение IP-адреса клиента с лучшей поддержкой IPv6
 */
private function getClientIPEnhanced() {
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
            $ip_string = $_SERVER[$key];
            
            // Обработка нескольких IP, разделенных запятыми (например, в X-Forwarded-For)
            foreach (explode(',', $ip_string) as $ip) {
                $ip = trim($ip);
                
                // Проверка на валидный IP-адрес (IPv4 или IPv6)
                if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                    // Проверка на корректный IPv6-адрес без локальных или особых адресов
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                        // Проверяем, не является ли это локальным IPv6
                        if (strpos($ip, 'fc00::') !== 0 && strpos($ip, 'fd00::') !== 0 && 
                            strpos($ip, '::1') !== 0) {
                            error_log("Detected valid IPv6: " . $ip);
                            return $ip;
                        }
                    }
                    
                    // Проверка на корректный IPv4-адрес без локальных или особых адресов
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                        // Проверяем, не является ли это локальным или приватным IPv4
                        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
                            continue; // Пропускаем приватные IP-диапазоны
                        }
                        error_log("Detected valid IPv4: " . $ip);
                        return $ip;
                    }
                }
            }
        }
    }
    
    // Если ничего не нашли, возвращаем REMOTE_ADDR (даже если это локальный адрес)
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';
    error_log("Falling back to REMOTE_ADDR: " . $ip);
    return $ip;
}

/**
 * Улучшенная функция нормализации IP-адреса (для IPv6 приводим к полному формату)
 */
private function normalizeIPEnhanced($ip) {
    // Проверяем, является ли IP валидным IPv6
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        // Пытаемся нормализовать IPv6 адрес
        try {
            $packed = @inet_pton($ip);
            if ($packed !== false) {
                $normalized = @inet_ntop($packed);
                if ($normalized !== false) {
                    return $normalized;
                }
            }
            
            // Если произошла ошибка, вернем оригинальный IP
            error_log("IPv6 normalization failed for: " . $ip);
            return $ip;
        } catch (Exception $e) {
            error_log("IPv6 normalization exception: " . $e->getMessage());
            return $ip;
        }
    }
    return $ip;
}

/**
 * Исправление для проверки входа IP в диапазон CIDR
 */
private function ipInCIDREnhanced($ip, $cidr) {
    // Используем временные переменные вместо list() для совместимости с PHP 5.6
    $cidr_parts = explode('/', $cidr);
    $subnet = $cidr_parts[0];
    $mask = isset($cidr_parts[1]) ? $cidr_parts[1] : '';
    
    // Проверка на валидность входных данных
    if (!$this->isValidIP($ip) || !$this->isValidIP($subnet)) {
        return false;
    }
    
    // Если маска не указана или не является числом, считаем что это не соответствует
    if ($mask === '' || !is_numeric($mask)) {
        return false;
    }
    
    // Обрабатываем IPv4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && 
        filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        
        // Преобразуем IP и подсеть в числовой формат
        $ip_decimal = ip2long($ip);
        $subnet_decimal = ip2long($subnet);
        
        if ($ip_decimal === false || $subnet_decimal === false) {
            return false;
        }
        
        // Создаем маску сети
        $mask_decimal = ~((1 << (32 - (int)$mask)) - 1);
        
        // Сравниваем сетевые части
        return ($ip_decimal & $mask_decimal) === ($subnet_decimal & $mask_decimal);
    }
    
    // Обрабатываем IPv6
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && 
        filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        
        try {
            // Преобразуем в бинарный формат, более безопасно для PHP 5.6
            $ip_packed = @inet_pton($ip);
            $subnet_packed = @inet_pton($subnet);
            
            if ($ip_packed === false || $subnet_packed === false) {
                return false;
            }
            
            // Для IPv6 маска может быть максимум 128
            $mask = min((int)$mask, 128);
            
            // Сравниваем только нужное количество бит
            for ($i = 0; $i < 16; $i++) {
                $remaining_bits = $mask - 8 * $i;
                
                if ($remaining_bits <= 0) {
                    // Все биты уже проверены
                    break;
                }
                
                $mask_bits = ($remaining_bits >= 8) ? 8 : $remaining_bits;
                $mask_byte = 0xFF & (0xFF << (8 - $mask_bits));
                
                $ip_byte = ord($ip_packed[$i]);
                $subnet_byte = ord($subnet_packed[$i]);
                
                if (($ip_byte & $mask_byte) !== ($subnet_byte & $mask_byte)) {
                    return false;
                }
            }
            
            return true;
        } catch (Exception $e) {
            error_log("IPv6 CIDR check error: " . $e->getMessage());
            return false;
        }
    }
    
    return false;
}

/**
 * Запасной метод для мониторинга с отказоустойчивостью
 */
public function monitorRequestFallback() {
    // Если IP в белом списке, пропускаем всё
    if ($this->isIpInWhitelist($this->ip)) {
        return;
    }
    
    // Проверка и применение автоматической жесткой блокировки
    if (method_exists($this, 'checkAndApplyAutoHardBlock')) {
        $this->checkAndApplyAutoHardBlock();
    }
    
    // Если используем Redis и он доступен
    if ($this->useRedis && $this->redis) {
        try {
            // Тестируем соединение с Redis перед использованием
            $testPing = $this->redis->ping();
            if ($testPing === false) {
                error_log("Redis ping failed in monitorRequestFallback(), falling back to database");
                $this->useRedis = false;
                $this->redis = null;
            }
        } catch (Exception $e) {
            error_log("Redis error in monitorRequestFallback(): " . $e->getMessage());
            $this->useRedis = false;
            $this->redis = null;
        }
    }
    
    // Если Redis используется и доступен
    if ($this->useRedis && $this->redis) {
        try {
            // Проверяем и обновляем частоту запросов IP через Redis
            if (method_exists($this, 'checkIPRateLimitRedis') && $this->checkIPRateLimitRedis()) {
                if (method_exists($this, 'logRequestRedis')) {
                    $this->logRequestRedis();
                }
                if (method_exists($this, 'blockIPRedis')) {
                    $this->blockIPRedis(BLOCK_TIME_FIRST, 'Превышен лимит запросов (защита от подмены сессии)');
                }
                $this->redirectToUnlockPage();
                exit;
            }
            
            // Проверка на слишком частые запросы страниц
            if (method_exists($this, 'checkPageRateLimitRedis') && $this->checkPageRateLimitRedis()) {
                if (method_exists($this, 'logRequestRedis')) {
                    $this->logRequestRedis();
                }
                if (method_exists($this, 'blockIPRedis')) {
                    $this->blockIPRedis(BLOCK_TIME_FIRST, 'Превышен лимит запросов страниц');
                }
                $this->redirectToUnlockPage();
                exit;
            }
            
            // Проверяем только подозрительные запросы
            if (method_exists($this, 'isRequestSuspicious') && $this->isRequestSuspicious()) {
                if (method_exists($this, 'logRequestRedis')) {
                    $this->logRequestRedis(); // Логируем только подозрительные запросы
                }
                if (method_exists($this, 'checkSuspiciousActivityRedis')) {
                    $this->checkSuspiciousActivityRedis();
                }
            }
            
            // Проверка состояния памяти Redis и очистка при необходимости
            if (method_exists($this, 'checkRedisMemory')) {
                $this->checkRedisMemory();
            }
        } catch (Exception $e) {
            error_log("Error in Redis monitoring: " . $e->getMessage());
            // Если ошибка при работе с Redis, пробуем использовать базу данных
            $this->useRedis = false;
            // Вызываем fallback на базу данных
            $this->fallbackToDatabaseEnhanced();
        }
    }
    // Если Redis не используется или недоступен, используем стандартный метод
    else {
        $this->fallbackToDatabaseEnhanced();
    }
}

/**
 * Усиленный запасной метод для использования БД вместо Redis
 */
private function fallbackToDatabaseEnhanced() {
    try {
        // Проверка через БД, независимая от сессии
        if (method_exists($this, 'checkIPRateLimitInDatabase') && $this->checkIPRateLimitInDatabase()) {
            if (method_exists($this, 'connectDBSafe')) {
                $this->connectDBSafe();
            } else {
                $this->connectDB();
            }
            
            if ($this->db) {
                if (method_exists($this, 'logRequest')) {
                    $this->logRequest();
                }
                if (method_exists($this, 'blockIP')) {
                    $this->blockIP(3600, 'Превышен лимит запросов (защита от подмены сессии)');
                }
                $this->redirectToUnlockPage();
                exit;
            } else {
                // Проверяем настройку DISABLE_FILE_FALLBACK
                if (!defined('DISABLE_FILE_FALLBACK') || !DISABLE_FILE_FALLBACK) {
                    // Если файловый кеш не отключен, используем его
                    $this->blockIPFallback(3600, 'Превышен лимит запросов (файловая блокировка)');
                }
                $this->redirectToUnlockPage();
                exit;
            }
        }
        
        // Проверка на слишком частые запросы страниц
        if (method_exists($this, 'checkPageRateLimit') && $this->checkPageRateLimit()) {
            // Если лимит превышен, блокируем IP
            if (method_exists($this, 'connectDBSafe')) {
                $this->connectDBSafe();
            } else {
                $this->connectDB();
            }
            
            if ($this->db) {
                if (method_exists($this, 'logRequest')) {
                    $this->logRequest();
                }
                if (method_exists($this, 'blockIP')) {
                    $this->blockIP(3600, 'Превышен лимит запросов страниц (>3 в секунду)');
                }
            } else {
                // Проверяем настройку DISABLE_FILE_FALLBACK
                if (!defined('DISABLE_FILE_FALLBACK') || !DISABLE_FILE_FALLBACK) {
                    // Если файловый кеш не отключен, используем его
                    $this->blockIPFallback(3600, 'Превышен лимит запросов страниц (файловая блокировка)');
                }
            }
            
            $this->redirectToUnlockPage();
            exit;
        }
        
        // Проверяем только подозрительные запросы
        if (method_exists($this, 'isRequestSuspicious') && $this->isRequestSuspicious()) {
            if (method_exists($this, 'connectDBSafe')) {
                $this->connectDBSafe(); // Подключаемся к БД только для подозрительных IP
            } else {
                $this->connectDB();
            }
            
            // Создаем необходимые таблицы, если соединение успешно
            if ($this->db) {
                if (method_exists($this, 'initializeTables')) {
                    $this->initializeTables();
                }
                if (method_exists($this, 'logRequest')) {
                    $this->logRequest(); // Логируем только подозрительные запросы
                }
                if (method_exists($this, 'checkSuspiciousActivity')) {
                    $this->checkSuspiciousActivity();
                }
            } else {
                // Если нет соединения с БД, логируем в файл только если файловый режим не отключен
                if (!defined('DISABLE_FILE_FALLBACK') || !DISABLE_FILE_FALLBACK) {
                    $this->logRequestToFile();
                }
            }
        }
    } catch (Exception $e) {
        error_log("Error in database monitoring: " . $e->getMessage());
    }
}

/**
 * Запасной метод для блокировки IP, если ни Redis, ни БД не доступны
 */
/**
 * Запасной метод для блокировки IP, если ни Redis, ни БД не доступны
 */
private function blockIPFallback($seconds, $reason) {
    try {
        // Получаем текущие блокировки
        $cache_file = $this->dos_dir . 'blocked_ips.php';
        $blocked_ips = array();
        
        if (file_exists($cache_file)) {
            include $cache_file;
        }
        
        // Устанавливаем время блокировки
        $blocked_ips[$this->ip] = time() + $seconds;
        
        // Формируем содержимое файла
        $content = "<?php\n\$blocked_ips = " . var_export($blocked_ips, true) . ";\n";
        
        // Сохраняем файл
        $tmp_file = $cache_file . '.tmp';
        if (file_put_contents($tmp_file, $content) !== false) {
            rename($tmp_file, $cache_file);
        } else {
            // Прямая запись, если временный файл не удалось создать
            file_put_contents($cache_file, $content);
        }
        
        // Логируем блокировку
        $log_message = date('Y-m-d H:i:s') . " - " . $this->ip . " заблокирован на " . 
                      $this->formatBlockTime($seconds) . ": " . $reason . "\n";
        @file_put_contents($this->dos_dir . 'blocked_ips.log', $log_message, FILE_APPEND);
        
        return true;
    } catch (Exception $e) {
        error_log("Ошибка при файловой блокировке IP: " . $e->getMessage());
        return false;
    }
}

/**
 * Запасной метод для логирования запросов в файл
 */
private function logRequestToFile() {
    try {
        $log_file = $this->dos_dir . 'suspicious_requests.log';
        
        // Ограничиваем размер лог-файла
        if (file_exists($log_file) && filesize($log_file) > 10485760) { // 10MB
            rename($log_file, $log_file . '.old');
        }
        
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Empty';
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
        
        $log_entry = date('Y-m-d H:i:s') . " - " . $this->ip . " - " . 
                    $user_agent . " - " . $request_uri . "\n";
        
        @file_put_contents($log_file, $log_entry, FILE_APPEND);
        
        return true;
    } catch (Exception $e) {
        error_log("Ошибка при логировании запроса в файл: " . $e->getMessage());
        return false;
    }
}

/**
 * Добавьте этот метод для обработки ошибок PHP
 * Метод должен быть вызван в конструкторе класса
 */
private function setupErrorHandling() {
	// Проверяем, отключено ли перехватывание ошибок
    if (defined('DISABLE_ERROR_HANDLING') && DISABLE_ERROR_HANDLING) {
        return; // Выходим из метода без установки обработчиков
    }
    error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
    ini_set('display_errors', 0);
    // Регистрируем обработчик ошибок
    set_error_handler(function($errno, $errstr, $errfile, $errline) {
        // Логируем ошибку
        error_log("PHP Error in security_monitor.php [$errno]: $errstr in $errfile on line $errline");
        
        // Разрешаем стандартному обработчику продолжить работу
        return false;
    });
    
    // Регистрируем обработчик исключений
    set_exception_handler(function($exception) {
        error_log("Uncaught exception in security_monitor.php: " . $exception->getMessage() . 
                 " in " . $exception->getFile() . " on line " . $exception->getLine());
    });
}

/**
 * Безопасный запуск сессии
 */
private function safeStartSession() {
    // Проверяем, не запущена ли уже сессия
    if (session_status() == PHP_SESSION_NONE) {
        // Устанавливаем безопасные параметры сессии
        @ini_set('session.use_cookies', 1);
        @ini_set('session.use_only_cookies', 1);
        
        // Попытка запуска сессии с перехватом ошибок
        try {
            @session_start();
        } catch (Exception $e) {
            error_log("Session start error: " . $e->getMessage());
        }
        
        // Проверяем, запустилась ли сессия
        if (session_status() != PHP_SESSION_ACTIVE) {
            error_log("Failed to start session");
        }
    }
}

/**
 * Безопасная проверка условий
 */
private function runSafeChecks() {
    try {
        // Пробуем безопасно запустить сессию
        $this->safeStartSession();
        
        // Проверяем подключение к Redis
        if ($this->useRedis && $this->redis) {
            try {
                $pingResult = $this->redis->ping();
                if ($pingResult === false) {
                    error_log("Redis ping failed in runSafeChecks(), falling back to database");
                    $this->useRedis = false;
                    $this->redis = null;
                }
            } catch (Exception $e) {
                error_log("Redis error in runSafeChecks(): " . $e->getMessage());
                $this->useRedis = false;
                $this->redis = null;
            }
        }
        
        // Проверяем IP на наличие в белом списке
        if ($this->isIpInWhitelist($this->ip)) {
            return false;
        }
        
        // Проверяем, заблокирован ли IP
        $blocked = false;
        
        // Проверяем через Redis, если доступен
        if ($this->useRedis && $this->redis && method_exists($this, 'isIPBlockedRedis')) {
            try {
                $blocked = $this->isIPBlockedRedis($this->ip);
            } catch (Exception $e) {
                error_log("Error checking IP block status in Redis: " . $e->getMessage());
            }
        }
        
        // Проверяем через файл кеша
        if (!$blocked) {
            $cache_file = $this->dos_dir . 'blocked_ips.php';
            if (file_exists($cache_file)) {
                include $cache_file;
                if (isset($blocked_ips) && isset($blocked_ips[$this->ip]) && $blocked_ips[$this->ip] > time()) {
                    $blocked = true;
                }
            }
        }
        
        // Если IP заблокирован, перенаправляем на страницу разблокировки
        if ($blocked) {
            error_log("IP {$this->ip} is blocked, redirecting");
            $this->redirectToUnlockPage();
            exit;
        }
        
        return true;
    } catch (Exception $e) {
        error_log("Error in runSafeChecks: " . $e->getMessage());
        return false;
    }
}
/**
 * Проверка частоты запросов IP через файловую систему (работает без Cookies)
 */
private function checkIPRateLimitFile() {
    // Пропускаем, если файловое отслеживание отключено
    if (!defined('ENABLE_FILE_IP_TRACKING') || !ENABLE_FILE_IP_TRACKING) {
        return false;
    }
    
    try {
        // Подготовка пути к файлу для хранения запросов
        $ip_requests_dir = $this->dos_dir . (defined('FILE_IP_TRACKING_DIR') ? FILE_IP_TRACKING_DIR : 'ip_requests/');
        
        // Создаем директорию, если не существует
        if (!is_dir($ip_requests_dir)) {
            if (!@mkdir($ip_requests_dir, 0755, true)) {
                error_log("Не удалось создать директорию для отслеживания IP: " . $ip_requests_dir);
                return false;
            }
        }
        
        // Безопасный идентификатор IP для имени файла
        $ip_safe = str_replace([':', '.'], '_', $this->ip);
        $file_path = $ip_requests_dir . $ip_safe . '.txt';
        
        $current_time = microtime(true);
        $request_times = array();
        
        // Читаем существующие данные о запросах, если файл существует
        if (file_exists($file_path)) {
            $content = @file_get_contents($file_path);
            if ($content !== false) {
                $lines = explode("\n", trim($content));
                foreach ($lines as $line) {
                    if (is_numeric($line)) {
                        $request_time = (float)$line;
                        // Сохраняем только запросы за последние 5 секунд
                        if ($current_time - $request_time <= 5) {
                            $request_times[] = $request_time;
                        }
                    }
                }
            }
        }
        
        // Добавляем текущее время запроса
        $request_times[] = $current_time;
        
        // Подсчитываем количество запросов за последнюю секунду
        $requests_last_second = 0;
        foreach ($request_times as $time) {
            if ($current_time - $time <= 1) {
                $requests_last_second++;
            }
        }
        
        // Записываем обновленные данные о запросах
        $content = implode("\n", $request_times);
        if (@file_put_contents($file_path, $content) === false) {
            error_log("Не удалось записать данные о запросах IP: " . $this->ip);
        }
        
        // Устанавливаем TTL для файла (удаляем старые файлы)
        $this->cleanupOldIPRequestFiles();
        
        // Определяем лимит запросов
        $rate_limit = defined('MAX_REQUESTS_PER_SECOND') ? MAX_REQUESTS_PER_SECOND : 4;
        
        // Проверяем, не превышен ли лимит запросов в секунду
        if ($requests_last_second > $rate_limit) {
            error_log("File-based IP rate limit exceeded: " . $this->ip . " - " . $requests_last_second . " requests per second");
            return true; // Лимит превышен
        }
        
        return false; // Лимит не превышен
    } catch (Exception $e) {
        error_log("Ошибка при проверке частоты запросов IP через файл: " . $e->getMessage());
        return false;
    }
}

/**
 * Очистка старых файлов отслеживания IP
 */
private function cleanupOldIPRequestFiles() {
    // Выполняем очистку с вероятностью 5%, чтобы не делать это при каждом запросе
    if (mt_rand(1, 100) > 5) {
        return;
    }
    
    try {
        $ip_requests_dir = $this->dos_dir . (defined('FILE_IP_TRACKING_DIR') ? FILE_IP_TRACKING_DIR : 'ip_requests/');
        if (!is_dir($ip_requests_dir)) {
            return;
        }
        
        $current_time = time();
        $ttl = defined('FILE_IP_TTL') ? FILE_IP_TTL : 300; // 5 минут по умолчанию
        
        // Открываем директорию
        $dir = opendir($ip_requests_dir);
        if ($dir) {
            while (($file = readdir($dir)) !== false) {
                if ($file == '.' || $file == '..') {
                    continue;
                }
                
                $file_path = $ip_requests_dir . $file;
                
                // Удаляем файлы старше TTL
                if (is_file($file_path) && $current_time - filemtime($file_path) > $ttl) {
                    @unlink($file_path);
                }
            }
            
            closedir($dir);
        }
    } catch (Exception $e) {
        error_log("Ошибка при очистке старых файлов IP: " . $e->getMessage());
    }
}

/**
 * Применение прямой блокировки через внешние механизмы
 */
private function applyDirectBlockings($ip, $request_count = 0) {
    // Логируем попытку блокировки
    error_log("Applying direct blockings for IP {$ip} with {$request_count} req/sec");
    
    // Блокируем IP через htaccess, если этот механизм включен
    if (defined('ENABLE_HTACCESS_BLOCKING') && ENABLE_HTACCESS_BLOCKING) {
        $this->blockIPInHtaccess($ip);
    }
    
    // Блокируем IP через iptables, если этот механизм включен
    if (defined('ENABLE_FIREWALL_BLOCKING') && ENABLE_FIREWALL_BLOCKING) {
        $this->blockIPWithIptables($ip);
    }
    
    // Блокируем IP через Nginx, если этот механизм включен
    if (defined('ENABLE_NGINX_BLOCKING') && ENABLE_NGINX_BLOCKING) {
        $this->logIPToConf($ip);
    }
    
    // Блокируем IP через API, если этот механизм включен
    if (defined('ENABLE_API_BLOCKING') && ENABLE_API_BLOCKING) {
        $this->blockIPWithAPI($ip);
    }
    
    // Пытаемся также записать в файловый кеш для полноты
    try {
        $this->blockIPFallback(3600, "Превышен лимит запросов ({$request_count} в секунду)");
    } catch (Exception $e) {
        error_log("Could not update blocked_ips.php: " . $e->getMessage());
    }
    
    return true;
}
}

// Использование класса
if (!defined('DISABLE_SECURITY_MONITOR')) {
    $monitor = new LightSecurityMonitor();
    $monitor->monitorRequest();
}
