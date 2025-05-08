<?php
// Проверка авторизации
require_once 'settings.php';

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

// Проверка сообщений из сессии
session_start();

// Функция для безопасного вывода описаний констант с поддержкой тега <br>
function echoConstantDescription($description) {
    // Применяем htmlspecialchars для всего, кроме <br>
    $safe = htmlspecialchars($description, ENT_QUOTES, 'UTF-8');
    // Затем заменяем обратно наши безопасные теги
    $safe = str_replace('&lt;br&gt;', '<br>', $safe);
    echo $safe;
}

// Функция для безопасного вывода значений
function e($value) {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

// Функция для получения текущего значения из settings.php
function getCurrentValue($constantName) {
    // Прямое чтение из файла
    $settingsContent = file_get_contents('settings.php');
    
    // Ищем определение константы в файле
    if (preg_match("/define\('$constantName',\s*(.*?)\);/", $settingsContent, $matches)) {
        $rawValue = trim($matches[1]);
        
        // Обработка булевых значений
        if ($rawValue === 'true' || $rawValue === 'false') {
            return $rawValue;
        }
        
        // Обработка числовых значений
        if (is_numeric($rawValue)) {
            return $rawValue;
        }
        
        // Обработка строковых значений (в одинарных кавычках)
        if (preg_match("/^'(.*)'$/", $rawValue, $strMatches)) {
            return $strMatches[1];
        }
        
        return $rawValue;
    }
    
    // Если не нашли в файле, используем константу
    if (defined($constantName)) {
        $value = constant($constantName);
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        return $value;
    }
    
    return '';
}
// Предустановленные режимы настроек
$presetModes = [
    'light' => [
        'title' => 'Слабый режим (минимальное воздействие)',
        'description' => 'Этот режим минимально влияет на пользователей, используя преимущественно временные блокировки на уровне приложения и троттлинг. Жесткие блокировки отключены, а пороги обнаружения атак установлены достаточно высоко.',
        'settings' => [
            'HARD_BLOCK_ON_FIRST_VIOLATION' => 'false',
            'BLOCK_TIME_FIRST' => '900',
            'BLOCK_TIME_SECOND' => '1800',
            'BLOCK_TIME_THIRD' => '3600',
            'BLOCK_TIME_FOURTH' => '7200',
            'BLOCK_TIME_FIFTH' => '14400',
            'BLOCK_TIME_SIXTH' => '28800',
            'BLOCK_TIME_SEVENTH_PLUS' => '86400',
            'MAX_REQUESTS_PER_SECOND' => '4',
            'MAX_REQUESTS_PER_MINUTE' => '60',
            'MAX_REQUESTS_PER_IP' => '300',
            'RATE_CHECK_WINDOW' => '10',
            'RATE_THRESHOLD' => '20',
            'AUTO_HARD_BLOCK_ENABLED' => 'false',
            'THROTTLING_ENABLED' => 'true',
            'THROTTLING_APPLY_DELAY' => 'true',
            'THROTTLING_BLOCK_ON_HARD_LIMIT' => 'false',
            'DISABLE_COOKIE_SECURITY_CHECK' => 'false',
            'ENABLE_TIMING_CHECK' => 'false',
            'ENABLE_UA_CONSISTENCY_CHECK' => 'false'
        ]
    ],
    'medium' => [
        'title' => 'Средний режим (сбалансированный)',
        'description' => 'Этот режим обеспечивает сбалансированную защиту, используя комбинацию механизмов блокировки. Жесткая блокировка активируется автоматически при массовых атаках, а пороги обнаружения установлены на среднем уровне.',
        'settings' => [
            'HARD_BLOCK_ON_FIRST_VIOLATION' => 'false',
            'BLOCK_TIME_FIRST' => '3600',
            'BLOCK_TIME_SECOND' => '10800',
            'BLOCK_TIME_THIRD' => '21600',
            'BLOCK_TIME_FOURTH' => '43200',
            'BLOCK_TIME_FIFTH' => '86400',
            'BLOCK_TIME_SIXTH' => '259200',
            'BLOCK_TIME_SEVENTH_PLUS' => '604800',
            'MAX_REQUESTS_PER_SECOND' => '3',
            'MAX_REQUESTS_PER_MINUTE' => '40',
            'MAX_REQUESTS_PER_IP' => '200',
            'RATE_CHECK_WINDOW' => '10',
            'RATE_THRESHOLD' => '20',
            'AUTO_HARD_BLOCK_ENABLED' => 'true',
            'AUTO_HARD_BLOCK_THRESHOLD' => '100',
            'THROTTLING_ENABLED' => 'true',
            'THROTTLING_APPLY_DELAY' => 'true',
            'THROTTLING_BLOCK_ON_HARD_LIMIT' => 'true',
            'DISABLE_COOKIE_SECURITY_CHECK' => 'false',
            'DISABLE_COOKIE_SECURITY_BLOCKING' => 'false',
            'ENABLE_TIMING_CHECK' => 'true',
            'TIMING_MIN_REQUESTS' => '5',
            'TIMING_DISPERSION_MIN' => '0.2',
            'ENABLE_UA_CONSISTENCY_CHECK' => 'true',
            'UA_MAX_DIFFERENT' => '5',
            'UA_CHECK_WINDOW' => '3600'
        ]
    ],
    'strict' => [
        'title' => 'Жесткий режим (максимальная защита)',
        'description' => 'Этот режим обеспечивает максимальную защиту от атак, используя все доступные механизмы блокировки с низкими порогами обнаружения атак. Жесткая блокировка применяется с первого нарушения, а времена блокировки значительно увеличены.',
        'settings' => [
            'HARD_BLOCK_ON_FIRST_VIOLATION' => 'true',
            'BLOCK_TIME_FIRST' => '10800',
            'BLOCK_TIME_SECOND' => '21600',
            'BLOCK_TIME_THIRD' => '43200',
            'BLOCK_TIME_FOURTH' => '86400',
            'BLOCK_TIME_FIFTH' => '259200',
            'BLOCK_TIME_SIXTH' => '604800',
            'BLOCK_TIME_SEVENTH_PLUS' => '2592000',
            'MAX_REQUESTS_PER_SECOND' => '2',
            'MAX_REQUESTS_PER_MINUTE' => '20',
            'MAX_REQUESTS_PER_IP' => '60',
            'RATE_CHECK_WINDOW' => '10',
            'RATE_THRESHOLD' => '20',
            'AUTO_HARD_BLOCK_ENABLED' => 'true',
            'AUTO_HARD_BLOCK_THRESHOLD' => '50',
            'AUTO_HARD_BLOCK_NOTIFY_ADMIN' => 'true',
            'THROTTLING_ENABLED' => 'true',
            'THROTTLING_APPLY_DELAY' => 'true',
            'THROTTLING_BLOCK_ON_HARD_LIMIT' => 'true',
            'DISABLE_COOKIE_SECURITY_CHECK' => 'false',
            'DISABLE_COOKIE_SECURITY_BLOCKING' => 'false',
            'FORCE_BLOCKING_ON_FAILURE' => 'true',
            'ESCALATE_BLOCK_ON_REPEAT_ATTEMPTS' => 'true',
            'ATTEMPTS_BEFORE_ESCALATION' => '1',
            'ENABLE_TIMING_CHECK' => 'true',
            'TIMING_MIN_REQUESTS' => '3',
            'TIMING_DISPERSION_MIN' => '0.3',
            'ENABLE_UA_CONSISTENCY_CHECK' => 'true',
            'UA_MAX_DIFFERENT' => '3',
            'UA_CHECK_WINDOW' => '1800'
        ]
    ]
];
// Обработка применения пресета
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['apply_preset']) && isset($_POST['preset_mode'])) {
    $presetMode = $_POST['preset_mode'];
    
    if (isset($presetModes[$presetMode])) {
        $settingsFile = file_get_contents('settings.php');
        
        foreach ($presetModes[$presetMode]['settings'] as $key => $value) {
            // Обработка булевых значений
            if ($value === 'true' || $value === 'false') {
                $pattern = "/define\('$key',\s*(true|false)\);/";
                $replacement = "define('$key', $value);";
            } 
            // Обработка числовых значений
            else if (is_numeric($value) && strpos($value, '"') === false && strpos($value, "'") === false) {
                $pattern = "/define\('$key',\s*[0-9.]+\);/";
                $replacement = "define('$key', $value);";
            }
            // Обработка строковых значений
            else {
                $safeValue = str_replace("'", "\'", $value);
                $pattern = "/define\('$key',\s*'[^']*'\);/";
                $replacement = "define('$key', '$safeValue');";
            }
            
            $settingsFile = preg_replace($pattern, $replacement, $settingsFile);
        }
        
        if (file_put_contents('settings.php', $settingsFile)) {
            $message = 'Режим "' . $presetModes[$presetMode]['title'] . '" успешно применен!';
            $messageType = 'success';
        } else {
            $message = 'Ошибка при сохранении настроек. Проверьте права доступа к файлу.';
            $messageType = 'error';
        }
    } else {
        $message = 'Неизвестный режим настроек!';
        $messageType = 'error';
    }
}

// Обработка формы при сохранении
$message = isset($message) ? $message : '';
$messageType = isset($messageType) ? $messageType : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_settings'])) {
    $settingsFile = file_get_contents('settings.php');
    $isModified = false;
    
    foreach ($_POST as $key => $value) {
        if ($key !== 'save_settings' && $key !== 'current_tab') {
            // Обработка булевых значений
            if ($value === 'true' || $value === 'false') {
                $pattern = "/define\('$key',\s*(true|false)\);/";
                $replacement = "define('$key', $value);";
            } 
            // Обработка числовых значений
            else if (is_numeric($value) && strpos($value, '"') === false && strpos($value, "'") === false) {
                $pattern = "/define\('$key',\s*[0-9.]+\);/";
                $replacement = "define('$key', $value);";
            }
            // Обработка строковых значений
            else {
                $safeValue = str_replace("'", "\'", $value);
                $pattern = "/define\('$key',\s*'[^']*'\);/";
                $replacement = "define('$key', '$safeValue');";
            }
            
            $newSettingsFile = preg_replace($pattern, $replacement, $settingsFile);
            if ($newSettingsFile !== $settingsFile) {
                $settingsFile = $newSettingsFile;
                $isModified = true;
            }
        }
    }
    
    if ($isModified) {
        if (file_put_contents('settings.php', $settingsFile)) {
            $message = 'Настройки успешно сохранены!';
            $messageType = 'success';
            
            // Сохраним сообщение в сессии
            $_SESSION['message'] = $message;
            $_SESSION['messageType'] = $messageType;
            
            // Определяем, с какой вкладки пришел запрос
            $currentTab = isset($_POST['current_tab']) ? $_POST['current_tab'] : $activeTab;
            
            // Перенаправление на нужную вкладку
            header('Location: ' . $_SERVER['PHP_SELF'] . '?tab=' . urlencode($currentTab));
            exit;
        } else {
            $message = 'Ошибка при сохранении настроек. Проверьте права доступа к файлу.';
            $messageType = 'error';
        }
    } else {
        $message = 'Изменений не обнаружено или шаблоны регулярных выражений не соответствуют формату в файле.';
        $messageType = 'error';
    }
}
// Группировка настроек по категориям с добавлением новых параметров
$settingsCategories = [
    'предустановки' => [
        'title' => 'Предустановленные режимы',
        'icon' => 'shield-lock',
        'settings' => [] // Пустой массив, т.к. здесь будут кнопки для пресетов
    ],
    'база_данных' => [
        'title' => 'База данных',
        'icon' => 'database',
        'settings' => [
            'DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS'
        ]
    ],
    'recaptcha' => [
        'title' => 'reCAPTCHA',
        'icon' => 'shield-check',
        'settings' => [
            'RECAPTCHA_SITE_KEY', 'RECAPTCHA_SECRET_KEY'
        ]
    ],
    'администратор' => [
        'title' => 'Администратор',
        'icon' => 'user',
        'settings' => [
            'ADMIN_USERNAME', 'ADMIN_PASSWORD'
        ]
    ],
    'блокировка' => [
        'title' => 'Механизмы блокировки',
        'icon' => 'lock',
        'settings' => [
            'ENABLE_HTACCESS_BLOCKING', 'ENABLE_NGINX_BLOCKING', 'ENABLE_FIREWALL_BLOCKING', 
            'ENABLE_API_BLOCKING', 'HARD_BLOCK_ON_FIRST_VIOLATION', 'EXPORT_BLOCKED_IPS_TO_FILES',
            'BLOCKED_IPV4_FILE', 'BLOCKED_IPV6_FILE'
        ]
    ],
    'эскалация' => [
        'title' => 'Прогрессивная блокировка',
        'icon' => 'trending-up',
        'settings' => [
            'ESCALATE_BLOCK_ON_REPEAT_ATTEMPTS', 'ATTEMPTS_BEFORE_ESCALATION', 
            'BLOCK_ESCALATION_COOLDOWN'
        ]
    ],
    'iptables' => [
        'title' => 'IPTables',
        'icon' => 'server',
        'settings' => [
            'CLEANUP_IPTABLES_DUPLICATES', 'MAX_DUPLICATES_TO_KEEP'
        ]
    ],
    'api_блокировка' => [
        'title' => 'API блокировка',
        'icon' => 'link',
        'settings' => [
            'API_BLOCK_URL', 'API_BLOCK_KEY', 'API_USER_AGENT'
        ]
    ],
	'нагрузка' => [
        'title' => 'Управление нагрузкой',
        'icon' => 'activity',
        'settings' => [
            'LOAD_BALANCING_ENABLED', 'MAX_CONCURRENT_REQUESTS', 'REQUEST_PROCESSING_DELAY',
            'DYNAMIC_DELAY_ENABLED', 'LOAD_THRESHOLD', 'MAX_DYNAMIC_DELAY'
        ]
    ],
    'системные' => [
        'title' => 'Системные настройки',
        'icon' => 'settings',
        'settings' => [
            'SEM_KEY_PATH', 'LOAD_TRACKING_FILE', 'DISABLE_ERROR_HANDLING'
        ]
    ],
    'redis' => [
        'title' => 'Redis',
        'icon' => 'database',
        'settings' => [
            'USE_REDIS', 'REDIS_HOST', 'REDIS_PORT', 'REDIS_PASSWORD', 'REDIS_DATABASE', 
            'REDIS_PREFIX', 'REDIS_TTL_IP_REQUEST_RATE', 'REDIS_TTL_SUSPICIOUS_REQUEST',
            'REDIS_MEMORY_LIMIT_PERCENT', 'REDIS_EMERGENCY_MEMORY_PERCENT'
        ]
    ],
    'лимиты' => [
        'title' => 'Лимиты запросов',
        'icon' => 'bar-chart-2',
        'settings' => [
            'MAX_REQUESTS_PER_SECOND', 'MAX_REQUESTS_PER_MINUTE', 'MAX_REQUESTS_PER_IP',
            'RATE_CHECK_WINDOW', 'RATE_THRESHOLD'
        ]
    ],
    'блок_время' => [
        'title' => 'Время блокировки',
        'icon' => 'clock',
        'settings' => [
            'BLOCK_TIME_FIRST', 'BLOCK_TIME_SECOND', 'BLOCK_TIME_THIRD', 'BLOCK_TIME_FOURTH',
            'BLOCK_TIME_FIFTH', 'BLOCK_TIME_SIXTH', 'BLOCK_TIME_SEVENTH_PLUS'
        ]
    ],
    'логи' => [
        'title' => 'Логи и кэш',
        'icon' => 'file-text',
        'settings' => [
            'LOG_MAX_SIZE', 'LOG_MAX_AGE', 'CACHE_FILES_MAX_AGE'
        ]
    ],
	'обслуживание' => [
        'title' => 'Обслуживание',
        'icon' => 'tool',
        'settings' => [
            'CLEANUP_OPTIMIZE_TABLES', 'CLEANUP_SYNC_DATABASES', 'DISABLE_RDNS_LOOKUP'
        ]
    ],
    'автоблок' => [
        'title' => 'Автоматическая блокировка',
        'icon' => 'shield',
        'settings' => [
            'AUTO_HARD_BLOCK_ENABLED', 'AUTO_HARD_BLOCK_THRESHOLD', 'AUTO_HARD_BLOCK_ACTION'
        ]
    ],
    'уведомления' => [
        'title' => 'Уведомления',
        'icon' => 'mail',
        'settings' => [
            'AUTO_HARD_BLOCK_NOTIFY_ADMIN', 'AUTO_HARD_BLOCK_ADMIN_EMAIL', 'AUTO_HARD_BLOCK_EMAIL_SUBJECT',
            'AUTO_HARD_BLOCK_EMAIL_FROM', 'AUTO_HARD_BLOCK_NOTIFY_INTERVAL'
        ]
    ],
    'throttling' => [
        'title' => 'Троттлинг',
        'icon' => 'sliders',
        'settings' => [
            'THROTTLING_ENABLED', 'THROTTLING_APPLY_DELAY', 'THROTTLING_BLOCK_ON_HARD_LIMIT',
            'DISABLE_THROTTLING_ON_THRESHOLD', 'THROTTLING_DEFAULT_LIMIT', 'THROTTLING_DEFAULT_WINDOW',
            'THROTTLING_DEFAULT_MAX_DELAY'
        ]
    ],
    'throttling_api' => [
        'title' => 'Троттлинг API',
        'icon' => 'cpu',
        'settings' => [
            'THROTTLING_API_LIMIT', 'THROTTLING_API_WINDOW', 'THROTTLING_API_MAX_DELAY',
            'THROTTLING_LOGIN_LIMIT', 'THROTTLING_LOGIN_WINDOW', 'THROTTLING_LOGIN_MAX_DELAY',
            'THROTTLING_SEARCH_LIMIT', 'THROTTLING_SEARCH_WINDOW', 'THROTTLING_SEARCH_MAX_DELAY'
        ]
    ],
    'боты' => [
        'title' => 'Поисковые боты',
        'icon' => 'search',
        'settings' => [
            'DISABLE_BOT_DNS_CHECK', 'BOT_VERIFICATION_CACHE_TTL', 'SEARCH_BOT_SPECIAL_LIMITS',
            'LOG_SEARCH_BOT_ACTIVITY', 'BOT_MAX_REQUESTS_PER_SECOND', 'BOT_RATE_THRESHOLD',
            'BOT_MAX_REQUESTS_PER_IP'
        ]
    ],
    'ip_tracking' => [
        'title' => 'Отслеживание IP',
        'icon' => 'eye',
        'settings' => [
            'ENABLE_FILE_IP_TRACKING', 'FILE_IP_TRACKING_DIR', 'FILE_IP_TTL',
            'FORCE_BLOCKING_ON_FAILURE'
        ]
    ],
    'cookie' => [
        'title' => 'Проверка Cookie',
        'icon' => 'cookie',
        'settings' => [
            'DISABLE_COOKIE_SECURITY_CHECK', 'DISABLE_COOKIE_SECURITY_BLOCKING',
            'MIN_SESSION_ID_LENGTH', 'DISABLE_FILE_FALLBACK'
        ]
    ],
    'timing_check' => [
        'title' => 'Проверка таймингов',
        'icon' => 'clock-history',
        'settings' => [
            'ENABLE_TIMING_CHECK', 'TIMING_MIN_REQUESTS', 'TIMING_DISPERSION_MIN'
        ]
    ],
    'user_agent_check' => [
        'title' => 'Проверка User-Agent',
        'icon' => 'browser-chrome',
        'settings' => [
            'ENABLE_UA_CONSISTENCY_CHECK', 'UA_MAX_DIFFERENT', 'UA_CHECK_WINDOW'
        ]
    ],
	'errors_404' => [
        'title' => 'Защита от 404-атак',
        'icon' => 'exclamation-triangle',
        'settings' => [
            'MAX_404_ERRORS', 'ERROR_404_WINDOW'
        ]
    ]
	
];
// Получение описаний констант из файла settings.php
function getConstantDescriptions() {
    $fileContent = file_get_contents('settings.php');
    $descriptions = [];
    
    // Разбиваем файл на строки
    $lines = explode("\n", $fileContent);
    $prevComment = '';
    
    foreach ($lines as $line) {
        // Проверяем, есть ли определение константы и комментарий в одной строке
        if (preg_match('/^\s*define\(\'([A-Z_]+)\'.*\/\/\s*(.+)$/', $line, $matches)) {
            $constantName = $matches[1];
            $inlineComment = trim($matches[2]);
            
            // Объединяем предыдущий и строчный комментарии с переносом строки
            $descriptions[$constantName] = !empty($prevComment) ? 
                (!empty($inlineComment) ? "$prevComment<br>$inlineComment" : $prevComment) : 
                $inlineComment;
            $prevComment = ''; // Сбрасываем предыдущий комментарий
        }
        // Если строка содержит только комментарий
        elseif (preg_match('/^\s*\/\/\s*(.+)$/', $line, $matches)) {
            $prevComment = trim($matches[1]);
        }
        // Если строка содержит определение константы без комментария
        elseif (preg_match('/^\s*define\(\'([A-Z_]+)\'/', $line, $matches)) {
            $constantName = $matches[1];
            if (!empty($prevComment)) {
                $descriptions[$constantName] = $prevComment;
                $prevComment = ''; // Сбрасываем комментарий после использования
            }
        }
        // Если строка не содержит ни комментария, ни определения константы - сбрасываем предыдущий комментарий
        elseif (trim($line) !== '') {
            $prevComment = '';
        }
    }
    
    return $descriptions;
}

$constantDescriptions = getConstantDescriptions();

// Определение имени активной вкладки
$activeTab = isset($_GET['tab']) ? $_GET['tab'] : 'предустановки';
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#4e73df">
    <title>Настройки системы безопасности DOS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/bootstrap-icons.css">
    <style>
	:root {
            --primary: #4e73df;
            --secondary: #858796;
            --success: #1cc88a;
            --info: #36b9cc;
            --warning: #f6c23e;
            --danger: #e74a3b;
            --light: #f8f9fc;
            --dark: #5a5c69;
        }
        body {
            background-color: #f8f9fc;
            font-family: 'Nunito', 'Segoe UI', Roboto, sans-serif;
            overflow-x: hidden;
        }
        .sidebar {
            background: linear-gradient(180deg, #4e73df 10%, #224abe 100%);
            box-shadow: 0 .15rem 1.75rem 0 rgba(58,59,69,.15);
            z-index: 1040;
            width: 250px;
            transition: all 0.3s ease;
        }
        
        /* Мобильный вид сайдбара */
        @media (max-width: 991.98px) {
            .sidebar {
                position: fixed;
                top: 0;
                left: -250px;
                height: 100vh;
                z-index: 1050;
                overflow-y: auto;
            }
            .sidebar.show {
                left: 0;
            }
            .sidebar-backdrop {
                position: fixed;
                top: 0;
                left: 0;
                width: 100vw;
                height: 100vh;
                background-color: rgba(0, 0, 0, 0.5);
                z-index: 1040;
                display: none;
            }
            .sidebar-backdrop.show {
                display: block;
            }
            .content-wrapper {
                margin-left: 0 !important;
            }
        }
        
        /* Десктопный вид сайдбара */
        @media (min-width: 992px) {
            .sidebar {
                position: fixed;
                min-height: 100vh;
                top: 0;
                bottom: 0;
                overflow-y: auto;
            }
            .content-wrapper {
                margin-left: 250px;
            }
            .menu-toggle {
                display: none;
            }
        }

        .sidebar .nav-link {
            color: rgba(255, 255, 255, 0.8);
            padding: 0.75rem 1rem;
            position: relative;
            font-size: 0.85rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .sidebar .nav-link:hover {
            color: white;
            background: rgba(255, 255, 255, 0.1);
        }
        .sidebar .nav-link.active {
            color: white;
            font-weight: bold;
            background: rgba(255, 255, 255, 0.2);
        }
		.card-header {
            background-color: #f8f9fc;
            border-bottom: 1px solid #e3e6f0;
            padding: 1rem 1.25rem;
            font-weight: 700;
            font-size: 1rem;
            color: #5a5c69;
        }
        .card-body {
            padding: 1.25rem;
        }
        .form-label {
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        .form-text {
            margin-top: 0.25rem;
            font-size: 0.875em;
            color: #6c757d;
        }
        .btn-primary {
            background-color: #4e73df;
            border-color: #4e73df;
        }
        .btn-primary:hover {
            background-color: #2e59d9;
            border-color: #2653d4;
        }
        .alert-success {
            background-color: #1cc88a;
            border-color: #1cc88a;
            color: white;
        }
        .alert-danger {
            background-color: #e74a3b;
            border-color: #e74a3b;
            color: white;
        }
		.login-form {
            max-width: 400px;
            margin: 100px auto;
            padding: 20px;
            background-color: white;
            border-radius: 5px;
           box-shadow: 0 .15rem 1.75rem 0 rgba(58,59,69,.15);
       }
       .logo {
           padding: 1.5rem 1rem;
           text-align: center;
           color: white;
           margin-bottom: 1rem;
           border-bottom: 1px solid rgba(255, 255, 255, 0.2);
       }
       .logo h4 {
           margin: 0;
           font-weight: 700;
       }
       .divider {
           height: 0;
           margin: 0.5rem 0;
           overflow: hidden;
           border-top: 1px solid rgba(255, 255, 255, 0.15);
       }
       .logout {
           padding: 1rem;
           border-top: 1px solid rgba(255, 255, 255, 0.15);
       }
       /* Стилизация для фиксированных описаний */
       .const-description {
           font-style: italic;
           color: #6c757d;
           margin-bottom: 5px;
           font-size: 0.85rem;
       }
       .toggle-section {
           cursor: pointer;
           display: flex;
           justify-content: space-between;
           align-items: center;
       }
       .toggle-icon {
           transition: transform 0.3s;
       }
       .toggle-section.collapsed .toggle-icon {
           transform: rotate(-90deg);
       }
       .tooltip-icon {
           color: #4e73df;
           margin-left: 5px;
           cursor: help;
       }
	   /* Стили для предустановленных режимов */
       .preset-mode {
           border: 1px solid #e3e6f0;
           border-radius: 0.5rem;
           padding: 1.25rem;
           margin-bottom: 1.5rem;
           transition: all 0.3s;
       }
       .preset-mode:hover {
           box-shadow: 0 .25rem 1.5rem 0 rgba(58,59,69,.2);
       }
       .preset-mode.light {
           background-color: #e3f2fd;
           border-color: #bbdefb;
       }
       .preset-mode.medium {
           background-color: #fff3e0;
           border-color: #ffe0b2;
       }
       .preset-mode.strict {
           background-color: #ffebee;
           border-color: #ffcdd2;
       }
       .preset-mode h3 {
           margin-top: 0;
           margin-bottom: 1rem;
           font-size: 1.25rem;
           font-weight: 600;
       }
       .preset-mode p {
           margin-bottom: 1.25rem;
           color: #666;
       }
       
       /* Мобильные улучшения */
       .menu-toggle {
           background-color: #4e73df;
           color: white;
           border: none;
           width: 45px;
           height: 45px;
           border-radius: 50%;
           display: flex;
           align-items: center;
           justify-content: center;
           position: fixed;
           bottom: 20px;
           right: 20px;
           z-index: 1050;
           box-shadow: 0 .15rem 1.75rem 0 rgba(58,59,69,.3);
       }
       
       /* Стили для мобильной навигации по категориям */
       .mobile-category-nav {
           display: none;
           margin-bottom: 1rem;
       }
	   @media (max-width: 991.98px) {
           .mobile-category-nav {
               display: block;
           }
           .card-body {
               padding: 1rem;
           }
           .header h1 {
               font-size: 1.5rem;
           }
           .form-label {
               font-size: 0.95rem;
           }
           .const-description {
               font-size: 0.8rem;
           }
       }
       
       /* Улучшения для маленьких экранов */
       @media (max-width: 576px) {
           .content-wrapper {
               padding: 1rem 0.75rem;
           }
           .header {
               padding: 0.75rem;
           }
           .card-header {
               padding: 0.75rem 1rem;
           }
           .preset-mode {
               padding: 1rem;
           }
           .preset-mode h3 {
               font-size: 1.1rem;
           }
       }
    </style>
</head>
<body>
   <!-- Кнопка открытия меню для мобильных -->
   <button class="menu-toggle d-lg-none" id="sidebarToggle" aria-label="Открыть меню">
       <i class="bi bi-list fs-4"></i>
   </button>
   
   <!-- Затемнение при открытом меню -->
   <div class="sidebar-backdrop" id="sidebarBackdrop"></div>
   
   <!-- Боковое меню -->
   <div class="sidebar" id="sidebar">
       <div class="logo">
           <h4><i class="bi bi-shield me-2"></i>DOS Настройки</h4>
       </div>
       <div class="nav flex-column">
           <?php foreach ($settingsCategories as $categoryId => $category): ?>
           <a class="nav-link <?php echo $activeTab === $categoryId ? 'active' : ''; ?>" href="?tab=<?php echo $categoryId; ?>">
               <i class="bi bi-<?php echo e($category['icon']); ?>"></i> <?php echo e($category['title']); ?>
           </a>
           <?php endforeach; ?>
           <div class="divider"></div>
       </div>
       <div class="logout">
           <div class="d-flex justify-content-between align-items-center mb-2 text-white-50">
               <small>Вы вошли как:</small>
               <span class="badge bg-light text-dark"><?php echo e(ADMIN_USERNAME); ?></span>
           </div>
           <a href="admin.php" class="btn btn-light btn-sm w-100 mb-2">
               <i class="bi bi-shield-lock me-1"></i> К панели управления
           </a>
       </div>
   </div>
   <div class="content-wrapper">
       <div class="header d-flex justify-content-between align-items-center">
           <h1 class="h3 mb-0 text-gray-800">
               <i class="bi bi-<?php echo e($settingsCategories[$activeTab]['icon']); ?> me-2"></i>
               <?php echo e($settingsCategories[$activeTab]['title']); ?>
           </h1>
           <button class="btn btn-sm btn-outline-primary d-lg-none" id="mobileCategoryToggle" aria-label="Показать категории">
               <i class="bi bi-filter me-1"></i> Категории
           </button>
       </div>
       
       <!-- Мобильная навигация по категориям -->
       <div class="mobile-category-nav" id="mobileCategoryNav" style="display: none;">
           <div class="card mb-3">
               <div class="card-body p-2">
                   <select class="form-select" id="categorySelect" onchange="window.location.href='?tab='+this.value">
                       <?php foreach ($settingsCategories as $categoryId => $category): ?>
                       <option value="<?php echo $categoryId; ?>" <?php echo $activeTab === $categoryId ? 'selected' : ''; ?>>
                           <?php echo e($category['title']); ?>
                       </option>
                       <?php endforeach; ?>
                   </select>
               </div>
           </div>
       </div>
       
       <?php if (isset($auto_unblocked) && $auto_unblocked): ?>
       <div class="alert alert-success alert-dismissible fade show" role="alert">
           <i class="bi bi-check-circle-fill me-2"></i>
           Ваш IP-адрес был автоматически разблокирован.
           <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
       </div>
       <?php endif; ?>
       
       <?php if ($message): ?>
       <div class="alert alert-<?php echo $messageType === 'success' ? 'success' : 'danger'; ?> alert-dismissible fade show" role="alert">
           <i class="bi bi-<?php echo $messageType === 'success' ? 'check-circle' : 'exclamation-triangle'; ?> me-2"></i>
           <?php echo e($message); ?>
           <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
       </div>
       <?php endif; ?>
	   <div class="card">
           <div class="card-header d-flex justify-content-between align-items-center">
               <span>
                   <i class="bi bi-<?php echo e($settingsCategories[$activeTab]['icon']); ?> me-1"></i>
                   <?php echo e($settingsCategories[$activeTab]['title']); ?>
               </span>
               <?php if ($activeTab !== 'предустановки'): ?>
               <span class="badge bg-info text-white">
                   <?php echo count($settingsCategories[$activeTab]['settings']); ?> параметров
               </span>
               <?php endif; ?>
           </div>
           <div class="card-body">
               <?php if ($activeTab === 'предустановки'): ?>
               <!-- Секция предустановленных режимов -->
               <div class="row">
                   <div class="col-12 mb-3">
                       <div class="alert alert-info">
                           <i class="bi bi-info-circle-fill me-2"></i>
                           Выберите один из предустановленных режимов защиты. При применении режима текущие настройки будут заменены на предустановленные значения.
                       </div>
                   </div>
				   <!-- Слабый режим -->
                   <div class="col-lg-4 col-md-6 mb-3">
                       <div class="preset-mode light h-100">
                           <h3><i class="bi bi-shield me-2"></i><?php echo e($presetModes['light']['title']); ?></h3>
                           <p><?php echo e($presetModes['light']['description']); ?></p>
                           <form method="post" action="" class="mt-3">
                               <input type="hidden" name="preset_mode" value="light">
                               <button type="submit" name="apply_preset" class="btn btn-primary w-100">
                                   <i class="bi bi-check-circle me-1"></i> Применить слабый режим
                               </button>
                           </form>
                       </div>
                   </div>
                   
                   <!-- Средний режим -->
                   <div class="col-lg-4 col-md-6 mb-3">
                       <div class="preset-mode medium h-100">
                           <h3><i class="bi bi-shield-lock me-2"></i><?php echo e($presetModes['medium']['title']); ?></h3>
                           <p><?php echo e($presetModes['medium']['description']); ?></p>
                           <form method="post" action="" class="mt-3">
                               <input type="hidden" name="preset_mode" value="medium">
                               <button type="submit" name="apply_preset" class="btn btn-primary w-100">
                                   <i class="bi bi-check-circle me-1"></i> Применить средний режим
                               </button>
                           </form>
                       </div>
                   </div>
                   
                   <!-- Жесткий режим -->
                   <div class="col-lg-4 col-md-6 mb-3">
                       <div class="preset-mode strict h-100">
                           <h3><i class="bi bi-shield-fill-exclamation me-2"></i><?php echo e($presetModes['strict']['title']); ?></h3>
                           <p><?php echo e($presetModes['strict']['description']); ?></p>
                           <form method="post" action="" class="mt-3">
                               <input type="hidden" name="preset_mode" value="strict">
                               <button type="submit" name="apply_preset" class="btn btn-primary w-100" data-confirm="true">
                                   <i class="bi bi-check-circle me-1"></i> Применить жесткий режим
                               </button>
                           </form>
                       </div>
                   </div>
				   <!-- Подробное описание параметров каждого режима -->
                   <div class="col-12 mt-2">
                       <div class="accordion" id="presetAccordion">
                           <!-- Слабый режим - подробности -->
                           <div class="accordion-item">
                               <h2 class="accordion-header" id="headingLight">
                                   <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseLight" aria-expanded="false" aria-controls="collapseLight">
                                       Подробности слабого режима
                                   </button>
                               </h2>
                               <div id="collapseLight" class="accordion-collapse collapse" aria-labelledby="headingLight" data-bs-parent="#presetAccordion">
                                   <div class="accordion-body">
                                       <div class="table-responsive">
                                           <table class="table table-sm table-hover">
                                               <thead>
                                                   <tr>
                                                       <th>Параметр</th>
                                                       <th>Значение</th>
                                                   </tr>
                                               </thead>
                                               <tbody>
                                                   <?php foreach ($presetModes['light']['settings'] as $param => $value): ?>
                                                   <tr>
                                                       <td><strong><?php echo e($param); ?></strong></td>
                                                       <td><?php echo e($value); ?></td>
                                                   </tr>
                                                   <?php endforeach; ?>
                                               </tbody>
                                           </table>
                                       </div>
                                   </div>
                               </div>
                           </div>
						   <!-- Средний режим - подробности -->
                           <div class="accordion-item">
                               <h2 class="accordion-header" id="headingMedium">
                                   <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseMedium" aria-expanded="false" aria-controls="collapseMedium">
                                       Подробности среднего режима
                                   </button>
                               </h2>
                               <div id="collapseMedium" class="accordion-collapse collapse" aria-labelledby="headingMedium" data-bs-parent="#presetAccordion">
                                   <div class="accordion-body">
                                       <div class="table-responsive">
                                           <table class="table table-sm table-hover">
                                               <thead>
                                                   <tr>
                                                       <th>Параметр</th>
                                                       <th>Значение</th>
                                                   </tr>
                                               </thead>
                                               <tbody>
                                                   <?php foreach ($presetModes['medium']['settings'] as $param => $value): ?>
                                                   <tr>
                                                       <td><strong><?php echo e($param); ?></strong></td>
                                                       <td><?php echo e($value); ?></td>
                                                   </tr>
                                                   <?php endforeach; ?>
                                               </tbody>
                                           </table>
                                       </div>
                                   </div>
                               </div>
                           </div>
                           
                           <!-- Жесткий режим - подробности -->
                           <div class="accordion-item">
                               <h2 class="accordion-header" id="headingStrict">
                                   <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseStrict" aria-expanded="false" aria-controls="collapseStrict">
                                       Подробности жесткого режима
                                   </button>
                               </h2>
                               <div id="collapseStrict" class="accordion-collapse collapse" aria-labelledby="headingStrict" data-bs-parent="#presetAccordion">
                                   <div class="accordion-body">
                                       <div class="table-responsive">
                                           <table class="table table-sm table-hover">
                                               <thead>
                                                   <tr>
                                                       <th>Параметр</th>
                                                       <th>Значение</th>
                                                   </tr>
                                               </thead>
                                               <tbody>
                                                   <?php foreach ($presetModes['strict']['settings'] as $param => $value): ?>
                                                   <tr>
                                                       <td><strong><?php echo e($param); ?></strong></td>
                                                       <td><?php echo e($value); ?></td>
                                                   </tr>
                                                   <?php endforeach; ?>
                                               </tbody>
                                           </table>
                                       </div>
                                   </div>
                               </div>
                           </div>
                       </div>
                   </div>
               </div>
               <?php else: ?>
               <!-- Стандартная форма настроек -->
               <form method="post" action="">
                   <input type="hidden" name="current_tab" value="<?php echo e($activeTab); ?>">
				   <?php foreach ($settingsCategories[$activeTab]['settings'] as $settingName): ?>
                   <div class="mb-4">
                       <?php if (isset($constantDescriptions[$settingName])): ?>
                       <div class="const-description"><?php echoConstantDescription($constantDescriptions[$settingName]); ?></div>
                       <?php endif; ?>
                       
                       <label for="<?php echo e($settingName); ?>" class="form-label"><?php echo e($settingName); ?></label>
                       
                       <?php 
                       $currentValue = getCurrentValue($settingName);
                       $isBoolean = in_array($currentValue, ['true', 'false']);
                       ?>
                       
                       <?php if ($isBoolean): ?>
                       <div class="form-check form-switch">
                           <input class="form-check-input" type="checkbox" id="<?php echo e($settingName); ?>_switch" 
                                  <?php echo $currentValue === 'true' ? 'checked' : ''; ?>
                                  onchange="document.getElementById('<?php echo e($settingName); ?>').value = this.checked ? 'true' : 'false';">
                           <label class="form-check-label" for="<?php echo e($settingName); ?>_switch">
                               <span id="<?php echo e($settingName); ?>_status"><?php echo $currentValue === 'true' ? 'Включено' : 'Выключено'; ?></span>
                           </label>
                       </div>
                       <select class="form-select d-none" id="<?php echo e($settingName); ?>" name="<?php echo e($settingName); ?>">
                           <option value="true" <?php echo $currentValue === 'true' ? 'selected' : ''; ?>>true</option>
                           <option value="false" <?php echo $currentValue === 'false' ? 'selected' : ''; ?>>false</option>
                       </select>
                       <?php elseif (strpos($settingName, 'PASSWORD') !== false || $settingName === 'REDIS_PASSWORD' || $settingName === 'DB_PASS'): ?>
                       <div class="input-group">
                           <input type="password" class="form-control" id="<?php echo e($settingName); ?>" name="<?php echo e($settingName); ?>" value="<?php echo e($currentValue); ?>">
                           <button class="btn btn-outline-secondary" type="button" onclick="togglePasswordVisibility('<?php echo e($settingName); ?>')">
                               <i class="bi bi-eye" id="<?php echo e($settingName); ?>-toggle-icon"></i>
                           </button>
                       </div>
					   <?php elseif (is_numeric($currentValue) && strpos($currentValue, '.') === false): ?>
                       <div class="input-group">
                           <input type="number" class="form-control" id="<?php echo e($settingName); ?>" name="<?php echo e($settingName); ?>" value="<?php echo e($currentValue); ?>">
                           <button class="btn btn-outline-secondary" type="button" onclick="restoreDefault('<?php echo e($settingName); ?>', '<?php echo e($currentValue); ?>')">
                               <i class="bi bi-arrow-counterclockwise"></i>
                           </button>
                       </div>
                       <?php else: ?>
                       <div class="input-group">
                           <input type="text" class="form-control" id="<?php echo e($settingName); ?>" name="<?php echo e($settingName); ?>" value="<?php echo e($currentValue); ?>">
                           <button class="btn btn-outline-secondary" type="button" onclick="restoreDefault('<?php echo e($settingName); ?>', '<?php echo e($currentValue); ?>')">
                               <i class="bi bi-arrow-counterclockwise"></i>
                           </button>
                       </div>
                       <?php endif; ?>
                   </div>
                   <?php endforeach; ?>
                   
                   <div class="d-grid gap-2 d-md-flex justify-content-md-end mt-4">
                       <button type="reset" class="btn btn-outline-secondary me-md-2">
                           <i class="bi bi-x-circle me-1"></i> Отменить
                       </button>
                       <button type="submit" name="save_settings" class="btn btn-primary">
                           <i class="bi bi-save me-1"></i> Сохранить настройки
                       </button>
                   </div>
               </form>
               <?php endif; ?>
           </div>
       </div>
       
       <footer class="text-center text-muted mt-4 pb-4">
           <small>Панель управления DOS &copy; <?php echo date('Y'); ?></small>
       </footer>
   </div>
   <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
   <script>
       // Функция для переключения видимости пароля
       function togglePasswordVisibility(fieldId) {
           const passwordField = document.getElementById(fieldId);
           const toggleIcon = document.getElementById(fieldId + '-toggle-icon');
           
           if (passwordField.type === 'password') {
               passwordField.type = 'text';
               if (toggleIcon) toggleIcon.classList.replace('bi-eye', 'bi-eye-slash');
           } else {
               passwordField.type = 'password';
               if (toggleIcon) toggleIcon.classList.replace('bi-eye-slash', 'bi-eye');
           }
       }
       
       // Функция для восстановления значения по умолчанию
       function restoreDefault(fieldId, defaultValue) {
           const field = document.getElementById(fieldId);
           field.value = defaultValue;
       }
       
       // Инициализация всех подсказок и обработчиков
       document.addEventListener('DOMContentLoaded', function() {
           // Инициализация всех подсказок
           const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
           tooltipTriggerList.map(function (tooltipTriggerEl) {
               return new bootstrap.Tooltip(tooltipTriggerEl);
           });
           
           // Обработчик для переключения мобильного меню
           const sidebarToggle = document.getElementById('sidebarToggle');
           const sidebar = document.getElementById('sidebar');
           const sidebarBackdrop = document.getElementById('sidebarBackdrop');
           
           if (sidebarToggle && sidebar && sidebarBackdrop) {
               sidebarToggle.addEventListener('click', function() {
                   sidebar.classList.toggle('show');
                   sidebarBackdrop.classList.toggle('show');
                   document.body.classList.toggle('overflow-hidden');
               });
               
               sidebarBackdrop.addEventListener('click', function() {
                   sidebar.classList.remove('show');
                   sidebarBackdrop.classList.remove('show');
                   document.body.classList.remove('overflow-hidden');
               });
               
               // Закрытие меню при выборе ссылки на мобильных
               const sidebarLinks = sidebar.querySelectorAll('.nav-link');
               sidebarLinks.forEach(link => {
                   link.addEventListener('click', function() {
                       if (window.innerWidth < 992) { // Только на мобильных
                           sidebar.classList.remove('show');
                           sidebarBackdrop.classList.remove('show');
                           document.body.classList.remove('overflow-hidden');
                       }
                   });
               });
           }
		   // Обработчик для мобильного выбора категории
           const mobileCategoryToggle = document.getElementById('mobileCategoryToggle');
           const mobileCategoryNav = document.getElementById('mobileCategoryNav');
           
           if (mobileCategoryToggle && mobileCategoryNav) {
               mobileCategoryToggle.addEventListener('click', function() {
                   if (mobileCategoryNav.style.display === 'none' || !mobileCategoryNav.style.display) {
                       mobileCategoryNav.style.display = 'block';
                   } else {
                       mobileCategoryNav.style.display = 'none';
                   }
               });
           }
           
           // Добавляем обработчик для переключателей булевых значений
           const switchesToggles = document.querySelectorAll('.form-check-input[type="checkbox"]');
           switchesToggles.forEach(switchToggle => {
               switchToggle.addEventListener('change', function() {
                   const statusElement = document.getElementById(this.id.replace('_switch', '_status'));
                   if (statusElement) {
                       statusElement.textContent = this.checked ? 'Включено' : 'Выключено';
                   }
               });
           });
           
           // Добавляем обработчик для предупреждения при выборе жесткого режима
           const confirmButtons = document.querySelectorAll('button[data-confirm="true"]');
           confirmButtons.forEach(button => {
               button.addEventListener('click', function(e) {
                   if (!confirm('Внимание! Применение жесткого режима может привести к блокировке легитимных пользователей и повышенной нагрузке на сервер. Вы уверены, что хотите продолжить?')) {
                       e.preventDefault();
                   }
               });
           });
           
           // Автоматическое скрытие алертов через 8 секунд
           const alerts = document.querySelectorAll('.alert:not(.alert-info)');
           alerts.forEach(alert => {
               setTimeout(() => {
                   const closeButton = alert.querySelector('.btn-close');
                   if (closeButton) {
                       closeButton.click();
                   }
               }, 8000);
           });
       });
   </script>
</body>
</html>
