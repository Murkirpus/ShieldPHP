<?php
// /dos/settings.php
// Общие настройки для всех файлов системы безопасности
// Support https://murkir.pp.ua https://dj-x.info

// Настройки подключения к БД
define('DB_HOST', 'localhost');    // Хост базы данных
define('DB_NAME', 'dos');          // Имя базы данных
define('DB_USER', 'dosUSER');          // Имя пользователя базы данных
define('DB_PASS', 'dosPASS');          // Пароль базы данных

// https://www.google.com/recaptcha/admin/create
// Настройки reCAPTCHA (замените на свои ключи от Google)
//define('RECAPTCHA_SITE_KEY', '');  // Публичный ключ
//define('RECAPTCHA_SECRET_KEY', ''); // Секретный ключ

// Настройки администратора
define('ADMIN_USERNAME', 'username'); // Имя пользователя для доступа к админ-панели
define('ADMIN_PASSWORD', 'murkir.pp.ua'); // Пароль для доступа к админ-панели

// Настройки механизмов блокировки (true - включено, false - отключено)
define('ENABLE_HTACCESS_BLOCKING', true);  // Блокировка через .htaccess
define('ENABLE_NGINX_BLOCKING', false);     // Блокировка через Nginx (ip.conf)
define('ENABLE_FIREWALL_BLOCKING', true);   // Блокировка через брандмауэр (iptables/ip6tables)
define('ENABLE_API_BLOCKING', false);        // Блокировка через внешний API

// Настройки экспорта IP в текстовые файлы
define('EXPORT_BLOCKED_IPS_TO_FILES', true);           // Экспортировать заблокированные IP в текстовые файлы
define('BLOCKED_IPV4_FILE', 'blocked_ipv4.txt');       // Имя файла для блокированных IPv4
define('BLOCKED_IPV6_FILE', 'blocked_ipv6.txt');       // Имя файла для блокированных IPv6

// Настройка принудительной жесткой блокировки
define('HARD_BLOCK_ON_FIRST_VIOLATION', false);  // Применять жесткую блокировку при первом нарушении

// Настройки прогрессивного повышения уровня блокировки
define('ESCALATE_BLOCK_ON_REPEAT_ATTEMPTS', true);  // Повышать уровень блокировки при повторных запросах
define('ATTEMPTS_BEFORE_ESCALATION', 1);            // Количество попыток до повышения уровня
define('BLOCK_ESCALATION_COOLDOWN', 300);           // Таймаут между повышениями уровня (5 минут)

// Настройки очистки дублирующихся правил iptables
define('CLEANUP_IPTABLES_DUPLICATES', true);     // Включить очистку дублирующихся правил iptables
define('MAX_DUPLICATES_TO_KEEP', 1);             // Максимальное количество правил для одного IP

// Начало - Настройки API для блокировки IP
define('API_BLOCK_URL', 'https://mysite.com/dos/iptables.php'); // URL API для блокировки
define('API_BLOCK_KEY', 'api_key'); // Ключ API для блокировки (должен совпадать с ключом в iptables.php)
define('API_USER_AGENT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'); // User-Agent для запросов
// Настройки распределения нагрузки API запросов
define('LOAD_BALANCING_ENABLED', true);      // Включить/выключить распределение нагрузки
// Настройки управления параллельными запросами
define('MAX_CONCURRENT_REQUESTS', 20);       // Максимальное количество одновременно обрабатываемых запросов
// Настройки задержек
define('REQUEST_PROCESSING_DELAY', 0);       // Фиксированная задержка в микросекундах (0 - отключено)
define('DYNAMIC_DELAY_ENABLED', true);       // Включить динамическую задержку при высокой нагрузке
define('LOAD_THRESHOLD', 4.0);               // Порог загрузки CPU, при котором включается динамическая задержка
define('MAX_DYNAMIC_DELAY', 100000);         // Максимальная динамическая задержка в микросекундах (0.1 сек)
// Системные настройки
define('SEM_KEY_PATH', __FILE__);            // Путь для генерации ключа семафора
define('LOAD_TRACKING_FILE', '/tmp/iptables_load_tracking'); // Файл для отслеживания нагрузки
// Конец - Настройки API для блокировки IP

// НОВЫЕ НАСТРОЙКИ: Redis для хранения данных безопасности
define('USE_REDIS', true);          // Использовать Redis вместо MariaDB (true) или совместно (false)
define('REDIS_HOST', '127.0.0.1');  // Хост Redis
define('REDIS_PORT', 6379);         // Порт Redis
define('REDIS_PASSWORD', '');       // Пароль Redis (пустой, если не используется)
define('REDIS_DATABASE', 0);        // Номер базы данных Redis
define('REDIS_PREFIX', 'dos:');     // Префикс для ключей в Redis

// Настройки TTL (время жизни объектов в Redis) в секундах
define('REDIS_TTL_IP_REQUEST_RATE', 600);      // Частота запросов IP (10 минут)
define('REDIS_TTL_SUSPICIOUS_REQUEST', 86400); // Подозрительные запросы (24 часа)

// Лимиты для обнаружения атак
define('MAX_REQUESTS_PER_SECOND', 3);         // Максимальное количество запросов в секунду
define('MAX_REQUESTS_PER_MINUTE', 40);       // Максимальное количество запросов в минуту
define('MAX_REQUESTS_PER_IP', 500);          // Максимум запросов с одного IP (до блокировки)
// Текущие настройки означают, что если с одного IP-адреса поступает более 20 запросов за 10 секунды, система считает это подозрительной активностью и блокирует - без Cookies.
define('RATE_CHECK_WINDOW', 10);              // Окно проверки частоты запросов (секунды) - за 10 секунды
define('RATE_THRESHOLD', 20);                 // Порог запросов в окне для блокировки - поступает более 30 запросов

// Настройки безопасности памяти
define('REDIS_MEMORY_LIMIT_PERCENT', 80);     // Порог использования памяти для предупреждения
define('REDIS_EMERGENCY_MEMORY_PERCENT', 95); // Порог для аварийной очистки

// Настройки прогрессивных блокировок (в секундах)
define('BLOCK_TIME_FIRST', 3600);         // Первая блокировка (1 час)
define('BLOCK_TIME_SECOND', 10800);       // Вторая блокировка (3 часа)
define('BLOCK_TIME_THIRD', 21600);        // Третья блокировка (6 часов)
define('BLOCK_TIME_FOURTH', 43200);       // Четвертая блокировка (12 часов)
define('BLOCK_TIME_FIFTH', 86400);        // Пятая блокировка (24 часа)
define('BLOCK_TIME_SIXTH', 259200);       // Шестая блокировка (3 дня)
define('BLOCK_TIME_SEVENTH_PLUS', 604800); // Седьмая и последующие блокировки (7 дней)

// Настройки лог-файлов
define('LOG_MAX_SIZE', 1048576);    // Максимальный размер лог-файла (1 МБ)
define('LOG_MAX_AGE', 30);          // Максимальное время хранения записей (30 дней)

// Настройки очистки кеша
define('CACHE_FILES_MAX_AGE', 86400); // Максимальный возраст файлов кеша (1 день)

// Настройки обслуживания
define('CLEANUP_OPTIMIZE_TABLES', true);   // Выполнять оптимизацию таблиц
define('CLEANUP_SYNC_DATABASES', true);    // Синхронизировать Redis и MariaDB

// Настройка DNS-запросов
define('DISABLE_RDNS_LOOKUP', false);  // По умолчанию DNS-запросы включены

// Настройки для автоматической жесткой блокировки
define('AUTO_HARD_BLOCK_ENABLED', true);    // Включить/выключить автоматическую жесткую блокировку
define('AUTO_HARD_BLOCK_THRESHOLD', 500);   // Настройка порога - для небольших сайтов разумно установить порог 50-100 IP, для крупных - 200-500 IP
define('AUTO_HARD_BLOCK_ACTION', 'iptables'); // Метод жесткой блокировки: 'all', 'iptables', 'nginx', 'htaccess', 'api', 'iptables+nginx', 'database'.

// Настройки уведомлений о жесткой блокировке
define('AUTO_HARD_BLOCK_NOTIFY_ADMIN', true);  // Отправлять уведомления администратору
define('AUTO_HARD_BLOCK_ADMIN_EMAIL', 'info@murkir.pp.ua');  // Email администратора (ЗАМЕНИТЕ НА СВОЙ)
define('AUTO_HARD_BLOCK_EMAIL_SUBJECT', 'ВНИМАНИЕ: Активирована автоматическая жесткая блокировка');  // Тема письма
define('AUTO_HARD_BLOCK_EMAIL_FROM', 'security@' . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'info@mysite.com'));  // Email отправителя
define('AUTO_HARD_BLOCK_NOTIFY_INTERVAL', 24);  // Минимальный интервал между уведомлениями (в часах)

// Отключить использование файлового кеша как запасного варианта
define('DISABLE_FILE_FALLBACK', false);

// Настройки троттлинга
define('THROTTLING_ENABLED', true);                // Включение/отключение троттлинга
define('THROTTLING_APPLY_DELAY', true);            // Применять ли задержку или только добавлять заголовки
define('THROTTLING_BLOCK_ON_HARD_LIMIT', true);    // Блокировать ли IP при жестком превышении лимита
define('DISABLE_THROTTLING_ON_THRESHOLD', true);   // Отключать троттлинг при достижении порога жесткой блокировки

// Настройки для общего троттлинга
define('THROTTLING_DEFAULT_LIMIT', 60);            // Лимит запросов в окне (по умолчанию)
define('THROTTLING_DEFAULT_WINDOW', 60);           // Размер окна в секундах (по умолчанию)
define('THROTTLING_DEFAULT_MAX_DELAY', 1000);      // Максимальная задержка в мс (по умолчанию)

// Настройки для API запросов
define('THROTTLING_API_LIMIT', 20);                // Лимит API запросов в окне
define('THROTTLING_API_WINDOW', 60);               // Размер окна для API в секундах
define('THROTTLING_API_MAX_DELAY', 2000);          // Максимальная задержка для API в мс

// Настройки для попыток входа
define('THROTTLING_LOGIN_LIMIT', 5);               // Лимит попыток входа в окне
define('THROTTLING_LOGIN_WINDOW', 300);            // Размер окна для входа в секундах
define('THROTTLING_LOGIN_MAX_DELAY', 5000);        // Максимальная задержка для входа в мс

// Настройки для поисковых запросов
define('THROTTLING_SEARCH_LIMIT', 10);             // Лимит поисковых запросов в окне
define('THROTTLING_SEARCH_WINDOW', 60);            // Размер окна для поиска в секундах
define('THROTTLING_SEARCH_MAX_DELAY', 1500);       // Максимальная задержка для поиска в мс

// Настройки для работы с поисковыми ботами
define('DISABLE_BOT_DNS_CHECK', false);        // Отключить DNS проверку для ботов (true - доверять только User-Agent)
define('BOT_VERIFICATION_CACHE_TTL', 43200);   // Время кэширования результатов проверки ботов (12 часов)
define('SEARCH_BOT_SPECIAL_LIMITS', true);     // Применять специальные лимиты для поисковых ботов
define('LOG_SEARCH_BOT_ACTIVITY', false);      // Логировать активность поисковых ботов

// Лимиты для поисковых ботов (при SEARCH_BOT_SPECIAL_LIMITS = true)
define('BOT_MAX_REQUESTS_PER_SECOND', 10);      // Максимум запросов в секунду для ботов
define('BOT_RATE_THRESHOLD', 500);              // Порог для ботов (более высокий)
define('BOT_MAX_REQUESTS_PER_IP', 1000); // Максимум общих запросов с IP для поисковых ботов

// Настройки для механизма обнаружения атак без Cookies
define('ENABLE_FILE_IP_TRACKING', true);         // Включить файловое отслеживание IP
define('FILE_IP_TRACKING_DIR', 'ip_requests/');  // Директория для хранения данных
define('FILE_IP_TTL', 300);                      // Время жизни файлов IP (5 минут)

// Принудительная блокировка
define('FORCE_BLOCKING_ON_FAILURE', true);      // Включить принудительную блокировку при отказе

// Настройки проверки Cookie
define('DISABLE_COOKIE_SECURITY_CHECK', false);     // Установите true, чтобы полностью отключить проверку Cookie
define('DISABLE_COOKIE_SECURITY_BLOCKING', false);  // Установите true, чтобы только логировать, но не блокировать
define('MIN_SESSION_ID_LENGTH', 20);               // Минимальная рекомендуемая длина ID сессии

// Перехват ошибок
define('DISABLE_ERROR_HANDLING', true); // Отключить перехват ошибок

// Настройки проверки дисперсии таймингов
define('ENABLE_TIMING_CHECK', true);      // Включить проверку дисперсии таймингов
define('TIMING_MIN_REQUESTS', 5);         // Минимальное количество запросов для анализа
define('TIMING_DISPERSION_MIN', 0.2);     // Минимальная дисперсия для трафика человека

// Настройки проверки соответствия User-Agent
define('ENABLE_UA_CONSISTENCY_CHECK', true);    // Включить проверку соответствия UA
define('UA_MAX_DIFFERENT', 5);                  // Максимальное количество разных UA с одного IP
define('UA_CHECK_WINDOW', 3600);                // Временное окно для проверки (1 час)

// Настройки для обнаружения 404-атак
define('MAX_404_ERRORS', 20);            // Максимальное количество 404 ошибок за период
define('ERROR_404_WINDOW', 600);         // Период отслеживания 404 ошибок (секунды)

// Список разрешенных поисковых ботов (добавлен новый массив)
$ALLOWED_SEARCH_BOTS = array(
    'google' => array(
        'user_agents' => array('Googlebot', 'AdsBot-Google', 'Google-AdWords', 'Google Favicon', 'Mediapartners-Google'),
        'domains' => array('.googlebot.com', '.google.com'),
        'auto_whitelist' => true  // Автоматически добавлять в белый список при проверке
    ),
    'yandex' => array(
        'user_agents' => array('YandexBot', 'YandexImages', 'YandexMetrika', 'YandexDirect'),
        'domains' => array('.yandex.ru', '.yandex.com', '.yandex.net'),
        'auto_whitelist' => true
    ),
    'bing' => array(
        'user_agents' => array('bingbot', 'BingPreview', 'msnbot'),
        'domains' => array('.msn.com', '.bing.com', '.msedge.net'),
        'auto_whitelist' => true
    ),
    'baidu' => array(
        'user_agents' => array('Baiduspider'),
        'domains' => array('.baidu.com', '.baidu.jp'),
        'auto_whitelist' => false
    ),
    'duckduckgo' => array(
        'user_agents' => array('DuckDuckBot', 'DuckDuckGo-Favicons-Bot'),
        'domains' => array('.duckduckgo.com'),
        'auto_whitelist' => false
    ),
    'mail.ru' => array(
        'user_agents' => array('Mail.RU_Bot'),
        'domains' => array('.mail.ru', '.mail.ru'),
        'auto_whitelist' => false
    ),
	'apple' => array(
    'user_agents' => array('Applebot', 'AppleNewsBot'),
    'domains' => array('.applebot.apple.com'),
    'auto_whitelist' => true  // Установите true, если хотите автоматически добавлять в белый список
	),
    // Добавьте других ботов по необходимости
);
?>
