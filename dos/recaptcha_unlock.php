<?php
require_once 'settings.php';
// /dos/recaptcha_unlock.php
// Страница разблокировки IP с использованием интегрированной защиты от ботов

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

// Получаем URL из GET-параметра, если он есть
if (isset($_GET['return_to']) && !empty($_GET['return_to'])) {
    $return_to = $_GET['return_to'];
    if ((function_exists('filter_var') && filter_var($return_to, FILTER_VALIDATE_URL)) && 
        (strpos($return_to, '/') === 0 || parse_url($return_to, PHP_URL_HOST) === $_SERVER['HTTP_HOST'])) {
        $_SESSION['original_url'] = $return_to;
    }
}

// Получаем URL страницы, с которой произошло перенаправление
if (!isset($_SESSION['original_url']) && isset($_SERVER['HTTP_REFERER'])) {
    $referer = $_SERVER['HTTP_REFERER'];
    if (strpos($referer, 'recaptcha_unlock.php') === false) {
        $_SESSION['original_url'] = $referer;
    }
}

// Подключаем класс разблокировки
require_once 'RecaptchaUnlock.php';

// Создаем экземпляр класса
$unlocker = new RecaptchaUnlock();

// Проверяем частоту посещений страницы
$too_many_visits = $unlocker->detectFrequentVisits();

// Переменные для шаблона
$success_message = '';
$error_message = '';
$is_blocked = $unlocker->isIPBlocked();
$current_ip = $unlocker->getIP();
$is_hard_blocked = $unlocker->isInHardBlockList() || $too_many_visits;

// Получаем URL для возврата
$return_url = isset($_SESSION['original_url']) ? $_SESSION['original_url'] : '/';

// Обработка формы с интегрированной защитой
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $verification_passed = false;
    $bot_protection_result = null;
    
    // Проверяем данные интегрированной защиты от ботов
    if (isset($_POST['bot_protection_data'])) {
        $bot_data = json_decode($_POST['bot_protection_data'], true);
        if ($bot_data && isset($bot_data['verification_result'])) {
            $bot_protection_result = $bot_data['verification_result'];
            $verification_passed = ($bot_protection_result['success'] && 
                                  $bot_protection_result['confidence'] >= 40 && 
                                  $bot_protection_result['riskScore'] <= 85);
        }
    }
    
    // Дополнительная проверка Google reCAPTCHA, если включена
    $recaptcha_passed = true;
    if (defined('RECAPTCHA_SITE_KEY') && defined('RECAPTCHA_SECRET_KEY') && 
        !empty(RECAPTCHA_SITE_KEY) && !empty(RECAPTCHA_SECRET_KEY)) {
        
        if (isset($_POST['g-recaptcha-response'])) {
            $recaptcha_response = $_POST['g-recaptcha-response'];
            $recaptcha_passed = $unlocker->verifyRecaptcha($recaptcha_response);
        } else {
            $recaptcha_passed = false;
        }
    }
    
    // Сохраняем URL возврата из POST-запроса
    if (isset($_POST['return_url']) && !empty($_POST['return_url'])) {
        $return_url = $_POST['return_url'];
        if ((function_exists('filter_var') && filter_var($return_url, FILTER_VALIDATE_URL)) && 
            (strpos($return_url, '/') === 0 || parse_url($return_url, PHP_URL_HOST) === $_SERVER['HTTP_HOST'])) {
            $_SESSION['original_url'] = $return_url;
        }
    }
    
    // Проверяем результаты всех проверок
    if ($is_hard_blocked) {
        $error_message = "Ваш IP-адрес был жестко заблокирован из-за подозрительной активности. Свяжитесь с администратором.";
        $unlocker->logUnlockAttempt(false);
    } else {
        $all_checks_passed = $verification_passed && $recaptcha_passed;
        
        if ($all_checks_passed) {
            if ($unlocker->unblockIP()) {
                $unlocker->cleanupRequestCounters();
                $success_message = "Ваш IP-адрес $current_ip успешно разблокирован!";
                $unlocker->logUnlockAttempt(true);
                $is_blocked = false;
            } else {
                $error_message = "Не удалось разблокировать IP-адрес. Пожалуйста, попробуйте еще раз.";
                $unlocker->logUnlockAttempt(false);
            }
        } else {
            $reasons = array();
            if (!$verification_passed) {
                $reasons[] = "интегрированная защита от ботов";
            }
            if (!$recaptcha_passed) {
                $reasons[] = "Google reCAPTCHA";
            }
            
            $error_message = "Проверка не пройдена (" . implode(", ", $reasons) . "). Пожалуйста, попробуйте еще раз.";
            $unlocker->logUnlockAttempt(false);
        }
    }
    
    $return_url = isset($_SESSION['original_url']) ? $_SESSION['original_url'] : '/';
}

// Заголовки для предотвращения кеширования
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Content-Type: text/html; charset=utf-8");

// Подключаем HTML шаблон
require_once 'unlock_template.php';
?>
