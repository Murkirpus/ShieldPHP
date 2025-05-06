<?php
/**
 * Анализатор логов NGINX
 * Группировка по IP адресу и User Agent
 * Совместимость с PHP 5.6-8.3
 * С поддержкой ограничений open_basedir
 * Оптимизированная версия
 */

// Настройки отображения ошибок и памяти
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
ini_set('memory_limit', '256M'); // Пытаемся увеличить лимит памяти, если это разрешено на хостинге

// Проверка авторизации
require_once $_SERVER['DOCUMENT_ROOT'] . '/dos/settings.php';

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

// Проверяем наличие обязательных файлов
if (!file_exists('logs_functions.php') || !file_exists('logs_display.php')) {
    die('Ошибка: отсутствуют необходимые файлы (logs_functions.php или logs_display.php)');
}

// Подключаем файлы с функциями
require_once 'logs_functions.php';  // Основные функции для работы с логами
require_once 'logs_display.php';    // Функции для отображения данных

// Запускаем сессию для сохранения данных между запросами
if (!isset($_SESSION)) {
    session_start();
}

// Определение максимально допустимого размера загружаемого файла
$maxFileUploadSize = min(
    convertToBytes(ini_get('upload_max_filesize')),
    convertToBytes(ini_get('post_max_size')),
    convertToBytes(ini_get('memory_limit'))
);

// Обработка AJAX-запросов
if (isset($_GET['action'])) {
    switch ($_GET['action']) {
        case 'get_logs':
            handleAjaxRequest();
            exit;
        case 'analyze_progress':
            // Здесь можно добавить обработку проверки прогресса анализа для очень больших файлов
            exit;
    }
}

// Инициализация переменных для предотвращения ошибок
$logData = array();
$logSource = '';
$hasData = false;
$errorMessages = array();
$successMessages = array();
$ipFilter = isset($_GET['ip']) ? htmlspecialchars($_GET['ip']) : '';
$uaFilter = isset($_GET['ua']) ? htmlspecialchars($_GET['ua']) : '';
$refererFilter = isset($_GET['referer']) ? htmlspecialchars($_GET['referer']) : '';
$statusFilter = isset($_GET['status']) ? htmlspecialchars($_GET['status']) : '';
$limit = isset($_GET['limit']) && is_numeric($_GET['limit']) ? (int)$_GET['limit'] : 100;

// Очистка данных, если запрошено (GET запрос для упрощения)
if (isset($_GET['clear']) && $_GET['clear'] == 1) {
    unset($_SESSION['log_data']);
    unset($_SESSION['log_source']);
    unset($_SESSION['parsed_logs']);
    $successMessages[] = 'Данные успешно очищены';
    // Перенаправляем, чтобы избежать повторной отправки запроса
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Очистка данных, если запрошено (POST запрос через форму)
if (isset($_POST['clear_data'])) {
    // CSRF проверка опциональна для операции очистки
    unset($_SESSION['log_data']);
    unset($_SESSION['log_source']);
    unset($_SESSION['parsed_logs']);
    $successMessages[] = 'Данные успешно очищены';
    
    // Перенаправляем, чтобы избежать повторной отправки формы
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Если был загружен файл
if (isset($_FILES['log_file']) && $_FILES['log_file']['error'] == UPLOAD_ERR_OK) {
    $uploadedFile = $_FILES['log_file'];
    $tempFilePath = saveUploadedFile($uploadedFile);
    
    if ($tempFilePath === false) {
        $errorMessages[] = 'Ошибка при загрузке файла. Проверьте тип файла и права на запись.';
    } else {
        try {
            $logData = processUploadedFile($tempFilePath);
            $logSource = 'Загруженный файл: ' . htmlspecialchars($uploadedFile['name']);
            
            // Сохраняем данные в сессии
            saveToSession($logData, $logSource);
            
            // Удаляем временный файл
            @unlink($tempFilePath);
            $hasData = true;
            $successMessages[] = 'Файл успешно загружен и проанализирован: ' . htmlspecialchars($uploadedFile['name']);
        } catch (Exception $e) {
            $errorMessages[] = 'Ошибка при обработке файла: ' . $e->getMessage();
        }
    }
}
// Если указан путь к файлу логов на сервере
elseif (isset($_POST['log_path']) && !empty($_POST['log_path'])) {
    $logPath = htmlspecialchars($_POST['log_path']);
    $maxLines = isset($_POST['max_lines']) && is_numeric($_POST['max_lines']) ? (int)$_POST['max_lines'] : 50000;
    
    // Проверяем и ограничиваем значение maxLines
    if ($maxLines < 1000) $maxLines = 1000;
    if ($maxLines > 1000000) $maxLines = 1000000;
    
    // Попытка прочитать файл логов напрямую с сервера
    $logData = readLogFileFromServer($logPath, $maxLines);
    
    if (isset($logData['error'])) {
        $errorMessages[] = $logData['error'];
    } else {
        $logSource = 'Файл на сервере: ' . htmlspecialchars($logPath);
        
        // Если есть предупреждение о частичном анализе, добавляем его к источнику
        if (isset($logData['warning'])) {
            $logSource .= ' (' . $logData['warning'] . ')';
        }
        
        // Сохраняем данные в сессии
        saveToSession($logData, $logSource);
        $hasData = true;
        $successMessages[] = 'Файл успешно проанализирован: ' . htmlspecialchars($logPath);
    }
}
// Если был отправлен текст лога
elseif (isset($_POST['log_content']) && !empty($_POST['log_content'])) {
    $logContent = $_POST['log_content'];
    $logData = parseLogContent($logContent);
    $logSource = 'Вставленный текст лога';
    
    // Сохраняем данные в сессии
    saveToSession($logData, $logSource);
    $hasData = true;
    $successMessages[] = 'Текст лога успешно проанализирован';
}
// Используем данные из сессии, если они есть
elseif (isset($_SESSION['log_data'])) {
    $logData = $_SESSION['log_data'];
    $logSource = isset($_SESSION['log_source']) ? $_SESSION['log_source'] : 'Сохраненные данные';
    $hasData = true;
}

// Установка лимита отображаемых результатов
if ($limit <= 0) {
    $limit = 100;
}

// Функция для сохранения данных в сессию
function saveToSession($logData, $logSource) {
    $_SESSION['log_data'] = $logData;
    $_SESSION['log_source'] = $logSource;
    $_SESSION['parsed_logs'] = isset($logData['parsedLogs']) ? $logData['parsedLogs'] : array();
}

// Подключаем HTML шаблон интерфейса
include 'logs_template.php';