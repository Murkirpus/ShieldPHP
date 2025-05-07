<?php
/**
 * Обработчик 404 ошибок с анализом и защитой от сканирования
 * 
 * Файл: /dos/check_404.php
 */

// Определяем корневую директорию
define('ROOT_DIR', dirname(dirname(__FILE__)));

// Устанавливаем заголовок 404
header("HTTP/1.0 404 Not Found");
header("Status: 404 Not Found");

// Подключаем файлы системы безопасности
require_once ROOT_DIR . '/dos/settings.php';
require_once ROOT_DIR . '/dos/security_monitor.php';

// Получаем запрошенный URI
$request_uri = isset($_SERVER['REDIRECT_URL']) ? $_SERVER['REDIRECT_URL'] : $_SERVER['REQUEST_URI'];
$request_uri = strtok($request_uri, '?'); // Удаляем query string

// Создаем экземпляр монитора безопасности
$security_monitor = new LightSecurityMonitor();

// Вызываем метод мониторинга запросов, который проверит все
// включая checkHoneypotUrl() внутри monitorRequest()
$security_monitor->monitorRequest();

// Проверяем, связан ли запрос с DLE
$is_dle_request = preg_match('/(\.html$|\/page\/|\/tags\/|\/user\/)/i', $request_uri);

// Если это запрос к DLE и есть index.php, используем стандартную DLE 404 страницу
if ($is_dle_request && file_exists(ROOT_DIR . '/index.php')) {
    // Переадресация на index.php сохранит внешний вид сайта
    header("Location: /index.php?do=404");
    exit;
}

// Выводим HTML-страницу 404
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Страница не найдена</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            text-align: center;
        }
        .container {
            max-width: 600px;
            padding: 40px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            font-size: 36px;
            margin-bottom: 20px;
            color: #e74c3c;
        }
        p {
            font-size: 18px;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        a {
            color: #3498db;
            text-decoration: none;
            font-weight: bold;
        }
        a:hover {
            text-decoration: underline;
        }
        .error-code {
            font-size: 120px;
            color: #e74c3c;
            font-weight: bold;
            margin: 0;
            line-height: 1;
            opacity: 0.2;
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: -1;
        }
    </style>
</head>
<body>
    <div class="error-code">404</div>
    <div class="container">
        <h1>Страница не найдена</h1>
        <p>Извините, запрошенная вами страница не существует или была перемещена.</p>
        <p>Вы можете вернуться на <a href="/">главную страницу</a> или воспользоваться поиском.</p>
    </div>
</body>
</html>
