<?php
//require_once $_SERVER['DOCUMENT_ROOT'] . '/dos/security_monitor.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/temp/dos-files/monitor-files.php';
// Установка заголовков для предотвращения кеширования
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Функция для эмуляции выполнения длительной задачи
function emulateLoading($totalSteps = 10, $totalTime = 5) {
    // Рассчитываем задержку для каждого шага
    $stepDelay = $totalTime / $totalSteps;
    
    // Отключаем буферизацию вывода
    ob_implicit_flush(true);
    ob_end_flush();
    
    // HTML-начало с прогресс-баром
    echo '<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Эмуляция загрузки</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f5f5f5;
            touch-action: none;
        }
        .progress-container {
            width: 80%;
            max-width: 500px;
            margin: 0 auto;
            background-color: #e0e0e0;
            border-radius: 5px;
            padding: 3px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.2);
        }
        .progress-bar {
            height: 20px;
            background-color: #4CAF50;
            border-radius: 3px;
            width: 0%;
            transition: width 0.3s ease;
        }
        .status {
            margin-top: 20px;
            font-size: 18px;
        }
        .spinner {
            display: inline-block;
            border: 4px solid rgba(0,0,0,0.1);
            border-left-color: #4CAF50;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            vertical-align: middle;
            margin-right: 10px;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <h1>Пожалуйста, подождите</h1>
    <div class="progress-container">
        <div class="progress-bar" id="progress"></div>
    </div>
    <div class="status">
        <div class="spinner"></div>
        <span id="status-text">Загрузка...</span>
    </div>
    <script>
        function updateProgress(percent, message) {
            document.getElementById("progress").style.width = percent + "%";
            document.getElementById("status-text").innerText = message;
        }
    </script>';
    
    // Эмуляция поэтапной загрузки
    $loadingMessages = [
        "Инициализация...",
        "Подключение к серверу...",
        "Проверка конфигурации...",
        "Установка соединения с базой данных...",
        "Получение данных...",
        "Обработка информации...",
        "Анализ данных...",
        "Подготовка временных файлов...",
        "Формирование отчета...",
        "Оптимизация...",
        "Сжатие данных...",
        "Подготовка результатов...",
        "Кэширование результатов...",
        "Финальная проверка...",
        "Завершение..."
    ];
    
    // Проходим по всем шагам загрузки
    for ($i = 0; $i < $totalSteps; $i++) {
        // Вычисляем процент выполнения
        $percent = ($i + 1) * (100 / $totalSteps);
        
        // Получаем сообщение для текущего шага
        $message = isset($loadingMessages[$i]) ? $loadingMessages[$i] : "Шаг " . ($i + 1);
        
        // Обновляем прогресс-бар
        echo '<script>updateProgress(' . $percent . ', "' . $message . '");</script>';
        
        // Очищаем буфер вывода, чтобы клиент получил обновление
        flush();
        
        // Задержка для эмуляции выполнения задачи
        sleep($stepDelay);
    }
    
    // Завершаем HTML и показываем сообщение о завершении
    echo '<script>
        updateProgress(100, "Загрузка завершена!");
        setTimeout(function() {
            // Скрываем спиннер
            document.querySelector(".spinner").style.display = "none";
            // Обновляем текст статуса
            document.getElementById("status-text").innerText = "Загрузка завершена!";
            // Добавляем сообщение о завершении и ссылку на обновление
            document.body.innerHTML += "<h2>Загрузка успешно завершена!</h2>" + 
                                       "<p>Страница полностью загружена.</p>" + 
                                       "<p><a href=\'" + window.location.href + "\' class=\'reload-button\'>Обновить страницу</a></p>";
        }, 500);
    </script>
    <style>
        .reload-button {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            transition: background-color 0.3s;
        }
        .reload-button:hover {
            background-color: #45a049;
            text-decoration: none;
            color: white;
        }
    </style>
</body>
</html>';
}

// Вызываем функцию с настройками: 15 шагов, общее время 20 секунд
emulateLoading(1, 3);
?>