<?php
/**
 * Файл безопасности с защитой от слишком частых запросов
 * Размещать в /temp/dos-files/security_monitor.php
 */

// Класс защиты от слишком частых запросов
class RequestThrottler {
    // Настройки по умолчанию
    private $requestLimit = 3;        // Максимальное количество запросов
    private $timeWindow = 60;         // Временное окно в секундах
    private $cooldownTime = 300;      // Время блокировки в секундах (5 минут)
    private $dataFile;                // Путь к файлу данных
    private $ipAddress;               // IP-адрес клиента
    private $debugMode = false;       // Режим отладки
    
    /**
     * Конструктор класса
     * 
     * @param int $requestLimit Максимальное количество запросов
     * @param int $timeWindow Временное окно в секундах
     * @param int $cooldownTime Время блокировки в секундах
     * @param bool $debugMode Режим отладки
     */
    public function __construct($requestLimit = 5, $timeWindow = 60, $cooldownTime = 300, $debugMode = false) {
        // Устанавливаем настройки
        $this->requestLimit = $requestLimit;
        $this->timeWindow = $timeWindow;
        $this->cooldownTime = $cooldownTime;
        $this->debugMode = $debugMode;
        
        // Определяем IP-адрес клиента
        $this->ipAddress = $this->getClientIP();
        
        // Определяем путь к файлу данных
        $this->dataFile = $_SERVER['DOCUMENT_ROOT'] . '/temp/dos-files/throttle_data.json';
        
        // Создаем директорию, если она не существует
        if (!is_dir(dirname($this->dataFile))) {
            mkdir(dirname($this->dataFile), 0755, true);
        }
    }
    
    /**
     * Получаем реальный IP-адрес клиента
     * 
     * @return string IP-адрес
     */
    private function getClientIP() {
        // Проверяем различные заголовки для определения IP
        $ipKeys = [
            'HTTP_CF_CONNECTING_IP',   // Cloudflare
            'HTTP_CLIENT_IP',          // Общий
            'HTTP_X_FORWARDED_FOR',    // Прокси
            'HTTP_X_FORWARDED',        // Прокси
            'HTTP_FORWARDED_FOR',      // Прокси
            'HTTP_FORWARDED',          // Прокси
            'REMOTE_ADDR'              // Прямое соединение
        ];
        
        foreach ($ipKeys as $key) {
            if (isset($_SERVER[$key]) && filter_var($_SERVER[$key], FILTER_VALIDATE_IP)) {
                return $_SERVER[$key];
            }
        }
        
        // Возвращаем REMOTE_ADDR как последний вариант
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    /**
     * Загружаем данные о запросах
     * 
     * @return array Данные о запросах
     */
    private function loadData() {
        if (file_exists($this->dataFile)) {
            $json = file_get_contents($this->dataFile);
            $data = json_decode($json, true);
            
            if (json_last_error() === JSON_ERROR_NONE && is_array($data)) {
                return $data;
            }
        }
        
        // Возвращаем пустую структуру данных, если файл не существует или поврежден
        return ['ips' => [], 'blocked' => []];
    }
    
    /**
     * Сохраняем данные о запросах
     * 
     * @param array $data Данные для сохранения
     */
    private function saveData($data) {
        file_put_contents($this->dataFile, json_encode($data), LOCK_EX);
        chmod($this->dataFile, 0644);
    }
    
    /**
     * Очищаем устаревшие данные
     * 
     * @param array $data Данные о запросах
     * @return array Очищенные данные
     */
    private function cleanOldData($data) {
        $now = time();
        
        // Очищаем историю запросов
        foreach ($data['ips'] as $ip => $requests) {
            foreach ($requests as $timestamp => $count) {
                if ($timestamp + $this->timeWindow < $now) {
                    unset($data['ips'][$ip][$timestamp]);
                }
            }
            
            // Удаляем IP из списка, если нет записей
            if (empty($data['ips'][$ip])) {
                unset($data['ips'][$ip]);
            }
        }
        
        // Очищаем список заблокированных IP
        foreach ($data['blocked'] as $ip => $timestamp) {
            if ($timestamp + $this->cooldownTime < $now) {
                unset($data['blocked'][$ip]);
            }
        }
        
        return $data;
    }
    
    /**
     * Проверяем, заблокирован ли IP
     * 
     * @param array $data Данные о запросах
     * @return bool|int Время оставшейся блокировки или false
     */
    private function isIPBlocked($data) {
        $now = time();
        
        if (isset($data['blocked'][$this->ipAddress])) {
            $remainingTime = ($data['blocked'][$this->ipAddress] + $this->cooldownTime) - $now;
            
            if ($remainingTime > 0) {
                return $remainingTime;
            } else {
                return false;
            }
        }
        
        return false;
    }
    
    /**
     * Блокируем IP
     * 
     * @param array $data Данные о запросах
     * @return array Обновленные данные
     */
    private function blockIP($data) {
        $data['blocked'][$this->ipAddress] = time();
        return $data;
    }
    
    /**
     * Проверяем превышение лимита запросов
     * 
     * @param array $data Данные о запросах
     * @return bool Результат проверки
     */
    private function checkLimit($data) {
        $now = time();
        $totalRequests = 0;
        
        // Считаем количество запросов за временное окно
        if (isset($data['ips'][$this->ipAddress])) {
            foreach ($data['ips'][$this->ipAddress] as $timestamp => $count) {
                if ($timestamp + $this->timeWindow >= $now) {
                    $totalRequests += $count;
                }
            }
        }
        
        // Возвращаем результат проверки
        return $totalRequests >= $this->requestLimit;
    }
    
    /**
     * Регистрируем текущий запрос
     * 
     * @param array $data Данные о запросах
     * @return array Обновленные данные
     */
    private function registerRequest($data) {
        $now = time();
        
        // Инициализируем структуру, если это первый запрос с IP
        if (!isset($data['ips'][$this->ipAddress])) {
            $data['ips'][$this->ipAddress] = [];
        }
        
        // Добавляем запрос
        $data['ips'][$this->ipAddress][$now] = 1;
        
        return $data;
    }
    
    /**
     * Проверяем запрос и принимаем решение
     * 
     * @return bool Разрешен ли запрос
     */
    public function checkRequest() {
        // Загружаем данные
        $data = $this->loadData();
        
        // Очищаем устаревшие данные
        $data = $this->cleanOldData($data);
        
        // Проверяем блокировку
        $blockedTime = $this->isIPBlocked($data);
        if ($blockedTime !== false) {
            $this->sendBlockedResponse($blockedTime);
            return false;
        }
        
        // Проверяем лимит
        if ($this->checkLimit($data)) {
            // Блокируем IP
            $data = $this->blockIP($data);
            $this->saveData($data);
            
            $this->sendBlockedResponse($this->cooldownTime);
            return false;
        }
        
        // Регистрируем запрос
        $data = $this->registerRequest($data);
        $this->saveData($data);
        
        return true;
    }
    
    /**
     * Отправляем ответ о блокировке
     * 
     * @param int $remainingTime Оставшееся время блокировки
     */
    private function sendBlockedResponse($remainingTime) {
        $minutes = ceil($remainingTime / 60);
        
        // Устанавливаем статус 429 Too Many Requests
        header('HTTP/1.1 429 Too Many Requests');
        header('Retry-After: ' . $remainingTime);
        
        echo '<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Слишком много запросов</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #fff;
            padding: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #d9534f;
        }
        .timer {
            font-size: 24px;
            margin: 20px 0;
            font-weight: bold;
        }
        .info {
            color: #666;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Слишком много запросов</h1>
        <div class="info">Вы выполнили слишком много запросов за короткий промежуток времени.</div>
        <div class="timer">Пожалуйста, подождите <span id="countdown">' . $remainingTime . '</span> секунд</div>
        <div>Или вернитесь через примерно ' . $minutes . ' ' . $this->pluralizeMinutes($minutes) . '</div>
    </div>
    
    <script>
        // Обратный отсчет
        let remainingTime = ' . $remainingTime . ';
        const countdownElement = document.getElementById("countdown");
        
        const timer = setInterval(function() {
            remainingTime--;
            countdownElement.textContent = remainingTime;
            
            if (remainingTime <= 0) {
                clearInterval(timer);
                window.location.reload();
            }
        }, 1000);
    </script>
</body>
</html>';
        
        // Завершаем выполнение скрипта
        exit;
    }
    
    /**
     * Склонение слова "минута"
     * 
     * @param int $minutes Количество минут
     * @return string Склоненное слово
     */
    private function pluralizeMinutes($minutes) {
        $cases = [2, 0, 1, 1, 1, 2];
        $words = ['минуту', 'минуты', 'минут'];
        
        return $words[($minutes % 100 > 4 && $minutes % 100 < 20) ? 2 : $cases[min($minutes % 10, 5)]];
    }
    
    /**
     * Выводим отладочную информацию
     */
    public function debug() {
        if (!$this->debugMode) {
            return;
        }
        
        $data = $this->loadData();
        
        echo '<pre>';
        echo 'IP: ' . $this->ipAddress . "\n";
        echo 'Limit: ' . $this->requestLimit . ' requests per ' . $this->timeWindow . " seconds\n";
        echo 'Cooldown: ' . $this->cooldownTime . " seconds\n\n";
        
        echo "Request history:\n";
        print_r($data);
        echo '</pre>';
    }
}

// Создаем экземпляр класса с настройками
// Параметры: 
// - максимальное число запросов (10)
// - в течение какого времени в секундах (60 сек = 1 минута)
// - время блокировки при превышении в секундах (300 сек = 5 минут)
// - режим отладки (false)
$throttler = new RequestThrottler(10, 60, 300, false);

// Проверяем запрос
if (!$throttler->checkRequest()) {
    // Если запрос заблокирован, скрипт уже завершен внутри класса
    exit;
}

// Если запрос прошел проверку, продолжаем выполнение
// $throttler->debug(); // Раскомментировать для отладки

// Конец файла безопасности
?>