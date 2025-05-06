<?php
/**
 * nginx.php - Скрипт для перезапуска Nginx
 * 
 * Этот скрипт должен быть настроен для запуска с правами, необходимыми
 * для выполнения команды reload для Nginx.
 */

// Логирование процесса
function log_message($message) {
    $log_file = __DIR__ . '/nginx_reload.log';
    $log_entry = date('Y-m-d H:i:s') . ' - ' . $message . "\n";
    file_put_contents($log_file, $log_entry, FILE_APPEND);
}

// Проверяем, включена ли функция exec
if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))))) {
    log_message("Запуск перезагрузки Nginx");
    
    // Пробуем перезагрузить Nginx
    $output = array();
    $return_var = 0;
    
    // Вариант 1: прямой вызов nginx -s reload
    exec('sudo /usr/sbin/nginx -s reload 2>&1', $output, $return_var);
    
    if ($return_var !== 0) {
        log_message("Ошибка при прямом перезапуске: " . implode("\n", $output));
        
        // Вариант 2: попробуем через systemctl
        exec('sudo systemctl reload nginx 2>&1', $output, $return_var);
        
        if ($return_var !== 0) {
            log_message("Ошибка при использовании systemctl: " . implode("\n", $output));
            
            // Вариант 3: использование сигналов
            exec('pkill -HUP nginx 2>&1', $output, $return_var);
            
            if ($return_var !== 0) {
                log_message("Все попытки перезапуска неудачны. Последняя ошибка: " . implode("\n", $output));
                echo "Ошибка: Не удалось перезапустить Nginx\n";
                exit(1);
            } else {
                log_message("Nginx перезапущен с помощью сигнала HUP");
            }
        } else {
            log_message("Nginx перезапущен с помощью systemctl");
        }
    } else {
        log_message("Nginx успешно перезапущен");
    }
    
    echo "Nginx успешно перезапущен\n";
} else {
    log_message("Функция exec отключена в PHP");
    echo "Ошибка: Функция exec отключена в PHP\n";
    exit(1);
}
?>