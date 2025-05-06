<?php
// super_simple_unlock.php - создайте этот файл в папке /dos/
// Отключаем вывод ошибок
error_reporting(0);
ini_set('display_errors', 0);

// Получаем IP пользователя
$ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

// Пути к файлам
$cache_file = __DIR__ . '/blocked_ips.php';
$htaccess_file = dirname(__DIR__) . '/.htaccess';

// Флаг успешной разблокировки
$success = false;
$message = '';

// Если нажата кнопка разблокировки
if (isset($_POST['unlock'])) {
    // Очистка файла блокировок
    if (file_exists($cache_file)) {
        // Создаем пустой массив блокировок
        $blocked_ips = array();
        $content = "<?php\n\$blocked_ips = " . var_export($blocked_ips, true) . ";\n";
        
        // Записываем в файл
        if (file_put_contents($cache_file, $content) !== false) {
            $message .= "• Файл блокировок очищен успешно.<br>";
            $success = true;
        } else {
            $message .= "• Ошибка при очистке файла блокировок.<br>";
        }
    } else {
        $message .= "• Файл блокировок не найден.<br>";
    }
    
    // Очистка .htaccess
    if (file_exists($htaccess_file) && is_writable($htaccess_file)) {
        $htaccess_content = file_get_contents($htaccess_file);
        if ($htaccess_content !== false) {
            // Удаляем все строки с "Deny from"
            $new_content = preg_replace('/Deny from .*\n?/', '', $htaccess_content);
            if (file_put_contents($htaccess_file, $new_content) !== false) {
                $message .= "• Файл .htaccess очищен успешно.<br>";
                $success = true;
            } else {
                $message .= "• Ошибка при очистке файла .htaccess.<br>";
            }
        }
    }
    
    // Создание проверочного файла, чтобы убедиться, что PHP работает
    $test_file = __DIR__ . '/unlock_test.txt';
    if (file_put_contents($test_file, "Unlock test at " . date('Y-m-d H:i:s')) !== false) {
        $message .= "• Тестовый файл создан успешно.<br>";
    } else {
        $message .= "• Ошибка создания тестового файла - проблема с правами доступа.<br>";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Сброс всех блокировок</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .success { color: green; background: #f0fff0; padding: 10px; border-radius: 5px; }
        .error { color: red; background: #fff0f0; padding: 10px; border-radius: 5px; }
        button { background: #4CAF50; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }
        h3 { margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Инструмент сброса всех блокировок</h2>
        
        <?php if (!empty($message)): ?>
            <div class="<?php echo $success ? 'success' : 'error'; ?>">
                <p><strong><?php echo $success ? 'Действия выполнены:' : 'Результат:'; ?></strong></p>
                <p><?php echo $message; ?></p>
                <p>Ваш IP: <?php echo $ip; ?></p>
                
                <?php if ($success): ?>
                    <p>Теперь вы можете вернуться на главную страницу:</p>
                    <p><a href="/">Вернуться на главную</a></p>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <form method="post">
            <p>Этот инструмент сбросит <strong>ВСЕ</strong> блокировки IP и очистит .htaccess.</p>
            <button type="submit" name="unlock">Сбросить все блокировки</button>
        </form>
        
        <h3>Текущий статус:</h3>
        <ul>
            <li>Ваш IP: <?php echo $ip; ?></li>
            <li>Файл блокировок: <?php echo file_exists($cache_file) ? 'существует' : 'не найден'; ?></li>
            <li>Файл .htaccess: <?php echo file_exists($htaccess_file) ? (is_writable($htaccess_file) ? 'существует и доступен для записи' : 'существует, но НЕ доступен для записи') : 'не найден'; ?></li>
        </ul>
    </div>
</body>
</html>