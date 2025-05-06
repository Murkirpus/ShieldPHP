<?php
// /dos/auto_whitelist.php
// Скрипт для автоматического добавления IP в белый список
// Разместите его в безопасном месте и настройте права доступа

// Подключаем класс мониторинга безопасности
require_once 'security_monitor.php';

// Функция для записи логов
function log_message($message) {
    $log_file = dirname(__FILE__) . '/auto_whitelist.log';
    $log_entry = date('Y-m-d H:i:s') . ' - ' . $message . "\n";
    file_put_contents($log_file, $log_entry, FILE_APPEND);
}

// Класс для автоматического управления белым списком
class AutoWhitelistManager {
    private $admin_ips = [
        // Добавьте здесь IP-адреса, которые всегда должны быть в белом списке
        // Например, ваш домашний IP, рабочий IP и т.д.
        // '192.168.1.100',
        // '2001:db8::1',
    ];
    
    private $dos_dir;
    private $whitelisted_ips = [];
    
    public function __construct() {
        $this->dos_dir = dirname(__FILE__) . '/';
        $this->loadWhitelist();
    }
    
    // Загрузка белого списка
    private function loadWhitelist() {
        $whitelist_file = $this->dos_dir . 'whitelist_ips.php';
        
        if (file_exists($whitelist_file)) {
            include $whitelist_file;
            if (isset($whitelist_ips) && is_array($whitelist_ips)) {
                $this->whitelisted_ips = $whitelist_ips;
            }
        }
    }
    
    // Сохранение белого списка
    private function saveWhitelist() {
        try {
            $whitelist_file = $this->dos_dir . 'whitelist_ips.php';
            $content = "<?php\n\$whitelist_ips = " . var_export($this->whitelisted_ips, true) . ";\n";
            
            // Атомарная запись
            $tmp_file = $whitelist_file . '.tmp';
            if (file_put_contents($tmp_file, $content) !== false) {
                rename($tmp_file, $whitelist_file);
                return true;
            }
            return false;
        } catch(Exception $e) {
            log_message("Ошибка сохранения белого списка: " . $e->getMessage());
            return false;
        }
    }
    
    // Добавление IP в белый список
    public function addToWhitelist($ip) {
        // Проверка, что IP валидный
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
            log_message("Попытка добавить некорректный IP: $ip");
            return false;
        }
        
        // Проверка, есть ли IP уже в белом списке
        if (in_array($ip, $this->whitelisted_ips)) {
            log_message("IP $ip уже в белом списке");
            return true;
        }
        
        // Добавляем IP в белый список
        $this->whitelisted_ips[] = $ip;
        
        // Сохраняем обновленный белый список
        $result = $this->saveWhitelist();
        
        if ($result) {
            log_message("Успешно добавлен IP в белый список: $ip");
        } else {
            log_message("Ошибка при добавлении IP в белый список: $ip");
        }
        
        return $result;
    }
    
    // Проверка и обновление белого списка с админскими IP
    public function syncAdminIPs() {
        $changes_made = false;
        
        foreach ($this->admin_ips as $admin_ip) {
            if (!in_array($admin_ip, $this->whitelisted_ips)) {
                $this->whitelisted_ips[] = $admin_ip;
                log_message("Добавлен админский IP в белый список: $admin_ip");
                $changes_made = true;
            }
        }
        
        if ($changes_made) {
            $this->saveWhitelist();
            log_message("Синхронизация админских IP завершена");
            return true;
        }
        
        return false;
    }
}

// Инициализируем менеджер белого списка
$manager = new AutoWhitelistManager();

// Синхронизируем админские IP-адреса
$manager->syncAdminIPs();

// Если запрос пришел с параметром добавления IP
if (isset($_GET['add_ip']) && !empty($_GET['add_ip'])) {
    $ip = trim($_GET['add_ip']);
    
    // Для безопасности можно добавить секретный ключ
    $secret = isset($_GET['secret']) ? $_GET['secret'] : '';
    $valid_secret = 'ваш_секретный_ключ'; // Измените на свой секретный ключ
    
    if ($secret === $valid_secret) {
        if ($manager->addToWhitelist($ip)) {
            echo "IP $ip успешно добавлен в белый список.";
        } else {
            echo "Ошибка при добавлении IP $ip в белый список.";
        }
    } else {
        echo "Неверный секретный ключ.";
        log_message("Попытка несанкционированного доступа с неверным секретным ключом");
    }
}

// Если нужно добавить текущий IP (можно использовать для автоматических скриптов)
if (isset($_GET['add_current']) && $_GET['add_current'] === '1') {
    $secret = isset($_GET['secret']) ? $_GET['secret'] : '';
    $valid_secret = 'ваш_секретный_ключ'; // Измените на свой секретный ключ
    
    if ($secret === $valid_secret) {
        // Определяем IP клиента (аналогично как в основном скрипте)
        $ip_keys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'REMOTE_ADDR'];
        $client_ip = '';
        
        foreach ($ip_keys as $key) {
            if (isset($_SERVER[$key])) {
                $client_ip = $_SERVER[$key];
                break;
            }
        }
        
        if (!empty($client_ip)) {
            if ($manager->addToWhitelist($client_ip)) {
                echo "Текущий IP $client_ip успешно добавлен в белый список.";
            } else {
                echo "Ошибка при добавлении текущего IP $client_ip в белый список.";
            }
        } else {
            echo "Не удалось определить текущий IP.";
        }
    } else {
        echo "Неверный секретный ключ.";
        log_message("Попытка несанкционированного доступа с неверным секретным ключом");
    }
}
?>