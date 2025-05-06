<?php
// Установка заголовков безопасности
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Content-Type: text/html; charset=utf-8');

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


// Файл для хранения правил
$rules_file = __DIR__ . '/firewall_rules.json';

// Функция для проверки валидности IPv4
function is_valid_ipv4($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
}

// Функция для проверки валидности IPv6
function is_valid_ipv6($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
}

// Функция для проверки валидности порта
function is_valid_port($port) {
    return is_numeric($port) && $port > 0 && $port <= 65535;
}

// Функция для проверки безопасности входных данных
function is_safe_input($input) {
    // Проверяем, что входные данные не содержат опасных символов
    if (preg_match('/[;&|`$><]/', $input)) {
        return false;
    }
    return true;
}

// Функция для логирования действий
function log_action($ip, $port, $action, $success) {
    $log_file = __DIR__ . '/firewall_access.log';
    $date = date('Y-m-d H:i:s');
    $message = "$date - IP: $ip, Port: $port, Action: $action, Success: " . ($success ? 'Да' : 'Нет') . "\n";
    
    // Запись в лог
    file_put_contents($log_file, $message, FILE_APPEND);
}

// Функция для загрузки сохраненных правил
function load_rules() {
    global $rules_file;
    
    if (file_exists($rules_file)) {
        $rules_json = file_get_contents($rules_file);
        return json_decode($rules_json, true) ?: [];
    }
    return [];
}

// Функция для сохранения правил
function save_rules($rules) {
    global $rules_file;
    
    $rules_json = json_encode($rules, JSON_PRETTY_PRINT);
    file_put_contents($rules_file, $rules_json);
}

// Функция для добавления правила
function add_rule($ip, $port, $is_ipv6) {
    $rules = load_rules();
    
    // Проверяем наличие дубликатов (одинаковый IP, порт и статус "открыт")
    $duplicate_found = false;
    $duplicate_id = null;
    
    foreach ($rules as $id => $rule) {
        if ($rule['ip'] === $ip && $rule['port'] == $port && $rule['is_ipv6'] === $is_ipv6 && $rule['status'] === 'открыт') {
            $duplicate_found = true;
            $duplicate_id = $id;
            break;
        }
    }
    
    // Если найден дубликат, возвращаем его ID
    if ($duplicate_found) {
        return $duplicate_id;
    }
    
    // Если нет дубликатов, добавляем новое правило
    $rule_id = uniqid();
    $rules[$rule_id] = [
        'ip' => $ip,
        'port' => $port,
        'is_ipv6' => $is_ipv6,
        'date_added' => date('Y-m-d H:i:s'),
        'status' => 'открыт'
    ];
    
    save_rules($rules);
    return $rule_id;
}

// Функция для удаления правила
function remove_rule($rule_id) {
    $rules = load_rules();
    
    if (isset($rules[$rule_id])) {
        $rule = $rules[$rule_id];
        unset($rules[$rule_id]);
        save_rules($rules);
        return $rule;
    }
    
    return false;
}

// Функция для обновления статуса правила
function update_rule_status($rule_id, $status) {
    $rules = load_rules();
    
    if (isset($rules[$rule_id])) {
        $rules[$rule_id]['status'] = $status;
        save_rules($rules);
        return true;
    }
    
    return false;
}

// Функция для удаления всех дубликатов правил для указанного IP и порта
function remove_duplicate_rules($ip, $port) {
    $rules = load_rules();
    $duplicate_ids = [];
    $count_removed = 0;
    
    // Находим все дубликаты
    foreach ($rules as $rule_id => $rule) {
        if ($rule['ip'] === $ip && $rule['port'] == $port) {
            $duplicate_ids[] = $rule_id;
        }
    }
    
    // Если найдено больше одного правила, оставляем только последнее (самое новое)
    if (count($duplicate_ids) > 1) {
        // Сортируем по дате добавления (от новых к старым)
        usort($duplicate_ids, function($a, $b) use ($rules) {
            return strtotime($rules[$b]['date_added']) - strtotime($rules[$a]['date_added']);
        });
        
        // Пропускаем первый элемент (самый новый) и удаляем остальные
        $keep_id = array_shift($duplicate_ids);
        
        foreach ($duplicate_ids as $id) {
            unset($rules[$id]);
            $count_removed++;
        }
        
        save_rules($rules);
    }
    
    return $count_removed;
}

// Создаем файл для проверки iptables
function create_check_iptables_file() {
    $check_file = __DIR__ . '/check_iptables.php';
    $content = <<<'EOT'
<?php
header('Content-Type: application/json');

// Проверка доступности iptables
$output = [];
$return_var = 0;
exec('sudo /sbin/iptables -L 2>&1', $output, $return_var);

$iptables_available = ($return_var === 0);

// Проверка доступности ip6tables
$output_ipv6 = [];
$return_var_ipv6 = 0;
exec('sudo /sbin/ip6tables -L 2>&1', $output_ipv6, $return_var_ipv6);

$ip6tables_available = ($return_var_ipv6 === 0);

echo json_encode([
    'iptables_available' => $iptables_available,
    'ip6tables_available' => $ip6tables_available,
    'iptables_output' => implode("\n", $output),
    'ip6tables_output' => implode("\n", $output_ipv6)
]);
EOT;

    file_put_contents($check_file, $content);
}

// Если файл проверки iptables не существует, создаем его
if (!file_exists(__DIR__ . '/check_iptables.php')) {
    create_check_iptables_file();
}

// Обработка запроса
$result = '';
$success = false;
$is_form_submitted = false;
$action_type = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $is_form_submitted = true;
    $action_type = isset($_POST['action']) ? $_POST['action'] : 'open';
    
    if ($action_type === 'open') {
        // Получение IP пользователя или из формы
        $ip = isset($_POST['custom_ip']) && !empty($_POST['custom_ip']) 
            ? trim($_POST['custom_ip']) 
            : $_SERVER['REMOTE_ADDR'];
        
        // Получение порта из формы
        $port = isset($_POST['port']) && !empty($_POST['port']) 
            ? trim($_POST['port']) 
            : '22'; // По умолчанию порт 22
        
        // Проверка валидности данных
        $is_ipv4 = is_valid_ipv4($ip);
        $is_ipv6 = is_valid_ipv6($ip);
        $is_valid_port = is_valid_port($port);
        
        if (($is_ipv4 || $is_ipv6) && $is_valid_port && is_safe_input($ip) && is_safe_input($port)) {
            // Проверяем наличие дубликатов перед выполнением команды
            $rules = load_rules();
            $duplicate_found = false;
            
            foreach ($rules as $id => $rule) {
                if ($rule['ip'] === $ip && $rule['port'] == $port && $rule['status'] === 'открыт') {
                    $duplicate_found = true;
                    break;
                }
            }
            
            if ($duplicate_found) {
                $result = "Порт $port уже открыт для IP: $ip";
                $success = true;
                log_action($ip, $port, "Повторное открытие порта (дубликат)", true);
            } else {
                // Команда для открытия порта
                if ($is_ipv4) {
                    // Команда для IPv4
                    $command = "sudo /sbin/iptables -A INPUT -p tcp -s $ip --dport $port -j ACCEPT";
                } else {
                    // Команда для IPv6
                    $command = "sudo /sbin/ip6tables -A INPUT -p tcp -s $ip --dport $port -j ACCEPT";
                }
                
                // Выполнение команды
                $output = [];
                $return_var = 0;
                exec($command . " 2>&1", $output, $return_var);
                
                if ($return_var === 0) {
                    // Сохраняем правило
                    add_rule($ip, $port, $is_ipv6);
                    
                    // Удаляем дубликаты
                    $count_removed = remove_duplicate_rules($ip, $port);
                    
                    $result = "Порт $port успешно открыт для IP: $ip";
                    if ($count_removed > 0) {
                        $result .= " (удалено дублирующихся правил: $count_removed)";
                    }
                    
                    $success = true;
                    log_action($ip, $port, "Открытие порта", true);
                } else {
                    $result = "Ошибка при выполнении команды: " . implode("\n", $output);
                    log_action($ip, $port, "Открытие порта", false);
                }
            }
        } else {
            $result = "Некорректный IP-адрес, порт или обнаружены подозрительные символы";
            log_action($ip, $port, "Попытка использования некорректных данных", false);
        }
    } elseif ($action_type === 'close' && isset($_POST['rule_id'])) {
        $rule_id = $_POST['rule_id'];
        
        if (is_safe_input($rule_id)) {
            $rules = load_rules();
            
            if (isset($rules[$rule_id])) {
                $rule = $rules[$rule_id];
                $ip = $rule['ip'];
                $port = $rule['port'];
                $is_ipv6 = $rule['is_ipv6'];
                
                // Команда для удаления правила из iptables
                if (!$is_ipv6) {
                    // Команда для IPv4
                    $command = "sudo /sbin/iptables -D INPUT -p tcp -s $ip --dport $port -j ACCEPT";
                } else {
                    // Команда для IPv6
                    $command = "sudo /sbin/ip6tables -D INPUT -p tcp -s $ip --dport $port -j ACCEPT";
                }
                
                // Выполнение команды
                $output = [];
                $return_var = 0;
                exec($command . " 2>&1", $output, $return_var);
                
                if ($return_var === 0) {
                    // Обновляем статус правила
                    update_rule_status($rule_id, 'закрыт');
                    
                    $result = "Порт $port успешно закрыт для IP: $ip";
                    $success = true;
                    log_action($ip, $port, "Закрытие порта", true);
                } else {
                    $result = "Ошибка при закрытии порта: " . implode("\n", $output);
                    log_action($ip, $port, "Закрытие порта", false);
                }
            } else {
                $result = "Правило не найдено";
            }
        } else {
            $result = "Некорректный идентификатор правила";
        }
    } elseif ($action_type === 'delete' && isset($_POST['rule_id'])) {
        $rule_id = $_POST['rule_id'];
        
        if (is_safe_input($rule_id)) {
            $rule = remove_rule($rule_id);
            
            if ($rule) {
                $ip = $rule['ip'];
                $port = $rule['port'];
                
                // Если порт уже закрыт, не нужно выполнять команду
                if ($rule['status'] === 'открыт') {
                    $is_ipv6 = $rule['is_ipv6'];
                    
                    // Команда для удаления правила из iptables
                    if (!$is_ipv6) {
                        // Команда для IPv4
                        $command = "sudo /sbin/iptables -D INPUT -p tcp -s $ip --dport $port -j ACCEPT";
                    } else {
                        // Команда для IPv6
                        $command = "sudo /sbin/ip6tables -D INPUT -p tcp -s $ip --dport $port -j ACCEPT";
                    }
                    
                    // Выполнение команды
                    $output = [];
                    $return_var = 0;
                    exec($command . " 2>&1", $output, $return_var);
                    
                    if ($return_var !== 0) {
                        $result = "Правило удалено из списка, но возникла ошибка при удалении из iptables: " . implode("\n", $output);
                        log_action($ip, $port, "Удаление правила из системы", false);
                        $success = false;
                    } else {
                        $result = "Правило для IP: $ip, порт: $port успешно удалено";
                        $success = true;
                        log_action($ip, $port, "Удаление правила", true);
                    }
                } else {
                    $result = "Правило для IP: $ip, порт: $port успешно удалено из списка";
                    $success = true;
                    log_action($ip, $port, "Удаление правила из списка", true);
                }
            } else {
                $result = "Правило не найдено";
            }
        } else {
            $result = "Некорректный идентификатор правила";
        }
    } elseif ($action_type === 'reopen' && isset($_POST['rule_id'])) {
        $rule_id = $_POST['rule_id'];
        
        if (is_safe_input($rule_id)) {
            $rules = load_rules();
            
            if (isset($rules[$rule_id])) {
                $rule = $rules[$rule_id];
                $ip = $rule['ip'];
                $port = $rule['port'];
                $is_ipv6 = $rule['is_ipv6'];
                
                // Команда для открытия порта
                if (!$is_ipv6) {
                    // Команда для IPv4
                    $command = "sudo /sbin/iptables -A INPUT -p tcp -s $ip --dport $port -j ACCEPT";
                } else {
                    // Команда для IPv6
                    $command = "sudo /sbin/ip6tables -A INPUT -p tcp -s $ip --dport $port -j ACCEPT";
                }
                
                // Выполнение команды
                $output = [];
                $return_var = 0;
                exec($command . " 2>&1", $output, $return_var);
                
                if ($return_var === 0) {
                    // Обновляем статус правила
                    update_rule_status($rule_id, 'открыт');
                    
                    $result = "Порт $port успешно открыт снова для IP: $ip";
                    $success = true;
                    log_action($ip, $port, "Повторное открытие порта", true);
                } else {
                    $result = "Ошибка при открытии порта: " . implode("\n", $output);
                    log_action($ip, $port, "Повторное открытие порта", false);
                }
            } else {
                $result = "Правило не найдено";
            }
        } else {
            $result = "Некорректный идентификатор правила";
        }
    } elseif ($action_type === 'show_rules') {
        // Просто отображаем правила, ничего не делаем
    } elseif ($action_type === 'backup_rules') {
        // Создаем файл резервной копии для скачивания
        $rules = load_rules();
        $rules_json = json_encode($rules, JSON_PRETTY_PRINT);
        
        // Устанавливаем заголовки для скачивания файла
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="firewall_rules_backup_' . date('Y-m-d_H-i-s') . '.json"');
        header('Content-Length: ' . strlen($rules_json));
        
        // Выводим содержимое файла
        echo $rules_json;
        exit;
    } elseif ($action_type === 'import_rules') {
        // Импортирование правил из JSON
        if (isset($_POST['rules_json']) && !empty($_POST['rules_json'])) {
            $rules_json = $_POST['rules_json'];
            
            try {
                $imported_rules = json_decode($rules_json, true);
                
                if ($imported_rules === null) {
                    throw new Exception("Ошибка в формате JSON");
                }
                
                // Проверяем структуру импортированных правил
                foreach ($imported_rules as $rule_id => $rule) {
                    if (!isset($rule['ip']) || !isset($rule['port']) || !isset($rule['is_ipv6']) || !isset($rule['status'])) {
                        throw new Exception("Некорректная структура правил");
                    }
                }
                
                // Сохраняем правила
                save_rules($imported_rules);
                
                $result = "Правила успешно импортированы. Всего правил: " . count($imported_rules);
                $success = true;
                log_action('system', 'all', "Импорт правил", true);
            } catch (Exception $e) {
                $result = "Ошибка при импорте правил: " . $e->getMessage();
                log_action('system', 'all', "Импорт правил", false);
            }
        } else {
            $result = "Не указаны правила для импорта";
        }
    } elseif ($action_type === 'remove_all_duplicates') {
        // Действие для удаления всех дубликатов
        $rules = load_rules();
        $processed_rules = [];
        $duplicates_removed = 0;
        
        // Создаем ключи в формате "ip:port" для отслеживания уникальных комбинаций
        foreach ($rules as $rule_id => $rule) {
            $key = $rule['ip'] . ':' . $rule['port'];
            
            if (!isset($processed_rules[$key])) {
                // Если это первое правило с такой комбинацией, добавляем его в обработанные
                $processed_rules[$key] = $rule_id;
            } else {
                // Если это дубликат, удаляем его
                unset($rules[$rule_id]);
                $duplicates_removed++;
            }
        }
        
        // Сохраняем обновленные правила
        save_rules($rules);
        
        if ($duplicates_removed > 0) {
            $result = "Удалено дублирующихся правил: $duplicates_removed";
            $success = true;
        } else {
            $result = "Дублирующихся правил не найдено";
            $success = true;
        }
        
        log_action('system', 'all', "Удаление всех дубликатов", true);
    }
}

// Загрузка существующих правил для отображения
$rules = load_rules();

// Группировка правил по IP с подсчетом открытых портов
$ip_rules = [];
foreach ($rules as $rule_id => $rule) {
    $ip = $rule['ip'];
    
    if (!isset($ip_rules[$ip])) {
        $ip_rules[$ip] = [
            'open_ports' => 0,
            'closed_ports' => 0,
            'rules' => []
        ];
    }
    
    if ($rule['status'] === 'открыт') {
        $ip_rules[$ip]['open_ports']++;
    } else {
        $ip_rules[$ip]['closed_ports']++;
    }
    
    $ip_rules[$ip]['rules'][$rule_id] = $rule;
}
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Управление доступом к портам для IP</title>
    <style>
        :root {
            --primary-color: #2a70e0;
            --primary-dark: #1d5bb8;
            --secondary-color: #1abc9c;
            --secondary-dark: #16a085;
            --success-color: #2ecc71;
            --success-dark: #27ae60;
            --danger-color: #e74c3c;
            --danger-dark: #c0392b;
            --warning-color: #f39c12;
            --warning-dark: #d35400;
            --info-color: #3498db;
            --info-dark: #2980b9;
            --light-color: #f9f9f9;
            --dark-color: #2c3e50;
            --gray-color: #95a5a6;
            --gray-dark: #7f8c8d;
            --border-color: #e0e0e0;
            --shadow-color: rgba(0, 0, 0, 0.1);
            --border-radius: 8px;
            --transition-time: 0.3s;
            --font-main: 'Roboto', 'Arial', sans-serif;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: var(--font-main);
            font-size: 16px;
            line-height: 1.6;
            color: #333;
            background-color: #f5f7fa;
            margin: 0;
            padding: 0;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 30px 20px;
        }

        header.app-header {
            background-color: #fff;
            padding: 20px 0;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            margin-bottom: 30px;
            border-bottom: 1px solid var(--border-color);
        }

        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        .app-title {
            font-size: 24px;
            font-weight: 600;
            color: var(--dark-color);
            margin: 0;
        }

        .user-info {
            display: flex;
            align-items: center;
            font-size: 14px;
            color: var(--gray-color);
        }

        .user-ip {
            background-color: var(--light-color);
            padding: 5px 10px;
            border-radius: 20px;
            margin-left: 10px;
            font-weight: 500;
        }

        .panel {
            background-color: #fff;
            border-radius: var(--border-radius);
            box-shadow: 0 2px 8px var(--shadow-color);
            margin-bottom: 25px;
            overflow: hidden;
        }

        .panel-header {
            padding: 15px 20px;
            background-color: var(--primary-color);
            color: white;
            font-weight: 500;
            font-size: 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .panel-body {
            padding: 20px;
        }

        h1, h2, h3, h4, h5, h6 {
            color: var(--dark-color);
            margin-bottom: 15px;
            font-weight: 600;
        }

        h1 {
            font-size: 28px;
            text-align: center;
            margin-bottom: 30px;
        }

        h2 {
            font-size: 22px;
            margin-bottom: 20px;
            color: var(--primary-color);
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 10px;
        }

        h3 {
            font-size: 20px;
            margin-bottom: 15px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--dark-color);
        }

        input[type="text"],
        input[type="number"],
        textarea,
        select {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            font-size: 15px;
            transition: border-color var(--transition-time);
            background-color: #fff;
        }

        input[type="text"]:focus,
        input[type="number"]:focus,
        textarea:focus,
        select:focus {
            border-color: var(--primary-color);
            outline: none;
            box-shadow: 0 0 0 3px rgba(42, 112, 224, 0.1);
        }

        .btn {
            display: inline-block;
            padding: 10px 20px;
            color: white;
            font-weight: 500;
            text-align: center;
            border: none;
            border-radius: var(--border-radius);
            cursor: pointer;
            transition: background-color var(--transition-time), transform var(--transition-time);
            font-size: 15px;
            margin-right: 8px;
            margin-bottom: 8px;
        }

        .btn:hover {
            opacity: 0.9;
            transform: translateY(-2px);
        }

        .btn:active {
            transform: translateY(0);
        }

        .btn-primary {
            background-color: var(--primary-color);
        }

        .btn-primary:hover {
            background-color: var(--primary-dark);
        }

        .btn-success {
            background-color: var(--success-color);
        }

        .btn-success:hover {
            background-color: var(--success-dark);
        }

        .btn-danger {
            background-color: var(--danger-color);
        }

        .btn-danger:hover {
            background-color: var(--danger-dark);
        }

        .btn-warning {
            background-color: var(--warning-color);
        }

        .btn-warning:hover {
            background-color: var(--warning-dark);
        }

        .btn-info {
            background-color: var(--info-color);
        }

        .btn-info:hover {
            background-color: var(--info-dark);
        }

        .btn-gray {
            background-color: var(--gray-color);
        }

        .btn-gray:hover {
            background-color: var(--gray-dark);
        }

        .btn-sm {
            padding: 6px 12px;
            font-size: 14px;
        }

        .alert {
            padding: 15px 20px;
            border-radius: var(--border-radius);
            margin-bottom: 20px;
            font-weight: 500;
        }

        .alert-success {
            background-color: #dff5e7;
            border-left: 4px solid var(--success-color);
            color: #2c7a4a;
        }

        .alert-danger {
            background-color: #fae9e7;
            border-left: 4px solid var(--danger-color);
            color: #a74135;
        }

        .alert-info {
            background-color: #e7f3fb;
            border-left: 4px solid var(--info-color);
            color: #2573a7;
        }

        .alert-warning {
            background-color: #fdf3e0;
            border-left: 4px solid var(--warning-color);
            color: #c87c14;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            overflow: hidden;
            border-radius: var(--border-radius);
            box-shadow: 0 1px 3px var(--shadow-color);
        }

        table th,
        table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        table th {
            background-color: #f8fafc;
            font-weight: 600;
            color: var(--dark-color);
        }

        table tr:nth-child(even) {
            background-color: #f9fafb;
        }

        table tr:hover {
            background-color: #f5f7fa;
        }

        table tr:last-child td {
            border-bottom: none;
        }

        .status-open {
            color: var(--success-color);
            font-weight: 600;
        }

        .status-closed {
            color: var(--danger-color);
            font-weight: 600;
        }

        .current-ip {
            font-weight: 600;
            color: var(--primary-color);
            background-color: #e7f0fb;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 14px;
            display: inline-block;
            margin-left: 5px;
        }

        .tabs {
            display: flex;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }

        .tab {
            padding: 12px 20px;
            cursor: pointer;
            font-weight: 500;
            color: var(--gray-color);
            border-bottom: 3px solid transparent;
            transition: all var(--transition-time);
            white-space: nowrap;
        }

        .tab:hover {
            color: var(--primary-color);
        }

        .tab.active {
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
        }

        .tab-content {
            display: none;
            animation: fadeIn 0.3s ease-in-out;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .ip-card {
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            margin-bottom: 20px;
            background-color: white;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.04);
            transition: transform var(--transition-time), box-shadow var(--transition-time);
            overflow: hidden;
        }

        .ip-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
        }

        .ip-header {
            padding: 15px 20px;
            background-color: #f8fafc;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 10px;
        }

        .ip-title {
            font-weight: 600;
            font-size: 18px;
            color: var(--dark-color);
            display: flex;
            align-items: center;
        }

        .ip-stats {
            display: flex;
            gap: 15px;
            font-size: 14px;
            color: var(--gray-color);
            align-items: center;
        }

        .stat-item {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .ip-badge {
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }

        .badge-open {
            background-color: #dff5e7;
            color: #2c7a4a;
        }

        .badge-closed {
            background-color: #fae9e7;
            color: #a74135;
        }

        .ip-body {
            padding: 0;
        }

        .ip-body table {
            margin: 0;
            box-shadow: none;
            border-radius: 0;
        }

        .actions {
            display: flex;
            gap: 5px;
        }

        .filter-section {
            background-color: white;
            padding: 20px;
            border-radius: var(--border-radius);
            margin-bottom: 20px;
            box-shadow: 0 1px 3px var(--shadow-color);
        }

        .filter-title {
            font-weight: 600;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .filter-icon {
            color: var(--primary-color);
        }

        .filter-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .filter-item label {
            font-size: 14px;
            margin-bottom: 5px;
        }

        .info-box {
            background-color: white;
            border-radius: var(--border-radius);
            padding: 20px;
            box-shadow: 0 1px 3px var(--shadow-color);
            margin-bottom: 20px;
        }

        .info-title {
            font-weight: 600;
            margin-bottom: 10px;
            color: var(--primary-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .info-content {
            color: #555;
        }

        .summary-item {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px dashed var(--border-color);
        }

        .summary-item:last-child {
            border-bottom: none;
        }

        .summary-label {
            font-weight: 500;
            color: var(--dark-color);
        }

        .summary-value {
            font-weight: 600;
            color: var(--primary-color);
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        code {
            background-color: #f1f5f9;
            padding: 2px 5px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 14px;
        }

        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            .user-info {
                margin-top: 5px;
            }
            
            .ip-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .ip-stats {
                margin-top: 5px;
                flex-wrap: wrap;
            }
            
            .actions {
                flex-direction: column;
                width: 100%;
            }
            
            .actions .btn {
                width: 100%;
                margin-right: 0;
            }
            
            .filter-grid {
                grid-template-columns: 1fr;
            }
            
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .tabs {
                flex-wrap: nowrap;
                overflow-x: auto;
            }
            
            .tab {
                flex: 0 0 auto;
            }
        }
    </style>
    <script>
        function showTab(tabId) {
            // Скрыть все вкладки
            const tabContents = document.getElementsByClassName('tab-content');
            for (let i = 0; i < tabContents.length; i++) {
                tabContents[i].classList.remove('active');
            }
            
            // Деактивировать все заголовки вкладок
            const tabs = document.getElementsByClassName('tab');
            for (let i = 0; i < tabs.length; i++) {
                tabs[i].classList.remove('active');
            }
            
            // Показать выбранную вкладку
            document.getElementById(tabId).classList.add('active');
            document.getElementById('tab-' + tabId).classList.add('active');
            
            // Обновляем URL с параметром tab
            const url = new URL(window.location.href);
            url.searchParams.set('tab', tabId);
            window.history.replaceState({}, '', url);
        }
        
        function confirmAction(action, ip, port) {
            let message = '';
            
            if (action === 'close') {
                message = 'Вы уверены, что хотите закрыть порт ' + port + ' для IP ' + ip + '?';
            } else if (action === 'reopen') {
                message = 'Вы уверены, что хотите открыть порт ' + port + ' для IP ' + ip + '?';
            } else if (action === 'delete') {
                message = 'Вы уверены, что хотите удалить правило для IP ' + ip + ' и порта ' + port + '?';
            }
            
            return confirm(message);
        }
        
        function filterTable() {
            const statusFilter = document.getElementById('filter-status').value;
            const ipFilter = document.getElementById('filter-ip').value.toLowerCase();
            const portFilter = document.getElementById('filter-port').value;
            
            const rows = document.querySelectorAll('#all-rules-table tbody tr');
            
            rows.forEach(row => {
                const ip = row.cells[0].textContent.toLowerCase();
                const port = row.cells[1].textContent;
                const status = row.cells[3].textContent.trim();
                
                const matchesStatus = statusFilter === 'all' || status === statusFilter;
                const matchesIp = ipFilter === '' || ip.includes(ipFilter);
                const matchesPort = portFilter === '' || port === portFilter;
                
                if (matchesStatus && matchesIp && matchesPort) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
        
        // Функция для проверки доступности iptables
        function checkIptablesAvailability() {
            const resultElement = document.getElementById('system-check-result');
            resultElement.innerHTML = '<div class="alert alert-info">Проверка доступности iptables...</div>';
            
            fetch('check_iptables.php')
                .then(response => response.json())
                .then(data => {
                    let resultHtml = '<div class="alert ' + (data.iptables_available && data.ip6tables_available ? 'alert-success' : 'alert-danger') + '">';
                    
                    resultHtml += '<h4>Результаты проверки:</h4>';
                    resultHtml += '<ul>';
                    resultHtml += '<li>iptables (IPv4): ' + (data.iptables_available ? '<span class="status-open">Доступен</span>' : '<span class="status-closed">Не доступен</span>') + '</li>';
                    resultHtml += '<li>ip6tables (IPv6): ' + (data.ip6tables_available ? '<span class="status-open">Доступен</span>' : '<span class="status-closed">Не доступен</span>') + '</li>';
                    resultHtml += '</ul>';
                    
                    if (!data.iptables_available || !data.ip6tables_available) {
                        resultHtml += '<p><strong>Рекомендации:</strong></p>';
                        resultHtml += '<ol>';
                        resultHtml += '<li>Проверьте, что iptables и ip6tables установлены в системе</li>';
                        resultHtml += '<li>Убедитесь, что у веб-сервера есть права на выполнение команд</li>';
                        resultHtml += '</ol>';
                    }
                    
                    resultHtml += '</div>';
                    
                    resultElement.innerHTML = resultHtml;
                })
                .catch(error => {
                    resultElement.innerHTML = '<div class="alert alert-danger">Ошибка при проверке iptables: ' + error.message + '</div>';
                });
        }
        
        // Вызов функции при загрузке страницы
        window.onload = function() {
            // Если в URL есть параметр tab, открываем соответствующую вкладку
            const urlParams = new URLSearchParams(window.location.search);
            const tab = urlParams.get('tab');
            if (tab) {
                showTab(tab);
            }
        };
    </script>
</head>
<body>
    <header class="app-header">
        <div class="header-content">
            <h1 class="app-title">Управление доступом к портам</h1>
            <div class="user-info">
                Ваш IP-адрес: <span class="user-ip"><?php echo htmlspecialchars($_SERVER['REMOTE_ADDR']); ?></span>
            </div>
        </div>
    </header>

    <div class="container">
        <!-- Предупреждение о проблемах с iptables (скрыто по умолчанию) -->
        <div id="iptables-warning" class="alert alert-danger" style="display: none;">
            <strong>Внимание!</strong> Не удалось выполнить команды iptables. Проверьте настройки и права доступа.
        </div>
        
        <!-- Результат выполнения операции -->
        <?php if ($is_form_submitted): ?>
            <div class="alert <?php echo $success ? 'alert-success' : 'alert-danger'; ?>">
                <?php echo htmlspecialchars($result); ?>
            </div>
        <?php endif; ?>
        
        <!-- Навигационные вкладки -->
        <div class="tabs">
            <div id="tab-add-rule" class="tab active" onclick="showTab('add-rule')">Открыть порт</div>
            <div id="tab-ip-rules" class="tab" onclick="showTab('ip-rules')">IP с открытыми портами</div>
            <div id="tab-all-rules" class="tab" onclick="showTab('all-rules')">Все правила</div>
            <div id="tab-dashboard" class="tab" onclick="showTab('dashboard')">Панель управления</div>
        </div>
        
        <!-- Форма для открытия порта -->
        <div id="add-rule" class="tab-content active">
            <div class="panel">
                <div class="panel-header">
                    Открыть новый порт
                </div>
                <div class="panel-body">
                    <form method="post" action="">
                        <input type="hidden" name="action" value="open">
                        
                        <div class="form-group">
                            <label for="custom_ip">IP-адрес (оставьте пустым для вашего текущего IP):</label>
                            <input type="text" id="custom_ip" name="custom_ip" placeholder="Введите IPv4 или IPv6" value="<?php echo isset($_SERVER['REMOTE_ADDR']) ? htmlspecialchars($_SERVER['REMOTE_ADDR']) : ''; ?>">
                        </div>
                        
                        <div class="form-group">
                            <label for="port">Порт:</label>
                            <input type="number" id="port" name="port" placeholder="Введите номер порта" value="22" min="1" max="65535">
                        </div>
                        
                        <button type="submit" class="btn btn-success">Открыть порт</button>
                    </form>
                </div>
            </div>
        </div>
        
        <!-- Раздел отображения правил по IP -->
        <div id="ip-rules" class="tab-content">
            <h2>IP-адреса с настроенными правилами</h2>
            
            <?php if (count($ip_rules) > 0): ?>
                <div class="ip-grid">
                    <?php foreach ($ip_rules as $ip => $ip_data): ?>
                        <div class="ip-card">
                            <div class="ip-header">
                                <div class="ip-title">
                                    <?php echo htmlspecialchars($ip); ?>
                                    <?php if ($ip === $_SERVER['REMOTE_ADDR']): ?>
                                        <span class="current-ip">Ваш IP</span>
                                    <?php endif; ?>
                                </div>
                                <div class="ip-stats">
                                    <div class="stat-item">
                                        <span class="ip-badge badge-open"><?php echo $ip_data['open_ports']; ?> открытых</span>
                                    </div>
                                    <div class="stat-item">
                                        <span class="ip-badge badge-closed"><?php echo $ip_data['closed_ports']; ?> закрытых</span>
                                    </div>
                                </div>
                            </div>
                            <div class="ip-body">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Порт</th>
                                            <th>Тип IP</th>
                                            <th>Статус</th>
                                            <th>Дата добавления</th>
                                            <th>Действия</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($ip_data['rules'] as $rule_id => $rule): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($rule['port']); ?></td>
                                                <td><?php echo $rule['is_ipv6'] ? 'IPv6' : 'IPv4'; ?></td>
                                                <td class="<?php echo $rule['status'] === 'открыт' ? 'status-open' : 'status-closed'; ?>">
                                                    <?php echo htmlspecialchars($rule['status']); ?>
                                                </td>
                                                <td><?php echo htmlspecialchars($rule['date_added']); ?></td>
                                                <td class="actions">
                                                    <?php if ($rule['status'] === 'открыт'): ?>
                                                        <form method="post" action="" style="display: inline;">
                                                            <input type="hidden" name="action" value="close">
                                                            <input type="hidden" name="rule_id" value="<?php echo htmlspecialchars($rule_id); ?>">
                                                            <button type="submit" class="btn btn-danger btn-sm" onclick="return confirmAction('close', '<?php echo htmlspecialchars($rule['ip']); ?>', '<?php echo htmlspecialchars($rule['port']); ?>')">Закрыть</button>
                                                        </form>
                                                    <?php else: ?>
                                                        <form method="post" action="" style="display: inline;">
                                                            <input type="hidden" name="action" value="reopen">
                                                            <input type="hidden" name="rule_id" value="<?php echo htmlspecialchars($rule_id); ?>">
                                                            <button type="submit" class="btn btn-success btn-sm" onclick="return confirmAction('reopen', '<?php echo htmlspecialchars($rule['ip']); ?>', '<?php echo htmlspecialchars($rule['port']); ?>')">Открыть</button>
                                                        </form>
                                                    <?php endif; ?>
                                                    <form method="post" action="" style="display: inline;">
                                                        <input type="hidden" name="action" value="delete">
                                                        <input type="hidden" name="rule_id" value="<?php echo htmlspecialchars($rule_id); ?>">
                                                        <button type="submit" class="btn btn-gray btn-sm" onclick="return confirmAction('delete', '<?php echo htmlspecialchars($rule['ip']); ?>', '<?php echo htmlspecialchars($rule['port']); ?>')">Удалить</button>
                                                    </form>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="alert alert-info">Нет активных правил для IP-адресов</div>
            <?php endif; ?>
        </div>
        
        <!-- Таблица всех существующих правил -->
        <div id="all-rules" class="tab-content">
            <h2>Все настроенные правила</h2>
            
            <!-- Фильтры для таблицы правил -->
            <div class="filter-section">
                <div class="filter-title">
                    <i class="filter-icon">🔍</i> Фильтр правил
                </div>
                <div class="filter-grid">
                    <div class="filter-item">
                        <label for="filter-status">Статус:</label>
                        <select id="filter-status" onchange="filterTable()" class="form-control">
                            <option value="all">Все</option>
                            <option value="открыт">Открытые</option>
                            <option value="закрыт">Закрытые</option>
                        </select>
                    </div>
                    <div class="filter-item">
                        <label for="filter-ip">IP-адрес:</label>
                        <input type="text" id="filter-ip" placeholder="Фильтр по IP" oninput="filterTable()" class="form-control">
                    </div>
                    <div class="filter-item">
                        <label for="filter-port">Порт:</label>
                        <input type="number" id="filter-port" placeholder="Фильтр по порту" oninput="filterTable()" class="form-control">
                    </div>
                </div>
            </div>
            
            <?php if (count($rules) > 0): ?>
                <div class="panel">
                    <div class="panel-body" style="padding: 0;">
                        <table id="all-rules-table">
                            <thead>
                                <tr>
                                    <th>IP-адрес</th>
                                    <th>Порт</th>
                                    <th>Тип IP</th>
                                    <th>Статус</th>
                                    <th>Дата добавления</th>
                                    <th>Действия</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($rules as $rule_id => $rule): ?>
                                    <tr>
                                        <td>
                                            <?php echo htmlspecialchars($rule['ip']); ?>
                                            <?php if ($rule['ip'] === $_SERVER['REMOTE_ADDR']): ?>
                                                <span class="current-ip">Ваш IP</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo htmlspecialchars($rule['port']); ?></td>
                                        <td><?php echo $rule['is_ipv6'] ? 'IPv6' : 'IPv4'; ?></td>
                                        <td class="<?php echo $rule['status'] === 'открыт' ? 'status-open' : 'status-closed'; ?>">
                                            <?php echo htmlspecialchars($rule['status']); ?>
                                        </td>
                                        <td><?php echo htmlspecialchars($rule['date_added']); ?></td>
                                        <td class="actions">
                                            <?php if ($rule['status'] === 'открыт'): ?>
                                                <form method="post" action="" style="display: inline;">
                                                    <input type="hidden" name="action" value="close">
                                                    <input type="hidden" name="rule_id" value="<?php echo htmlspecialchars($rule_id); ?>">
                                                    <button type="submit" class="btn btn-danger btn-sm" onclick="return confirmAction('close', '<?php echo htmlspecialchars($rule['ip']); ?>', '<?php echo htmlspecialchars($rule['port']); ?>')">Закрыть</button>
                                                </form>
                                            <?php else: ?>
                                                <form method="post" action="" style="display: inline;">
                                                    <input type="hidden" name="action" value="reopen">
                                                    <input type="hidden" name="rule_id" value="<?php echo htmlspecialchars($rule_id); ?>">
                                                    <button type="submit" class="btn btn-success btn-sm" onclick="return confirmAction('reopen', '<?php echo htmlspecialchars($rule['ip']); ?>', '<?php echo htmlspecialchars($rule['port']); ?>')">Открыть</button>
                                                </form>
                                            <?php endif; ?>
                                            <form method="post" action="" style="display: inline;">
                                                <input type="hidden" name="action" value="delete">
                                                <input type="hidden" name="rule_id" value="<?php echo htmlspecialchars($rule_id); ?>">
                                                <button type="submit" class="btn btn-gray btn-sm" onclick="return confirmAction('delete', '<?php echo htmlspecialchars($rule['ip']); ?>', '<?php echo htmlspecialchars($rule['port']); ?>')">Удалить</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            <?php else: ?>
                <div class="alert alert-info">Нет активных правил</div>
            <?php endif; ?>
        </div>
        
        <!-- Панель управления -->
        <div id="dashboard" class="tab-content">
            <h2>Панель управления</h2>
            
            <!-- Сводная статистика -->
            <div class="dashboard-grid">
                <div class="panel">
                    <div class="panel-header">
                        Общая статистика
                    </div>
                    <div class="panel-body">
                        <div class="summary-item">
                            <div class="summary-label">Всего правил:</div>
                            <div class="summary-value"><?php echo count($rules); ?></div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-label">Открытых портов:</div>
                            <div class="summary-value"><?php echo count(array_filter($rules, function($rule) { return $rule['status'] === 'открыт'; })); ?></div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-label">Закрытых портов:</div>
                            <div class="summary-value"><?php echo count(array_filter($rules, function($rule) { return $rule['status'] === 'закрыт'; })); ?></div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-label">Уникальных IP:</div>
                            <div class="summary-value"><?php echo count($ip_rules); ?></div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-label">Правил IPv4:</div>
                            <div class="summary-value"><?php echo count(array_filter($rules, function($rule) { return !$rule['is_ipv6']; })); ?></div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-label">Правил IPv6:</div>
                            <div class="summary-value"><?php echo count(array_filter($rules, function($rule) { return $rule['is_ipv6']; })); ?></div>
                        </div>
                    </div>
                </div>
                
                <div class="panel">
                    <div class="panel-header">
                        Проверка системы
                    </div>
                    <div class="panel-body">
                        <button onclick="checkIptablesAvailability()" class="btn btn-primary">Проверить доступность iptables</button>
                        <div id="system-check-result" style="margin-top: 15px;"></div>
                    </div>
                </div>
            </div>
            
            <!-- Управление файлом правил -->
            <div class="panel">
                <div class="panel-header">
                    Управление файлом правил
                </div>
                <div class="panel-body">
                    <p>Текущий файл правил: <code><?php echo htmlspecialchars($rules_file); ?></code></p>
                    
                    <div style="margin-top: 20px; margin-bottom: 20px;">
                        <form method="post" action="" style="margin-bottom: 20px;">
                            <input type="hidden" name="action" value="backup_rules">
                            <button type="submit" class="btn btn-info">Скачать резервную копию правил</button>
                        </form>
                        
                        <form method="post" action="">
                            <input type="hidden" name="action" value="import_rules">
                            <div class="form-group">
                                <label for="rules_import">Импортировать правила (JSON):</label>
                                <textarea id="rules_import" name="rules_json" rows="5" style="width: 100%; font-family: monospace;"></textarea>
                            </div>
                            <button type="submit" class="btn btn-warning">Импортировать правила</button>
                        </form>
                    </div>
                </div>
            </div>
            
            <!-- Удаление дубликатов -->
            <div class="panel">
                <div class="panel-header">
                    Обслуживание правил
                </div>
                <div class="panel-body">
                    <p>Функция удаления дубликатов уберет все дублирующиеся правила для одинаковых комбинаций IP:порт, оставив только самые свежие.</p>
                    
                    <form method="post" action="" style="margin-top: 15px;">
                        <input type="hidden" name="action" value="remove_all_duplicates">
                        <button type="submit" class="btn btn-danger" onclick="return confirm('Вы уверены, что хотите удалить все дублирующиеся правила?');">Удалить все дубликаты</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    <footer style="text-align: center; padding: 20px; color: #666; font-size: 14px; margin-top: 30px; border-top: 1px solid #eee;">
        <div class="container">
            <p>Система управления доступом к портам для IP-адресов</p>
            <p>Ваш IP-адрес: <span style="font-weight: 600;"><?php echo htmlspecialchars($_SERVER['REMOTE_ADDR']); ?></span></p>
        </div>
    </footer>
</body>
</html>