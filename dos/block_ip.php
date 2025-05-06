<?php
// /dos/block_ip.php
// Скрипт для безопасной блокировки IP через iptables
require_once 'settings.php';
require_once 'security_monitor.php';

if (isset($argv[1]) && filter_var($argv[1], FILTER_VALIDATE_IP)) {
    $ip = $argv[1];
    
    // Функция для блокирования IP через iptables
    function blockIPWithIptables($ip) {
        // Определяем, является ли IP адресом IPv6
        $isIPv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        
        // Блокируем порты 80 и 443
        $ports = array(80, 443);
        
        error_log("Блокируем IP в iptables: $ip, IPv6: " . ($isIPv6 ? "да" : "нет"));
        
        foreach ($ports as $port) {
            // Формируем команду в зависимости от версии IP
            if ($isIPv6) {
                $command = "sudo ip6tables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
            } else {
                $command = "sudo iptables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
            }
            
            // Выполняем команду блокировки
            exec($command);
        }
        
        // Сохраняем правила для сохранения после перезагрузки
        if ($isIPv6) {
            exec("sudo sh -c 'ip6tables-save > /etc/iptables/rules.v6'");
        } else {
            exec("sudo sh -c 'iptables-save > /etc/iptables/rules.v4'");
        }
        
        error_log("IP $ip успешно заблокирован через iptables");
    }
    
    blockIPWithIptables($ip);
    echo "IP $ip заблокирован\n";
}
?>