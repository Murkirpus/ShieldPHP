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