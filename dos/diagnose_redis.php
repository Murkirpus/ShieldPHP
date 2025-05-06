<?php
// /dos/diagnose_redis.php
// Script for diagnosing Redis connection issues
require_once 'settings.php';
require_once 'security_monitor.php';

// Disable security monitoring for this script
define('DISABLE_SECURITY_MONITOR', true);

echo "<!DOCTYPE html>
<html>
<head>
    <title>Redis Diagnostics</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        h1, h2 { color: #444; }
        pre { background: #f8f8f8; padding: 10px; border-radius: 4px; overflow: auto; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>Redis Security Monitor Diagnostics</h1>";

function testRedisConnection() {
    echo "<h2>Testing Redis Connection</h2>";
    
    if (!class_exists('Redis')) {
        echo "<p class='error'>Redis PHP extension is not installed!</p>";
        return false;
    }
    
    echo "<p>Redis PHP extension is installed.</p>";
    
    try {
        $redis = new Redis();
        $host = defined('REDIS_HOST') ? REDIS_HOST : '127.0.0.1';
        $port = defined('REDIS_PORT') ? REDIS_PORT : 6379;
        
        echo "<p>Connecting to Redis at $host:$port...</p>";
        
        if (!$redis->connect($host, $port, 2.0)) {
            echo "<p class='error'>Failed to connect to Redis!</p>";
            return false;
        }
        
        echo "<p class='success'>Successfully connected to Redis.</p>";
        
        // Authentication
        if (defined('REDIS_PASSWORD') && REDIS_PASSWORD) {
            echo "<p>Authenticating with Redis...</p>";
            if (!$redis->auth(REDIS_PASSWORD)) {
                echo "<p class='error'>Redis authentication failed!</p>";
                return false;
            }
            echo "<p class='success'>Redis authentication successful.</p>";
        } else {
            echo "<p>No Redis password configured.</p>";
        }
        
        // Select database
        $database = defined('REDIS_DATABASE') ? REDIS_DATABASE : 0;
        echo "<p>Selecting Redis database $database...</p>";
        if (!$redis->select($database)) {
            echo "<p class='error'>Failed to select Redis database $database!</p>";
            return false;
        }
        echo "<p class='success'>Redis database selection successful.</p>";
        
        // Ping
        echo "<p>Testing Redis ping...</p>";
        $ping_result = $redis->ping();
        if ($ping_result !== true && $ping_result !== "+PONG") {
            echo "<p class='error'>Redis ping failed: " . print_r($ping_result, true) . "</p>";
            return false;
        }
        echo "<p class='success'>Redis ping successful: " . print_r($ping_result, true) . "</p>";
        
        // Set/Get test
        echo "<p>Testing Redis SET/GET operations...</p>";
        $test_key = "dos:test_key";
        $test_value = "test_" . time();
        $set_result = $redis->set($test_key, $test_value);
        
        if (!$set_result) {
            echo "<p class='error'>Redis SET operation failed!</p>";
            return false;
        }
        
        $get_result = $redis->get($test_key);
        if ($get_result !== $test_value) {
            echo "<p class='error'>Redis GET operation failed! Expected: $test_value, Got: " . print_r($get_result, true) . "</p>";
            return false;
        }
        
        $redis->del($test_key);
        echo "<p class='success'>Redis SET/GET operations successful.</p>";
        
        // Redis server info
        echo "<h2>Redis Server Information</h2>";
        $info = $redis->info();
        
        echo "<table>";
        echo "<tr><th>Key</th><th>Value</th></tr>";
        echo "<tr><td>Redis Version</td><td>" . $info['redis_version'] . "</td></tr>";
        echo "<tr><td>Memory Used</td><td>" . $info['used_memory_human'] . "</td></tr>";
        echo "<tr><td>Memory Peak</td><td>" . $info['used_memory_peak_human'] . "</td></tr>";
        echo "<tr><td>Total Connections</td><td>" . $info['total_connections_received'] . "</td></tr>";
        echo "<tr><td>Uptime</td><td>" . $info['uptime_in_days'] . " days</td></tr>";
        echo "<tr><td>Total Keys</td><td>" . $redis->dbSize() . "</td></tr>";
        echo "</table>";
        
        return $redis;
    } catch (Exception $e) {
        echo "<p class='error'>Redis error: " . $e->getMessage() . "</p>";
        return false;
    }
}

function checkBlockingFunctionality($redis) {
    if (!$redis) return;
    
    echo "<h2>Checking Blocking Functionality</h2>";
    
    $prefix = defined('REDIS_PREFIX') ? REDIS_PREFIX : 'dos:';
    
    // Check sorted set of blocked IPs
    $blocked_count = $redis->zCard($prefix . "blocked_ips");
    echo "<p>Currently blocked IPs in Redis: $blocked_count</p>";
    
    if ($blocked_count > 0) {
        $now = time();
        $active_blocks = $redis->zCount($prefix . "blocked_ips", $now, '+inf');
        $expired_blocks = $blocked_count - $active_blocks;
        
        echo "<p>Active blocks: $active_blocks</p>";
        echo "<p>Expired blocks: $expired_blocks</p>";
        
        // Show some sample blocked IPs
        $sample_blocked = $redis->zRangeByScore($prefix . "blocked_ips", $now, '+inf', array('LIMIT' => array(0, 5)));
        
        if (!empty($sample_blocked)) {
            echo "<h3>Sample Blocked IPs</h3>";
            echo "<table>";
            echo "<tr><th>IP</th><th>Block Until</th><th>Block Data</th></tr>";
            
            foreach ($sample_blocked as $ip) {
                $score = $redis->zScore($prefix . "blocked_ips", $ip);
                $blockKey = $prefix . "blocked_ip:$ip";
                $blockData = $redis->exists($blockKey) ? $redis->hGetAll($blockKey) : array();
                
                echo "<tr>";
                echo "<td>" . htmlspecialchars($ip) . "</td>";
                echo "<td>" . date('Y-m-d H:i:s', $score) . "</td>";
                echo "<td><pre>" . print_r($blockData, true) . "</pre></td>";
                echo "</tr>";
            }
            
            echo "</table>";
        } else {
            echo "<p>No sample blocked IPs found.</p>";
        }
    } else {
        echo "<p class='warning'>No blocked IPs found in Redis.</p>";
    }
    
    // Check recent blocks
    $recent_blocks = $redis->lRange($prefix . "block_log", 0, 5);
    if (!empty($recent_blocks)) {
        echo "<h3>Recent Block Log</h3>";
        echo "<table>";
        echo "<tr><th>IP</th><th>Time</th><th>Reason</th><th>Block Until</th></tr>";
        
        foreach ($recent_blocks as $block_json) {
            $block = json_decode($block_json, true);
            if ($block) {
                echo "<tr>";
                echo "<td>" . htmlspecialchars($block['ip']) . "</td>";
                echo "<td>" . date('Y-m-d H:i:s', $block['time']) . "</td>";
                echo "<td>" . htmlspecialchars($block['reason']) . "</td>";
                echo "<td>" . date('Y-m-d H:i:s', $block['block_until']) . "</td>";
                echo "</tr>";
            }
        }
        
        echo "</table>";
    } else {
        echo "<p>No recent blocks found in log.</p>";
    }
    
    // Check rate limiting
    $rate_keys = $redis->keys($prefix . "ip_request_rate:*");
    echo "<p>IP rate limiting entries: " . count($rate_keys) . "</p>";
    
    if (count($rate_keys) > 0) {
        echo "<h3>Sample Rate Limiting Data</h3>";
        echo "<table>";
        echo "<tr><th>IP</th><th>Request Count</th><th>First Request</th><th>Last Request</th></tr>";
        
        for ($i = 0; $i < min(5, count($rate_keys)); $i++) {
            $key = $rate_keys[$i];
            $ip = str_replace($prefix . "ip_request_rate:", "", $key);
            $data = $redis->hGetAll($key);
            
            echo "<tr>";
            echo "<td>" . htmlspecialchars($ip) . "</td>";
            echo "<td>" . (isset($data['request_count']) ? $data['request_count'] : 'N/A') . "</td>";
            echo "<td>" . (isset($data['first_request_time']) ? date('Y-m-d H:i:s', $data['first_request_time']) : 'N/A') . "</td>";
            echo "<td>" . (isset($data['last_request_time']) ? date('Y-m-d H:i:s', $data['last_request_time']) : 'N/A') . "</td>";
            echo "</tr>";
        }
        
        echo "</table>";
    }
}

function testSecurityMonitor() {
    echo "<h2>Testing Security Monitor Class</h2>";
    
    try {
        $monitor = new LightSecurityMonitor();
        echo "<p class='success'>LightSecurityMonitor instance created successfully.</p>";
        
        if ($monitor->isRedisActive()) {
            echo "<p class='success'>Redis is active in security monitor.</p>";
        } else {
            echo "<p class='error'>Redis is NOT active in security monitor!</p>";
        }
        
        // Run Redis diagnosis
        if (method_exists($monitor, 'diagnoseRedis')) {
            echo "<p>Running Redis diagnosis...</p>";
            if ($monitor->diagnoseRedis()) {
                echo "<p class='success'>Redis diagnosis completed.</p>";
            } else {
                echo "<p class='error'>Redis diagnosis failed.</p>";
            }
        } else {
            echo "<p class='warning'>diagnoseRedis method not found (add it from the fixes provided).</p>";
        }
        
        // Test blocking a test IP
        $test_ip = "127.0.0.2"; // Use a safe local IP for testing
        if (method_exists($monitor, 'checkBlockStatus')) {
            echo "<p>Checking status of test IP $test_ip...</p>";
            $monitor->checkBlockStatus($test_ip);
        }
        
        // Rebuild Redis cache
        if (method_exists($monitor, 'rebuildRedisBlockCache')) {
            echo "<p>Rebuilding Redis block cache...</p>";
            $result = $monitor->rebuildRedisBlockCache();
            if ($result !== false) {
                echo "<p class='success'>Redis block cache rebuilt with $result entries.</p>";
            } else {
                echo "<p class='error'>Failed to rebuild Redis block cache.</p>";
            }
        }
        
        return $monitor;
    } catch (Exception $e) {
        echo "<p class='error'>Error creating security monitor: " . $e->getMessage() . "</p>";
        return false;
    }
}

function checkFileCache() {
    echo "<h2>Checking File Cache</h2>";
    
    $dos_dir = dirname(__FILE__) . '/';
    $cache_file = $dos_dir . 'blocked_ips.php';
    $info_file = $dos_dir . 'blocked_info.php';
    
    if (file_exists($cache_file)) {
        echo "<p>Blocked IPs cache file exists.</p>";
        include $cache_file;
        
        if (isset($blocked_ips) && is_array($blocked_ips)) {
            $now = time();
            $total = count($blocked_ips);
            $active = 0;
            $expired = 0;
            
            foreach ($blocked_ips as $ip => $until) {
                if ($until > $now) {
                    $active++;
                } else {
                    $expired++;
                }
            }
            
            echo "<p>Total cached IPs: $total (Active: $active, Expired: $expired)</p>";
            
            if ($active > 0) {
                echo "<h3>Sample Active Blocks</h3>";
                echo "<table>";
                echo "<tr><th>IP</th><th>Block Until</th></tr>";
                
                $count = 0;
                foreach ($blocked_ips as $ip => $until) {
                    if ($until > $now && $count < 5) {
                        echo "<tr>";
                        echo "<td>" . htmlspecialchars($ip) . "</td>";
                        echo "<td>" . date('Y-m-d H:i:s', $until) . "</td>";
                        echo "</tr>";
                        $count++;
                    }
                }
                
                echo "</table>";
            }
        } else {
            echo "<p class='error'>Invalid blocked_ips.php file format!</p>";
        }
    } else {
        echo "<p class='warning'>Blocked IPs cache file does not exist.</p>";
    }
    
    if (file_exists($info_file)) {
        echo "<p>Blocked info cache file exists.</p>";
        include $info_file;
        
        if (isset($blocked_info) && is_array($blocked_info)) {
            echo "<p>Total entries in blocked_info: " . count($blocked_info) . "</p>";
        } else {
            echo "<p class='error'>Invalid blocked_info.php file format!</p>";
        }
    } else {
        echo "<p class='warning'>Blocked info cache file does not exist.</p>";
    }
}

function repairSuggestions() {
    echo "<h2>Repair Suggestions</h2>";
    echo "<ol>";
    echo "<li>If Redis is not connecting, check if the Redis server is running:<br>
          <code>systemctl status redis</code> or <code>service redis-server status</code></li>";
    echo "<li>If Redis is running but still not connecting, verify the host and port settings in settings.php</li>";
    echo "<li>If Redis connects but blocks aren't working, try rebuilding the block cache using the Security Monitor class</li>";
    echo "<li>Make sure that Redis persistence is enabled to prevent losing data on restart</li>";
    echo "<li>Check Redis memory usage and increase max memory if needed</li>";
    echo "<li>Add the diagnostic methods to your security_monitor.php file to help track issues</li>";
    echo "<li>If all else fails, temporarily set USE_REDIS to false in settings.php to fall back to database mode</li>";
    echo "</ol>";
    
    echo "<h3>Code Fixes</h3>";
    echo "<p>To fix the Redis blocking issues, make sure you've implemented these improvements:</p>";
    echo "<ol>";
    echo "<li>Improved Redis connection handling with explicit error checking</li>";
    echo "<li>Fixed the blockIPRedis method to properly set TTL and manage keys</li>";
    echo "<li>Enhanced isIPBlockedRedis to check both sorted sets and hashes</li>";
    echo "<li>Fixed rate limit checking to handle edge cases</li>";
    echo "<li>Robust constructor with fallback mechanisms</li>";
    echo "<li>Added diagnostic methods for troubleshooting</li>";
    echo "</ol>";
}

// Run the tests
$redis = testRedisConnection();
if ($redis) {
    checkBlockingFunctionality($redis);
}

$monitor = testSecurityMonitor();
checkFileCache();
repairSuggestions();

echo "
</body>
</html>";