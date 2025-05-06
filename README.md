# ShieldPHP
DDoS protection system with progressive blocking, Redis/MariaDB storage, reCAPTCHA unblocking and administrative interface. Includes automatic blocking under critical loads, IP whitelists, bot detection and multi-layered protection (.htaccess, Nginx, iptables). Works with IPv4/IPv6.

# DoS Protection System - ShieldPHP

Multi-layered protection system against DoS/DDoS attacks with progressive blocking and flexible settings for various web servers.

## Features

- ⚡ **High performance** - optimized for high load
- 🔄 **Progressive blocking** - increasing blocking time for repeat offenders
- 🛡️ **Multi-level protection** - blocking at the web server, firewall and DB level
- 🗄️ **Flexible storage** - Redis and MariaDB support with automatic switching
- 🤖 **reCAPTCHA unblocking** - the ability for legitimate users to unblock their IP
- 📊 **Administrative panel** - monitoring and manual blocking management
- ⚙️ **Flexible settings** - adjustment to any load level
- 🔍 **Intelligent bot detection** - user behavior analysis
- 📝 **Detailed logging** - tracking all events security
- 🌐 **IPv4 and IPv6 support** - protection for all types of connections
- 🧹 **Automatic cleanup** - removes obsolete data and optimizes

## Requirements

- PHP 5.6 or higher
- MariaDB/MySQL for data storage (optional)
- Redis for high-load scenarios (optional)
- Permissions to manage .htaccess (Apache) or nginx.conf (Nginx)
- Permissions to manage iptables/ip6tables (optional)
- Access to cron for periodic cleaning tasks

## Installation

1. Upload files to the `/dos/` directory of your site
2. Create a MySQL/MariaDB database and user
3. Edit the `settings.php` file:
- Specify the connection settings to the database
- Set reCAPTCHA keys
- Configure blocking mechanisms
4. Configure the execution of `cleanup.php` via cron every hour:
```
0 * * * * php /path/to/your/site/dos/cleanup.php > /dev/null 2>&1
```
5. Add to `.htaccess` of the main site directory:
```
# DoS Protection
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_URI} !^/dos/recaptcha_unlock\.php
RewriteCond %{REQUEST_URI} !^/favicon\.ico
RewriteRule .* - [E=DOS_CHECK:1]
</IfModule>

<IfModule mod_php.c>
<If "%{ENV:DOS_CHECK} == '1'">
php_value auto_prepend_file "/path/to/your/site/dos/security_monitor.php"
</If>
</IfModule>
```

For Nginx, add to the server configuration:
```
# DoS Protection
location ~ \.php$ {
fastcgi_param PHP_VALUE "auto_prepend_file=/path/to/your/site/dos/security_monitor.php";
# ... other fastcgi settings
}
```

## Management

The admin panel is available at: `https://your-site.com/dos/admin.php`

Unlock page for users: `https://your-site.com/dos/recaptcha_unlock.php`

## Configuring protection levels

The system supports several blocking mechanisms that can be enabled/disabled in the `settings.php` file:

```php
// Blocking mechanism settings
define('ENABLE_HTACCESS_BLOCKING', true); // Blocking via .htaccess
define('ENABLE_NGINX_BLOCKING', false); // Blocking via Nginx (ip.conf)
define('ENABLE_FIREWALL_BLOCKING', true); // Blocking via firewall (iptables/ip6tables)
define('ENABLE_API_BLOCKING', false); // Blocking via external API

// Setting up progressive blocking
define('BLOCK_TIME_FIRST', 3600); // First blocking (1 hour)
define('BLOCK_TIME_SECOND', 10800); // Second blocking (3 hours)
// etc.
```

## Monitoring and maintenance

Use the admin panel to track blocking statistics. The `cleanup.php` file automatically:

1. Cleans outdated records from the DB and Redis
2. Removes expired locks
3. Optimizes DB tables
4. Updates the file cache

## Integration with other systems

The system supports integration with external APIs via the `API_BLOCK_URL` and `API_BLOCK_KEY` settings in the `settings.php` file.

## ❤️ Support the Project

If you like this project and want to support its development, you can make a donation via PayPal:

* PayPal: murkir@gmail.com
* 
## License

MIT

## 📞 Contacts

If you have questions or suggestions for improving the counter, please contact us:

- Email: murkir@gmail.com
- GitHub: [https://github.com/Murkirpus/ShieldPHP](https://github.com/Murkirpus/ShieldPHP)
https://murkir.pp.ua
https://dj-x.info

## Author

Vitalii Litvinov (murkir.pp.ua)
