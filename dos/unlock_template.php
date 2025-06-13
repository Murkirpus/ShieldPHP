<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Интегрированная система разблокировки</title>
    <?php if (defined('RECAPTCHA_SITE_KEY') && !empty(RECAPTCHA_SITE_KEY)): ?>
    <script src="https://www.google.com/recaptcha/api.js?render=<?php echo RECAPTCHA_SITE_KEY; ?>"></script>
    <?php endif; ?>
    
    <?php include 'unlock_styles.php'; ?>
</head>
<body>
    <!-- Honeypot ловушки -->
    <div style="position: absolute; left: -9999px; opacity: 0; pointer-events: none; width: 0; height: 0; visibility: hidden;">
        <input type="text" class="security-trap" name="email_address" tabindex="-1" autocomplete="off">
        <input type="text" class="bot-trap" name="user_website" tabindex="-1" autocomplete="off">
        <input type="password" class="hidden-field" name="security_token" tabindex="-1" autocomplete="off">
    </div>

    <div class="security-container">
        <h1>🛡️ Интегрированная система разблокировки</h1>
        <p class="subtitle">Многоуровневая система проверки подлинности и разблокировки</p>
        
        <?php if (!empty($success_message)): ?>
            <div class="message success"><?php echo htmlspecialchars($success_message); ?></div>
            <div class="info">
                <p>Доступ к сайту восстановлен. <a href="<?php echo htmlspecialchars($return_url); ?>">Вернуться на предыдущую страницу</a></p>
                <p><small>Ваш щит в цифровом мире. © MurKir Security, 2025</small></p>
            </div>
            
        <?php elseif (!$is_blocked): ?>
            <div class="info">
                <p>Ваш IP-адрес (<?php echo htmlspecialchars($current_ip); ?>) не заблокирован.</p>
                <p><a href="<?php echo htmlspecialchars($return_url); ?>">Вернуться на предыдущую страницу</a></p>
                <p><small>Ваш щит в цифровом мире. © MurKir Security, 2025</small></p>
            </div>
            
        <?php elseif ($is_hard_blocked): ?>
            <div class="message danger">
                <p><strong>Внимание: Ваш IP-адрес жестко заблокирован!</strong></p>
                <p>Ваш IP-адрес (<?php echo htmlspecialchars($current_ip); ?>) был заблокирован на уровне брандмауэра из-за подозрительной активности.</p>
                <p>Для разблокировки необходимо связаться с администрацией сайта.</p>
                <p><small>Ваш щит в цифровом мире. © MurKir Security, 2025</small></p>
            </div>
            
        <?php else: ?>
            <?php 
            $block_info = $unlocker->getBlockInfo();
            if ($block_info): 
                $block_count = $block_info['block_count'];
                $block_until = strtotime($block_info['block_until']);
                $time_remaining = $unlocker->formatTimeRemaining($block_until);
            ?>
                <div class="message warning">
                    <p><strong>Информация о блокировке:</strong></p>
                    <p>Ваш IP-адрес заблокирован <?php echo $block_count > 1 ? "повторно (блокировка #$block_count)" : ""; ?></p>
                    <p>Причина: <?php echo htmlspecialchars($block_info['reason']); ?></p>
                    <p>Блокировка автоматически истечет через: <strong><?php echo $time_remaining; ?></strong></p>
                    <?php if ($block_count > 1): ?>
                        <p><strong>Внимание:</strong> Из-за повторных блокировок время блокировки было увеличено.</p>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            
            <div class="info">
                <p>Ваш IP-адрес (<?php echo htmlspecialchars($current_ip); ?>) временно заблокирован системой безопасности.</p>
                <p>Для разблокировки пройдите интегрированную проверку безопасности ниже.</p>
                <p><strong>Внимание:</strong> Слишком частые попытки разблокировки могут привести к постоянной блокировке.</p>
            </div>
            
            <?php if (!empty($error_message)): ?>
                <div class="message error"><?php echo htmlspecialchars($error_message); ?></div>
            <?php endif; ?>
            
            <form method="post" action="" id="integrated-security-form">
                <input type="hidden" name="bot_protection_data" id="botProtectionData">
                <input type="hidden" name="return_url" value="<?php echo htmlspecialchars($return_url); ?>">
                <?php if (defined('RECAPTCHA_SITE_KEY') && !empty(RECAPTCHA_SITE_KEY)): ?>
                <input type="hidden" id="recaptcha-token" name="g-recaptcha-response">
                <?php endif; ?>
                
                <div class="verification-box" id="verificationBox">
                    <div class="verification-content">
                        <div class="checkbox-container">
                            <div class="security-checkbox" id="securityCheckbox">
                                <div class="security-spinner" id="securitySpinner"></div>
                                <svg class="checkmark" id="securityCheckmark" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3">
                                    <polyline points="20,6 9,17 4,12"></polyline>
                                </svg>
                            </div>
                        </div>
                        <div class="verification-text">Я подтверждаю, что являюсь человеком</div>
                    </div>
                    
                    <div class="security-badge">
                        <div class="shield-icon">🛡</div>
                        <span>AdvancedSecurity v2.0</span>
                        <span style="margin-left: auto; font-size: 11px;">Защищено ИИ</span>
                    </div>

                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                </div>

                <button type="button" class="security-button" id="securitySubmitButton">
                    Разблокировать доступ
                </button>

                <div class="status-message success-status" id="successMessage">
                    <strong>✅ Проверка успешно завершена!</strong><br>
                    Все системы безопасности подтвердили вашу подлинность.
                </div>

                <div class="status-message error-status" id="errorMessage">
                    <strong>❌ Обнаружена подозрительная активность</strong><br>
                    Повторите попытку через несколько секунд.
                </div>

                <div class="status-message warning-status" id="warningMessage">
                    <strong>⚠️ Дополнительная проверка требуется</strong><br>
                    Система анализирует ваше поведение...
                </div>

                <div class="security-details" id="securityDetails">
                    <strong>📊 Детальный анализ безопасности:</strong><br><br>
                    <div id="securityMetrics"></div>
                </div>
            </form>
            
            <div class="footer">
                <p>Если у вас возникли проблемы с разблокировкой, пожалуйста, свяжитесь с администратором сайта.</p>
                <p><small>MurKir Security, 2025</small></p>
            </div>
        <?php endif; ?>
    </div>
    
    <?php include 'unlock_scripts.php'; ?>

    <?php if (!empty($success_message)): ?>
    <script>
    // Автоматический редирект после успешной разблокировки
    document.addEventListener('DOMContentLoaded', function() {
        var returnLink = document.querySelector('.info a');
        if (returnLink) {
            var returnUrl = returnLink.href;
            var count = 3;
            
            function updateCounter() {
                returnLink.textContent = 'Автоматическое перенаправление через ' + count + ' сек...';
                count--;
                
                if (count < 0) {
                    window.location.href = returnUrl;
                } else {
                    setTimeout(updateCounter, 1000);
                }
            }
            
            setTimeout(updateCounter, 1000);
        }
    });
    </script>
    <?php endif; ?>
</body>
</html>