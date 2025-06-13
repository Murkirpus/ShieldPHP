<script>
// Интегрированная система защиты от ботов для страницы разблокировки
class IntegratedUnlockProtection {
    constructor() {
        // Временные метрики
        this.sessionStart = Date.now();
        this.pageLoadTime = performance.now();
        this.firstInteractionTime = null;
        
        // Поведенческие данные
        this.mouseData = [];
        this.clickEvents = [];
        this.keyboardData = [];
        this.scrollData = [];
        this.focusEvents = [];
        
        // Cookie и сессия
        this.cookieTests = {};
        this.cookieFallback = {};
        
        // Анализ окружения
        this.environmentData = {};
        
        // Система оценки
        this.riskScore = 0;
        this.confidenceLevel = 0;
        this.verificationAttempts = 0;
        
        // Инициализация системы
        this.initializeProtection();
    }

    initializeProtection() {
        console.log('🛡️ Инициализация интегрированной защиты для разблокировки...');
        
        this.setupCookieProtection();
        this.setupBehaviorTracking();
        this.setupEnvironmentAnalysis();
        this.startContinuousMonitoring();
        
        console.log('✅ Все системы защиты для разблокировки активированы');
    }

    setupCookieProtection() {
        this.cookieFallback = {};
        this.cookiesWorking = 0;
        
        const testValue = 'unlock_test123';
        
        try {
            document.cookie = `unlock_test=${testValue}`;
            
            setTimeout(() => {
                const testResult = document.cookie.includes(`unlock_test=${testValue}`);
                if (testResult) {
                    this.cookiesSupported = true;
                    this.cookiesWorking = 1;
                } else {
                    this.cookiesSupported = false;
                }
            }, 50);
            
        } catch (e) {
            this.cookiesSupported = false;
        }
        
        this.cookieFallback.unlock_session_id = this.generateSecureToken(16);
        this.cookieFallback.unlock_start_time = Date.now().toString();
        
        this.cookieTests = {
            session: this.cookieFallback.unlock_session_id,
            time: this.cookieFallback.unlock_start_time
        };
    }

    setupBehaviorTracking() {
        // Отслеживание мыши
        document.addEventListener('mousemove', (e) => {
            if (!this.firstInteractionTime) this.firstInteractionTime = Date.now();
            
            this.mouseData.push({
                x: e.clientX,
                y: e.clientY,
                timestamp: Date.now(),
                movementX: e.movementX || 0,
                movementY: e.movementY || 0
            });
            
            if (this.mouseData.length > 50) {
                this.mouseData.shift();
            }
        });

        // Отслеживание кликов
        document.addEventListener('click', (e) => {
            this.clickEvents.push({
                x: e.clientX,
                y: e.clientY,
                timestamp: Date.now(),
                target: e.target.tagName,
                isTrusted: e.isTrusted
            });
        });

        // Отслеживание клавиатуры
        document.addEventListener('keydown', (e) => {
            this.keyboardData.push({
                key: e.key,
                timestamp: Date.now(),
                isTrusted: e.isTrusted
            });
        });

        // Отслеживание прокрутки
        window.addEventListener('scroll', () => {
            this.scrollData.push({
                scrollY: window.scrollY,
                timestamp: Date.now()
            });
        });

        // События фокуса
        ['focus', 'blur'].forEach(event => {
            document.addEventListener(event, () => {
                this.focusEvents.push({
                    type: event,
                    timestamp: Date.now()
                });
            });
        });
    }

    setupEnvironmentAnalysis() {
        this.environmentData = {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            cookieEnabled: navigator.cookieEnabled,
            
            // Подозрительные признаки автоматизации
            webdriver: navigator.webdriver || false,
            phantom: !!window.phantom,
            selenium: !!window._selenium,
            
            // Размеры экрана
            screenWidth: screen.width,
            screenHeight: screen.height,
            windowWidth: window.innerWidth,
            windowHeight: window.innerHeight,
            
            // Временная зона
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timezoneOffset: new Date().getTimezoneOffset()
        };

        this.analyzeEnvironmentSuspicion();
    }

    analyzeEnvironmentSuspicion() {
        if (this.environmentData.webdriver) {
            this.riskScore += 20;
        }
        if (this.environmentData.phantom) {
            this.riskScore += 25;
        }
        if (this.environmentData.selenium) {
            this.riskScore += 25;
        }
    }

    startContinuousMonitoring() {
        setInterval(() => {
            this.updateRiskAssessment();
            this.updateConfidenceLevel();
        }, 2000);
    }

    updateRiskAssessment() {
        const criticalRisk = (this.environmentData?.webdriver ? 30 : 0) +
                           (this.environmentData?.phantom ? 35 : 0);
        
        this.riskScore = criticalRisk;
        
        const sessionTime = Date.now() - this.sessionStart;
        
        // Позитивные факторы для разблокировки
        if (this.mouseData?.length > 3) this.riskScore -= 15;
        if (this.mouseData?.length > 10) this.riskScore -= 10;
        if (this.clickEvents?.length > 0) this.riskScore -= 10;
        if (this.keyboardData?.length > 0) this.riskScore -= 8;
        if (sessionTime > 3000) this.riskScore -= 15;
        if (sessionTime > 10000) this.riskScore -= 10;
        
        const interactionTypes = [
            (this.mouseData?.length || 0) > 0,
            (this.clickEvents?.length || 0) > 0,
            (this.keyboardData?.length || 0) > 0,
            (this.scrollData?.length || 0) > 0
        ].filter(Boolean).length;
        
        this.riskScore -= interactionTypes * 6;
        
        if (this.cookiesSupported === true) {
            this.riskScore -= 15;
        } else if (this.cookieFallback && Object.keys(this.cookieFallback).length > 0) {
            this.riskScore -= 10;
        }
        
        this.riskScore = Math.max(0, Math.min(100, this.riskScore));
    }

    updateConfidenceLevel() {
        const sessionTime = Date.now() - this.sessionStart;
        
        const factors = [
            this.mouseData.length > 5 ? 20 : this.mouseData.length > 2 ? 10 : 5,
            this.clickEvents.length > 1 ? 15 : this.clickEvents.length > 0 ? 8 : 0,
            this.keyboardData.length > 0 ? 10 : 0,
            this.cookiesSupported !== false ? 15 : 8,
            sessionTime > 5000 ? 10 : sessionTime > 2000 ? 5 : 0,
            this.scrollData.length > 0 ? 8 : 0,
            this.focusEvents.length > 0 ? 7 : 0
        ];
        
        this.confidenceLevel = Math.min(100, factors.reduce((sum, factor) => sum + factor, 0));
    }

    performFinalVerification() {
        console.log('🛡️ Выполнение финальной проверки для разблокировки...');
        
        this.verificationAttempts = (this.verificationAttempts || 0) + 1;
        
        this.riskScore = 0;
        this.updateRiskAssessment();
        
        if (this.environmentData?.webdriver || this.environmentData?.phantom) {
            return { 
                success: false, 
                reason: 'automation_detected', 
                confidence: 95, 
                riskScore: 100, 
                details: this.generateDetailedReport() 
            };
        }
        
        const finalRiskScore = Math.max(0, Math.min(100, this.riskScore || 0));
        const finalConfidence = Math.max(0, Math.min(100, this.confidenceLevel || 0));
        
        // Более мягкие условия для разблокировки
        const hasMinimalActivity = (this.mouseData?.length || 0) > 2 || (this.clickEvents?.length || 0) > 0;
        const hasAnyStorage = this.cookiesSupported === true || (this.cookieFallback && Object.keys(this.cookieFallback).length > 0);
        const noAutomation = !this.environmentData?.webdriver && !this.environmentData?.phantom;
        const hasTime = Date.now() - this.sessionStart > 800;
        
        const successConditions = [
            finalRiskScore < 85,
            hasMinimalActivity,
            hasAnyStorage,
            noAutomation,
            hasTime,
            finalConfidence > 25
        ];
        
        const successCount = successConditions.filter(Boolean).length;
        const isHuman = successCount >= 4;
        
        const result = {
            success: isHuman,
            reason: isHuman ? 'unlock_verification_passed' : 'suspicious_unlock_behavior',
            confidence: finalConfidence,
            riskScore: finalRiskScore,
            successConditions: successCount,
            details: this.generateDetailedReport()
        };
        
        return result;
    }

    generateDetailedReport() {
        const now = Date.now();
        const sessionDuration = now - this.sessionStart;
        
        return {
            sessionDuration: sessionDuration,
            mouseMovements: this.mouseData?.length || 0,
            clickEvents: this.clickEvents?.length || 0,
            keyboardEvents: this.keyboardData?.length || 0,
            scrollEvents: this.scrollData?.length || 0,
            focusEvents: this.focusEvents?.length || 0,
            cookieStatus: this.cookiesSupported,
            cookiesSupported: this.cookiesSupported,
            cookiesWorking: this.cookiesWorking || 0,
            fallbackActive: this.cookieFallback ? Object.keys(this.cookieFallback).length : 0,
            environmentRisk: this.environmentData || {},
            verificationAttempts: this.verificationAttempts || 0,
            finalRiskScore: this.riskScore || 0,
            confidenceLevel: this.confidenceLevel || 0,
            unlockMode: true
        };
    }

    generateSecureToken(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        for (let i = 0; i < length; i++) {
            result += chars[array[i] % chars.length];
        }
        return result;
    }
}

// Инициализация системы защиты для разблокировки
const unlockProtection = new IntegratedUnlockProtection();

// Элементы интерфейса
const verificationBox = document.getElementById('verificationBox');
const securityCheckbox = document.getElementById('securityCheckbox');
const securitySpinner = document.getElementById('securitySpinner');
const securityCheckmark = document.getElementById('securityCheckmark');
const progressFill = document.getElementById('progressFill');
const successMessage = document.getElementById('successMessage');
const errorMessage = document.getElementById('errorMessage');
const warningMessage = document.getElementById('warningMessage');
const securitySubmitButton = document.getElementById('securitySubmitButton');
const securityDetails = document.getElementById('securityDetails');
const securityMetrics = document.getElementById('securityMetrics');
const integratedForm = document.getElementById('integrated-security-form');

let isVerified = false;
let isVerifying = false;

// Главная функция проверки
if (securityCheckbox) {
    securityCheckbox.addEventListener('click', async function() {
        if (isVerified || isVerifying) return;
        
        startUnlockVerificationProcess();
    });
}

async function startUnlockVerificationProcess() {
    isVerifying = true;
    
    // Визуальные изменения
    verificationBox.classList.add('checking');
    securityCheckbox.classList.add('checking');
    securitySpinner.classList.add('show');
    
    // Сброс предыдущих сообщений
    [successMessage, errorMessage, warningMessage].forEach(msg => 
        msg.classList.remove('show')
    );
    
    // Прогресс бар
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += Math.random() * 12;
        progressFill.style.width = Math.min(progress, 85) + '%';
    }, 200);
    
    // Показываем предупреждение во время проверки
    setTimeout(() => {
        warningMessage.classList.add('show');
    }, 800);
    
    // Выполняем проверку (2-4 секунды для разблокировки)
    const verificationDelay = 2000 + Math.random() * 2000;
    
    setTimeout(async () => {
        clearInterval(progressInterval);
        progressFill.style.width = '100%';
        
        const result = await unlockProtection.performFinalVerification();
        finishUnlockVerification(result);
    }, verificationDelay);
}

function finishUnlockVerification(result) {
    isVerifying = false;
    
    // Скрываем спиннер и предупреждение
    securitySpinner.classList.remove('show');
    warningMessage.classList.remove('show');
    verificationBox.classList.remove('checking');
    securityCheckbox.classList.remove('checking');
    
    if (result.success) {
        // Успешная проверка
        isVerified = true;
        verificationBox.classList.add('verified');
        securityCheckbox.classList.add('verified');
        securityCheckmark.classList.add('show');
        
        // Сохраняем данные проверки для отправки
        document.getElementById('botProtectionData').value = JSON.stringify({
            verification_result: result,
            timestamp: Date.now()
        });
        
        setTimeout(() => {
            successMessage.classList.add('show');
            securitySubmitButton.classList.add('enabled');
            showUnlockSecurityDetails(result);
        }, 500);
        
    } else {
        // Проверка не пройдена
        verificationBox.classList.add('failed');
        securityCheckbox.classList.add('failed');
        
        setTimeout(() => {
            errorMessage.classList.add('show');
            showUnlockSecurityDetails(result);
            
            // Сброс для повторной попытки через 3 секунды
            setTimeout(resetUnlockVerification, 3000);
        }, 500);
    }
}

function resetUnlockVerification() {
    verificationBox.classList.remove('failed');
    securityCheckbox.classList.remove('failed');
    errorMessage.classList.remove('show');
    progressFill.style.width = '0%';
    securityDetails.classList.remove('show');
}

function showUnlockSecurityDetails(result) {
    const report = result.details || {};
    const riskLevel = (result.riskScore || 0) < 30 ? 'low' : (result.riskScore || 0) < 60 ? 'medium' : 'high';
    const riskText = (result.riskScore || 0) < 30 ? 'Низкий' : (result.riskScore || 0) < 60 ? 'Средний' : 'Высокий';
    
    let cookieStatusText = '❓ Неизвестно';
    if (unlockProtection.cookiesSupported === true) {
        cookieStatusText = '✅ Работают';
    } else if (unlockProtection.cookiesSupported === false) {
        cookieStatusText = '⚠️ Используется fallback';
    } else if (unlockProtection.cookieFallback && Object.keys(unlockProtection.cookieFallback).length > 0) {
        cookieStatusText = '⚠️ Только fallback';
    }
    
    const sessionDuration = report.sessionDuration || (Date.now() - unlockProtection.sessionStart);
    const mouseMovements = report.mouseMovements || unlockProtection.mouseData?.length || 0;
    const clickEvents = report.clickEvents || unlockProtection.clickEvents?.length || 0;
    const keyboardEvents = report.keyboardEvents || unlockProtection.keyboardData?.length || 0;
    const verificationAttempts = report.verificationAttempts || unlockProtection.verificationAttempts || 0;
    const riskScore = result.riskScore || unlockProtection.riskScore || 0;
    const confidence = result.confidence || unlockProtection.confidenceLevel || 0;
    
    securityMetrics.innerHTML = `
        <div class="security-metric">
            <span class="metric-label">Режим:</span>
            <span class="metric-value">🔓 Разблокировка</span>
        </div>
        <div class="security-metric">
            <span class="metric-label">Уровень риска:</span>
            <span class="metric-value">
                <span class="security-level level-${riskLevel}">${riskText}</span>
                (${riskScore}/100)
            </span>
        </div>
        <div class="security-metric">
            <span class="metric-label">Уровень доверия:</span>
            <span class="metric-value">${confidence}%</span>
        </div>
        <div class="security-metric">
            <span class="metric-label">Время проверки:</span>
            <span class="metric-value">${Math.round(sessionDuration/1000)}с</span>
        </div>
        <div class="security-metric">
            <span class="metric-label">Движения мыши:</span>
            <span class="metric-value">${mouseMovements}</span>
        </div>
        <div class="security-metric">
            <span class="metric-label">Клики:</span>
            <span class="metric-value">${clickEvents}</span>
        </div>
        <div class="security-metric">
            <span class="metric-label">Нажатия клавиш:</span>
            <span class="metric-value">${keyboardEvents}</span>
        </div>
        <div class="security-metric">
            <span class="metric-label">Cookie статус:</span>
            <span class="metric-value">${cookieStatusText}</span>
        </div>
        <div class="security-metric">
            <span class="metric-label">WebDriver:</span>
            <span class="metric-value">${report.environmentRisk?.webdriver ? '🚨 Обнаружен' : '✅ Не найден'}</span>
        </div>
        <div class="security-metric">
            <span class="metric-label">Попытки:</span>
            <span class="metric-value">${verificationAttempts}</span>
        </div>
    `;
    
    securityDetails.classList.add('show');
}

// Отправка формы с интегрированной и reCAPTCHA проверкой
if (securitySubmitButton) {
    securitySubmitButton.addEventListener('click', async function() {
        if (!isVerified) return;
        
        // Выполняем reCAPTCHA проверку, если она настроена
        <?php if (defined('RECAPTCHA_SITE_KEY') && !empty(RECAPTCHA_SITE_KEY)): ?>
        try {
            const token = await grecaptcha.execute('<?php echo RECAPTCHA_SITE_KEY; ?>', {action: 'unlock'});
            document.getElementById('recaptcha-token').value = token;
        } catch (error) {
            console.error('reCAPTCHA error:', error);
            alert('Ошибка reCAPTCHA. Пожалуйста, попробуйте еще раз.');
            return;
        }
        <?php endif; ?>
        
        // Отправляем форму
        integratedForm.submit();
    });
}

// Эффекты при наведении
if (verificationBox) {
    verificationBox.addEventListener('mouseenter', function() {
        if (!isVerified && !isVerifying) {
            this.style.transform = 'translateY(-2px)';
            this.style.boxShadow = '0 15px 35px rgba(0,0,0,0.15)';
        }
    });

    verificationBox.addEventListener('mouseleave', function() {
        if (!isVerified && !isVerifying) {
            this.style.transform = 'translateY(0)';
            this.style.boxShadow = '0 20px 60px rgba(0, 0, 0, 0.2)';
        }
    });
}

console.log('🚀 Интегрированная система разблокировки активирована!');
console.log('🔓 Режим разблокировки с упрощенными проверками');

// Диагностическая информация
setTimeout(() => {
    console.log('📋 Диагностика разблокировки:');
    console.log('- Cookies поддержка:', unlockProtection.cookiesSupported);
    console.log('- Risk score:', unlockProtection.riskScore);
    console.log('- Confidence:', unlockProtection.confidenceLevel + '%');
    console.log('- Режим:', 'Разблокировка IP');
}, 1500);
</script>