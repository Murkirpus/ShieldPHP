<style>
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0;
        padding: 20px;
    }

    .security-container {
        background: white;
        border-radius: 16px;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2);
        padding: 40px;
        max-width: 600px;
        width: 100%;
        text-align: center;
        position: relative;
        overflow: hidden;
    }

    .security-container::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: linear-gradient(90deg, #4285f4, #34a853, #fbbc05, #ea4335);
    }

    .verification-box {
        border: 2px solid #e0e0e0;
        border-radius: 12px;
        padding: 25px;
        background: #fafafa;
        margin: 25px 0;
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
    }

    .verification-box.checking {
        border-color: #4285f4;
        background: linear-gradient(135deg, #f0f4ff 0%, #e8f0fe 100%);
        box-shadow: 0 8px 25px rgba(66, 133, 244, 0.15);
    }

    .verification-box.verified {
        border-color: #34a853;
        background: linear-gradient(135deg, #f0fff4 0%, #e8f5e8 100%);
        box-shadow: 0 8px 25px rgba(52, 168, 83, 0.15);
    }

    .verification-box.failed {
        border-color: #ea4335;
        background: linear-gradient(135deg, #fff0f0 0%, #fce8e6 100%);
        box-shadow: 0 8px 25px rgba(234, 67, 53, 0.15);
    }

    .verification-content {
        display: flex;
        align-items: center;
        justify-content: flex-start;
        gap: 20px;
    }

    .checkbox-container {
        position: relative;
        width: 28px;
        height: 28px;
    }

    .security-checkbox {
        width: 28px;
        height: 28px;
        border: 3px solid #d1d5db;
        border-radius: 6px;
        background: white;
        cursor: pointer;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
    }

    .security-checkbox:hover {
        border-color: #4285f4;
        transform: scale(1.05);
    }

    .security-checkbox.checking {
        border-color: #4285f4;
        background: #f8f9ff;
    }

    .security-checkbox.verified {
        border-color: #34a853;
        background: #34a853;
        transform: scale(1.1);
    }

    .security-checkbox.failed {
        border-color: #ea4335;
        background: #ffeaea;
    }

    .checkmark {
        width: 16px;
        height: 16px;
        opacity: 0;
        transform: scale(0) rotate(0deg);
        transition: all 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
    }

    .checkmark.show {
        opacity: 1;
        transform: scale(1) rotate(0deg);
    }

    .security-spinner {
        width: 20px;
        height: 20px;
        border: 3px solid #e0e0e0;
        border-top: 3px solid #4285f4;
        border-radius: 50%;
        animation: securitySpin 1.2s linear infinite;
        opacity: 0;
        position: absolute;
    }

    .security-spinner.show {
        opacity: 1;
    }

    @keyframes securitySpin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }

    .verification-text {
        font-size: 18px;
        font-weight: 500;
        color: #333;
        user-select: none;
        flex: 1;
        text-align: left;
    }

    .security-badge {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 13px;
        color: #666;
        margin-top: 15px;
        padding: 8px 12px;
        background: rgba(66, 133, 244, 0.05);
        border-radius: 20px;
        border: 1px solid rgba(66, 133, 244, 0.1);
    }

    .shield-icon {
        width: 18px;
        height: 18px;
        background: linear-gradient(135deg, #4285f4, #1a73e8);
        border-radius: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-weight: bold;
        font-size: 11px;
    }

    .progress-bar {
        width: 100%;
        height: 4px;
        background: #e0e0e0;
        border-radius: 2px;
        margin-top: 15px;
        overflow: hidden;
    }

    .progress-fill {
        height: 100%;
        background: linear-gradient(90deg, #4285f4, #34a853);
        width: 0%;
        transition: width 0.3s ease;
    }

    .message {
        padding: 15px;
        margin-bottom: 20px;
        border-radius: 8px;
        font-weight: 500;
    }

    .success {
        background: linear-gradient(135deg, #d4edda, #c3e6cb);
        border: 1px solid #c3e6cb;
        color: #155724;
    }

    .error {
        background: linear-gradient(135deg, #f8d7da, #f1b0b7);
        border: 1px solid #f1b0b7;
        color: #721c24;
    }

    .warning {
        background: linear-gradient(135deg, #fff3cd, #ffeaa7);
        border: 1px solid #ffeaa7;
        color: #856404;
    }

    .danger {
        background: linear-gradient(135deg, #f8d7da, #f5c6cb);
        border: 1px solid #f5c6cb;
        color: #721c24;
    }

    .info {
        background: linear-gradient(135deg, #d1ecf1, #bee5eb);
        border: 1px solid #bee5eb;
        color: #0c5460;
        margin-top: 20px;
        padding: 20px;
        border-radius: 8px;
    }

    .security-button {
        background: linear-gradient(135deg, #4285f4, #1a73e8);
        color: white;
        border: none;
        padding: 15px 40px;
        border-radius: 8px;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
        margin-top: 20px;
        opacity: 0.4;
        pointer-events: none;
        position: relative;
        overflow: hidden;
    }

    .security-button.enabled {
        opacity: 1;
        pointer-events: auto;
    }

    .security-button.enabled:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(66, 133, 244, 0.4);
    }

    .security-button:active {
        transform: translateY(0);
    }

    h1 {
        color: #333;
        margin-bottom: 10px;
        font-size: 28px;
        font-weight: 600;
    }

    .subtitle {
        color: #666;
        margin-bottom: 30px;
        font-size: 16px;
    }

    .security-details {
        margin-top: 25px;
        padding: 20px;
        background: #f8f9fa;
        border-radius: 10px;
        font-size: 13px;
        color: #666;
        text-align: left;
        display: none;
        border: 1px solid #e9ecef;
    }

    .security-details.show {
        display: block;
    }

    .security-metric {
        display: flex;
        justify-content: space-between;
        padding: 4px 0;
        border-bottom: 1px solid #e9ecef;
    }

    .security-metric:last-child {
        border-bottom: none;
    }

    .metric-label {
        font-weight: 500;
    }

    .metric-value {
        color: #333;
    }

    .security-level {
        display: inline-block;
        padding: 4px 8px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
    }

    .level-low { background: #d4edda; color: #155724; }
    .level-medium { background: #fff3cd; color: #856404; }
    .level-high { background: #f8d7da; color: #721c24; }

    .footer {
        margin-top: 30px;
        font-size: 14px;
        color: #777;
        text-align: center;
    }

    .footer a {
        color: #4285f4;
        text-decoration: none;
    }

    .footer a:hover {
        text-decoration: underline;
    }

    /* Honeypot ловушки */
    .security-trap, .bot-trap, .hidden-field {
        position: absolute !important;
        left: -9999px !important;
        top: -9999px !important;
        opacity: 0 !important;
        pointer-events: none !important;
        width: 0 !important;
        height: 0 !important;
        overflow: hidden !important;
        visibility: hidden !important;
        z-index: -1000 !important;
    }

    .status-message {
        margin-top: 25px;
        padding: 20px;
        border-radius: 10px;
        opacity: 0;
        transform: translateY(15px);
        transition: all 0.4s ease;
        font-weight: 500;
    }

    .status-message.show {
        opacity: 1;
        transform: translateY(0);
    }

    .success-status {
        background: linear-gradient(135deg, #d4edda, #c3e6cb);
        border: 1px solid #c3e6cb;
        color: #155724;
    }

    .error-status {
        background: linear-gradient(135deg, #f8d7da, #f1b0b7);
        border: 1px solid #f1b0b7;
        color: #721c24;
    }

    .warning-status {
        background: linear-gradient(135deg, #fff3cd, #ffeaa7);
        border: 1px solid #ffeaa7;
        color: #856404;
    }

    /* Адаптивность */
    @media (max-width: 768px) {
        .security-container {
            padding: 20px;
            margin: 10px;
        }
        
        h1 {
            font-size: 24px;
        }
        
        .verification-content {
            gap: 15px;
        }
        
        .verification-text {
            font-size: 16px;
        }
        
        .security-button {
            padding: 12px 30px;
            font-size: 14px;
        }
    }

    @media (max-width: 480px) {
        .security-container {
            padding: 15px;
        }
        
        .verification-box {
            padding: 15px;
        }
        
        .verification-content {
            flex-direction: column;
            gap: 10px;
            text-align: center;
        }
        
        .verification-text {
            text-align: center;
        }
    }
</style>