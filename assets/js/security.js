/**
 * Xavfsizlik JavaScript fayli
 * Web Security Project
 */

// DOM yuklangandan keyin ishga tushirish
document.addEventListener('DOMContentLoaded', function() {
    initSecurity();
});

/**
 * Xavfsizlik funksiyalarini ishga tushirish
 */
function initSecurity() {
    // Password strength checker
    initPasswordStrengthChecker();

    // Form validation
    initFormValidation();

    // Security monitoring
    initSecurityMonitoring();

    // CSRF token refresh
    initCSRFTokenRefresh();
}

/**
 * Parol kuchliligini tekshirish
 */
function initPasswordStrengthChecker() {
    const passwordInputs = document.querySelectorAll('input[type="password"]');

    passwordInputs.forEach(input => {
        if (input.name === 'password' || input.id === 'password') {
            input.addEventListener('input', function() {
                checkPasswordStrength(this.value, this);
            });
        }
    });
}

function checkPasswordStrength(password, inputElement) {
    const strengthIndicator = document.getElementById('password-strength');
    if (!strengthIndicator) return;

    let score = 0;
    let feedback = [];

    // Uzunlik tekshirish
    if (password.length >= 8) {
        score += 1;
    } else {
        feedback.push('Kamida 8 ta belgi');
    }

    // Katta harf
    if (/[A-Z]/.test(password)) {
        score += 1;
    } else {
        feedback.push('Katta harf');
    }

    // Kichik harf
    if (/[a-z]/.test(password)) {
        score += 1;
    } else {
        feedback.push('Kichik harf');
    }

    // Raqam
    if (/[0-9]/.test(password)) {
        score += 1;
    } else {
        feedback.push('Raqam');
    }

    // Maxsus belgi
    if (/[^A-Za-z0-9]/.test(password)) {
        score += 1;
    } else {
        feedback.push('Maxsus belgi');
    }

    // Natijani ko'rsatish
    updatePasswordStrengthUI(score, feedback, strengthIndicator);
}

function updatePasswordStrengthUI(score, feedback, indicator) {
    const levels = ['Juda zaif', 'Zaif', 'O\'rtacha', 'Kuchli', 'Juda kuchli'];
    const colors = ['#e74c3c', '#e67e22', '#f39c12', '#27ae60', '#2ecc71'];

    indicator.textContent = levels[score] || 'Zaif';
    indicator.style.color = colors[score] || '#e74c3c';

    if (feedback.length > 0) {
        indicator.textContent += ' (Kerak: ' + feedback.join(', ') + ')';
    }
}

/**
 * Form validatsiyasi
 */
function initFormValidation() {
    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!validateForm(this)) {
                e.preventDefault();
                return false;
            }
        });

        // Real-time validation
        const inputs = form.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            input.addEventListener('blur', function() {
                validateField(this);
            });
        });
    });
}

function validateForm(form) {
    let isValid = true;
    const inputs = form.querySelectorAll('input[required], textarea[required], select[required]');

    inputs.forEach(input => {
        if (!validateField(input)) {
            isValid = false;
        }
    });

    return isValid;
}

function validateField(field) {
    const value = field.value.trim();
    const fieldType = field.type || field.tagName.toLowerCase();
    let isValid = true;
    let errorMessage = '';

    // Required field check
    if (field.hasAttribute('required') && !value) {
        isValid = false;
        errorMessage = 'Bu maydon to\'ldirilishi shart';
    }

    // Specific validation
    if (value && isValid) {
        switch (fieldType) {
            case 'email':
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(value)) {
                    isValid = false;
                    errorMessage = 'Email manzil noto\'g\'ri';
                }
                break;

            case 'password':
                if (field.name === 'password' && value.length < 6) {
                    isValid = false;
                    errorMessage = 'Parol kamida 6 ta belgidan iborat bo\'lishi kerak';
                }
                break;

            case 'text':
                if (field.name === 'username') {
                    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
                    if (!usernameRegex.test(value)) {
                        isValid = false;
                        errorMessage = 'Foydalanuvchi nomi 3-20 ta belgi (harf, raqam, _)';
                    }
                }
                break;
        }
    }

    // Password confirmation
    if (field.name === 'confirm_password') {
        const passwordField = document.querySelector('input[name="password"]');
        if (passwordField && value !== passwordField.value) {
            isValid = false;
            errorMessage = 'Parollar mos kelmaydi';
        }
    }

    // UI update
    updateFieldValidation(field, isValid, errorMessage);

    return isValid;
}

function updateFieldValidation(field, isValid, errorMessage) {
    // Remove existing error classes
    field.classList.remove('error');

    // Remove existing error message
    const existingError = field.parentNode.querySelector('.error-message');
    if (existingError) {
        existingError.remove();
    }

    if (!isValid) {
        field.classList.add('error');

        // Add error message
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = errorMessage;
        field.parentNode.appendChild(errorDiv);
    }
}

/**
 * Xavfsizlik monitoring
 */
function initSecurityMonitoring() {
    // Suspicious activity detection
    monitorSuspiciousActivity();

    // Session timeout warning
    initSessionTimeout();
}

function monitorSuspiciousActivity() {
    let rapidClicks = 0;
    let lastClickTime = 0;

    document.addEventListener('click', function() {
        const currentTime = Date.now();

        if (currentTime - lastClickTime < 100) { // 100ms dan tez
            rapidClicks++;

            if (rapidClicks > 10) {
                console.warn('Suspicious rapid clicking detected');
                // Server ga yuborish mumkin
            }
        } else {
            rapidClicks = 0;
        }

        lastClickTime = currentTime;
    });
}

function initSessionTimeout() {
    let timeoutWarning;
    const warningTime = 25 * 60 * 1000; // 25 daqiqa
    const sessionTime = 30 * 60 * 1000; // 30 daqiqa

    function resetTimer() {
        clearTimeout(timeoutWarning);

        timeoutWarning = setTimeout(() => {
            if (confirm('Sessiya 5 daqiqadan keyin tugaydi. Davom etasizmi?')) {
                // AJAX request to extend session
                extendSession();
                resetTimer();
            }
        }, warningTime);
    }

    // User activity listeners
    ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(event => {
        document.addEventListener(event, resetTimer, true);
    });

    resetTimer();
}

function extendSession() {
    fetch('api/extend_session.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'same-origin'
    })
        .then(response => response.json())
        .then(data => {
            if (!data.success) {
                window.location.href = 'auth/login.php';
            }
        })
        .catch(error => {
            console.error('Session extension failed:', error);
        });
}

/**
 * CSRF token yangilash
 */
function initCSRFTokenRefresh() {
    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        form.addEventListener('submit', function() {
            refreshCSRFToken(this);
        });
    });
}

function refreshCSRFToken(form) {
    const csrfInput = form.querySelector('input[name="csrf_token"]');
    if (!csrfInput) return;

    fetch('security/csrf_token.php', {
        method: 'GET',
        credentials: 'same-origin'
    })
        .then(response => response.json())
        .then(data => {
            if (data.token) {
                csrfInput.value = data.token;
            }
        })
        .catch(error => {
            console.error('CSRF token refresh failed:', error);
        });
}

/**
 * XSS himoyasi - ma'lumotni tozalash
 */
function sanitizeInput(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Secure form submission
 */
function secureSubmit(form, callback) {
    const formData = new FormData(form);

    // CSRF token check
    const csrfToken = formData.get('csrf_token');
    if (!csrfToken) {
        alert('Xavfsizlik xatosi: CSRF token topilmadi');
        return false;
    }

    // Show loading
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="loading"></span> Yuborilmoqda...';
    }

    fetch(form.action || window.location.href, {
        method: form.method || 'POST',
        body: formData,
        credentials: 'same-origin'
    })
        .then(response => response.json())
        .then(data => {
            if (callback) callback(data);
        })
        .catch(error => {
            console.error('Form submission error:', error);
            alert('Xatolik yuz berdi. Iltimos qaytadan urinib ko\'ring.');
        })
        .finally(() => {
            // Hide loading
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = submitBtn.getAttribute('data-original-text') || 'Yuborish';
            }
        });
}

// Global utility functions
window.SecurityUtils = {
    sanitizeInput,
    validateField,
    secureSubmit,
    checkPasswordStrength
};