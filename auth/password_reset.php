<?php
/**
 * Parol tiklash sahifasi
 * Web Security Project
 */

require_once '../config/database.php';
require_once '../config/security.php';
require_once '../security/rate_limiter.php';
require_once '../security/security_logger.php';
require_once '../security/csrf_token.php';

// Agar foydalanuvchi allaqachon login qilgan bo'lsa
if (isset($_SESSION['user_id'])) {
    header('Location: ../index.php');
    exit;
}

$step = $_GET['step'] ?? 'request';
$token = $_GET['token'] ?? '';
$error = '';
$success = '';

// CSRF token
$csrfToken = CSRFToken::generate();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF tekshirish
    if (!CSRFToken::verify($_POST['csrf_token'] ?? '')) {
        $error = 'Xavfsizlik xatosi! Sahifani qaytadan yuklang.';
        SecurityLogger::log('csrf_token_invalid', null, null, 'high', 'Invalid CSRF token on password reset');
    } else {
        $action = $_POST['action'] ?? '';
        $clientIP = SecurityConfig::getClientIP();
        $rateLimiter = new RateLimiter();

        if ($action === 'request_reset') {
            // Parol tiklash so'rovi
            if ($rateLimiter->isBlocked($clientIP, 'password_reset')) {
                $error = 'Juda ko\'p urinish! Iltimos 1 soatdan keyin qaytadan urinib ko\'ring.';
                SecurityLogger::log('password_reset_blocked', null, $clientIP, 'high', 'Rate limit exceeded for password reset');
            } else {
                $email = SecurityConfig::sanitizeInput($_POST['email'] ?? '');

                if (!SecurityConfig::validateInput($email, 'email')) {
                    $error = 'Email manzil noto\'g\'ri!';
                } else {
                    try {
                        $db = getDB();

                        // Foydalanuvchini topish
                        $stmt = $db->prepare("SELECT id, username, full_name FROM users WHERE email = ? AND is_active = 1");
                        $stmt->execute([$email]);
                        $user = $stmt->fetch();

                        if ($user) {
                            // Reset token yaratish
                            $resetToken = bin2hex(random_bytes(32));
                            $expiresAt = date('Y-m-d H:i:s', time() + 3600); // 1 soat

                            // Eski tokenlarni o'chirish
                            $stmt = $db->prepare("DELETE FROM password_reset_tokens WHERE user_id = ?");
                            $stmt->execute([$user['id']]);

                            // Yangi token saqlash
                            $stmt = $db->prepare("
                                INSERT INTO password_reset_tokens (user_id, token, expires_at) 
                                VALUES (?, ?, ?)
                            ");
                            $stmt->execute([$user['id'], $resetToken, $expiresAt]);

                            // Email yuborish (demo uchun faqat link ko'rsatamiz)
                            $resetLink = "http://" . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']) . "/password_reset.php?step=reset&token=" . $resetToken;

                            $success = "Parol tiklash havolasi yaratildi! Demo uchun: <br><a href='{$resetLink}' target='_blank'>{$resetLink}</a>";

                            SecurityLogger::log('password_reset_requested', $user['id'], $clientIP, 'low',
                                "Password reset requested for email: {$email}");
                        } else {
                            // Xavfsizlik uchun hamma holda ham muvaffaqiyat xabarini ko'rsatamiz
                            $success = "Agar bu email manzil mavjud bo'lsa, parol tiklash havolasi yuborildi.";
                            $rateLimiter->recordAttempt($clientIP, 'password_reset');
                            SecurityLogger::log('password_reset_invalid_email', null, $clientIP, 'medium',
                                "Password reset attempt with non-existent email: {$email}");
                        }

                    } catch (PDOException $e) {
                        error_log("Password reset request error: " . $e->getMessage());
                        $error = 'Tizimda xatolik yuz berdi. Iltimos keyinroq urinib ko\'ring.';
                    }
                }
            }
        }

        if ($action === 'reset_password') {
            // Parolni yangilash
            $newPassword = $_POST['new_password'] ?? '';
            $confirmPassword = $_POST['confirm_password'] ?? '';
            $resetToken = $_POST['reset_token'] ?? '';

            if (empty($newPassword) || empty($confirmPassword) || empty($resetToken)) {
                $error = 'Barcha maydonlarni to\'ldiring!';
            } elseif ($newPassword !== $confirmPassword) {
                $error = 'Parollar mos kelmaydi!';
            } elseif (!SecurityConfig::isStrongPassword($newPassword)) {
                $error = 'Parol kamida 8 ta belgi, katta va kichik harf, raqam bo\'lishi kerak!';
            } else {
                try {
                    $db = getDB();

                    // Token tekshirish
                    $stmt = $db->prepare("
                        SELECT u.id, u.username, u.email 
                        FROM password_reset_tokens prt
                        JOIN users u ON prt.user_id = u.id
                        WHERE prt.token = ? AND prt.expires_at > NOW() AND u.is_active = 1
                    ");
                    $stmt->execute([$resetToken]);
                    $user = $stmt->fetch();

                    if ($user) {
                        // Parolni yangilash
                        $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);

                        $stmt = $db->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
                        $stmt->execute([$passwordHash, $user['id']]);

                        // Reset tokenni o'chirish
                        $stmt = $db->prepare("DELETE FROM password_reset_tokens WHERE user_id = ?");
                        $stmt->execute([$user['id']]);

                        // Failed login attempts ni tozalash
                        $stmt = $db->prepare("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?");
                        $stmt->execute([$user['id']]);

                        $success = 'Parol muvaffaqiyatli yangilandi! Endi yangi parol bilan kirishingiz mumkin.';

                        SecurityLogger::log('password_reset_completed', $user['id'], $clientIP, 'low',
                            "Password successfully reset for user: {$user['username']}");

                        // 3 soniyadan keyin login sahifasiga yo'naltirish
                        header("refresh:3;url=login.php");

                    } else {
                        $error = 'Token noto\'g\'ri yoki muddati tugagan!';
                        SecurityLogger::log('password_reset_invalid_token', null, $clientIP, 'medium',
                            'Invalid or expired password reset token used');
                    }

                } catch (PDOException $e) {
                    error_log("Password reset error: " . $e->getMessage());
                    $error = 'Tizimda xatolik yuz berdi. Iltimos keyinroq urinib ko\'ring.';
                }
            }
        }
    }
}

// Token tekshirish (reset sahifasi uchun)
if ($step === 'reset' && $token) {
    try {
        $db = getDB();
        $stmt = $db->prepare("
            SELECT u.username, u.email 
            FROM password_reset_tokens prt
            JOIN users u ON prt.user_id = u.id
            WHERE prt.token = ? AND prt.expires_at > NOW()
        ");
        $stmt->execute([$token]);
        $tokenUser = $stmt->fetch();

        if (!$tokenUser) {
            $error = 'Token noto\'g\'ri yoki muddati tugagan!';
            $step = 'request';
        }
    } catch (PDOException $e) {
        error_log("Token verification error: " . $e->getMessage());
        $error = 'Tizimda xatolik yuz berdi.';
        $step = 'request';
    }
}
?>

    <!DOCTYPE html>
    <html lang="uz">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Parol tiklash - Web Security</title>
        <link rel="stylesheet" href="../assets/css/style.css">
    </head>
    <body>
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">
                <h2><a href="../index.php" style="text-decoration: none; color: inherit;">🛡️ Web Security</a></h2>
            </div>
            <div class="nav-menu">
                <a href="../index.php" class="nav-link">Bosh sahifa</a>
                <a href="login.php" class="nav-link">Kirish</a>
                <a href="register.php" class="nav-link">Ro'yxatdan o'tish</a>
            </div>
        </div>
    </nav>

    <main class="main-content">
        <div class="container">
            <div class="form-container">
                <?php if ($step === 'request'): ?>
                    <h2 style="text-align: center; color: #764ba2; margin-bottom: 2rem;">Parolni Tiklash</h2>

                    <?php if ($error): ?>
                        <div class="alert alert-error"><?= SecurityConfig::sanitizeInput($error) ?></div>
                    <?php endif; ?>

                    <?php if ($success): ?>
                        <div class="alert alert-success"><?= $success ?></div>
                    <?php else: ?>
                        <form method="POST" action="" id="resetRequestForm">
                            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                            <input type="hidden" name="action" value="request_reset">

                            <div class="form-group">
                                <label for="email">Email manzil:</label>
                                <input
                                    type="email"
                                    id="email"
                                    name="email"
                                    class="form-control"
                                    required
                                    value="<?= SecurityConfig::sanitizeInput($_POST['email'] ?? '') ?>"
                                    placeholder="your@email.com"
                                    autocomplete="email"
                                >
                                <small style="color: #666;">Parol tiklash havolasi yuboriladi</small>
                            </div>

                            <button type="submit" class="btn btn-primary" style="width: 100%;">
                                Parol tiklash havolasini yuborish
                            </button>
                        </form>
                    <?php endif; ?>

                <?php elseif ($step === 'reset'): ?>
                    <h2 style="text-align: center; color: #764ba2; margin-bottom: 2rem;">Yangi Parol O'rnatish</h2>

                    <?php if ($error): ?>
                        <div class="alert alert-error"><?= SecurityConfig::sanitizeInput($error) ?></div>
                    <?php endif; ?>

                    <?php if ($success): ?>
                        <div class="alert alert-success">
                            <?= SecurityConfig::sanitizeInput($success) ?>
                            <br><small>3 soniyadan keyin login sahifasiga yo'naltirilasiz...</small>
                        </div>
                    <?php else: ?>
                        <?php if (isset($tokenUser)): ?>
                            <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
                                <p><strong>Foydalanuvchi:</strong> <?= SecurityConfig::sanitizeInput($tokenUser['username']) ?></p>
                                <p><strong>Email:</strong> <?= SecurityConfig::sanitizeInput($tokenUser['email']) ?></p>
                            </div>
                        <?php endif; ?>

                        <form method="POST" action="" id="resetPasswordForm">
                            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                            <input type="hidden" name="action" value="reset_password">
                            <input type="hidden" name="reset_token" value="<?= SecurityConfig::sanitizeInput($token) ?>">

                            <div class="form-group">
                                <label for="new_password">Yangi parol:</label>
                                <input
                                    type="password"
                                    id="new_password"
                                    name="new_password"
                                    class="form-control"
                                    required
                                    autocomplete="new-password"
                                >
                                <div id="password-strength" style="margin-top: 0.5rem; font-size: 0.875rem;"></div>
                                <small style="color: #666;">Kamida 8 ta belgi, katta va kichik harf, raqam</small>
                            </div>

                            <div class="form-group">
                                <label for="confirm_password">Parolni tasdiqlang:</label>
                                <input
                                    type="password"
                                    id="confirm_password"
                                    name="confirm_password"
                                    class="form-control"
                                    required
                                    autocomplete="new-password"
                                >
                            </div>

                            <button type="submit" class="btn btn-primary" style="width: 100%;">
                                Parolni yangilash
                            </button>
                        </form>
                    <?php endif; ?>
                <?php endif; ?>

                <div style="text-align: center; margin-top: 2rem;">
                    <p><a href="login.php" style="color: #667eea;">Kirish sahifasiga qaytish</a></p>
                </div>

                <!-- Xavfsizlik ma'lumotlari -->
                <div style="background: #e8f4fd; border: 1px solid #bee5eb; border-radius: 8px; padding: 1rem; margin-top: 2rem; font-size: 0.875rem;">
                    <h4 style="color: #0c5460; margin-bottom: 0.5rem;">🔒 Xavfsizlik eslatmasi:</h4>
                    <ul style="color: #0c5460; margin: 0;">
                        <li>Parol tiklash havolasi faqat 1 soat amal qiladi</li>
                        <li>Har bir havola faqat bir marta ishlatilishi mumkin</li>
                        <li>Shubhali faoliyat bo'lsa, darhol admin ga xabar bering</li>
                    </ul>
                </div>
            </div>
        </div>
    </main>

    <script src="../assets/js/security.js"></script>
    <script>
        // Form validation
        document.getElementById('resetPasswordForm')?.addEventListener('submit', function(e) {
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;

            if (newPassword !== confirmPassword) {
                e.preventDefault();
                alert('Parollar mos kelmaydi!');
                return false;
            }

            if (newPassword.length < 8) {
                e.preventDefault();
                alert('Parol kamida 8 ta belgidan iborat bo\'lishi kerak!');
                return false;
            }
        });

        // Real-time password confirmation check
        document.getElementById('confirm_password')?.addEventListener('input', function() {
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = this.value;

            if (confirmPassword && newPassword !== confirmPassword) {
                this.style.borderColor = '#e74c3c';
            } else {
                this.style.borderColor = '#ddd';
            }
        });
    </script>
    </body>
    </html>

<?php
// Password reset tokens jadvali yaratish uchun SQL (setup.sql ga qo'shish kerak)
/*
CREATE TABLE password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
*/
?>