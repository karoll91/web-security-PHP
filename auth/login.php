<?php
/**
 * Kirish sahifasi - Login
 * Web Security Project
 */

require_once '../config/database.php';
require_once '../config/security.php';
require_once '../security/rate_limiter.php';
require_once '../security/security_logger.php';

// Agar foydalanuvchi allaqachon login qilgan bo'lsa
if (isset($_SESSION['user_id'])) {
    header('Location: ../index.php');
    exit;
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = SecurityConfig::sanitizeInput($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember']);

    // Rate limiting tekshirish
    $clientIP = SecurityConfig::getClientIP();
    $rateLimiter = new RateLimiter();

    if ($rateLimiter->isBlocked($clientIP, 'login')) {
        $error = 'Juda ko\'p urinish! Iltimos 15 daqiqadan keyin qaytadan urinib ko\'ring.';
        SecurityLogger::log('login_blocked', null, $clientIP, 'high', 'Rate limit exceeded for login attempts');
    } else {
        // Ma'lumotlarni tekshirish
        if (empty($username) || empty($password)) {
            $error = 'Barcha maydonlarni to\'ldiring!';
        } else {
            try {
                $db = getDB();

                // Foydalanuvchini topish
                $stmt = $db->prepare("
                    SELECT id, username, password_hash, full_name, role, is_active, 
                           failed_login_attempts, locked_until 
                    FROM users 
                    WHERE (username = ? OR email = ?)
                ");
                $stmt->execute([$username, $username]);
                $user = $stmt->fetch();

                if ($user) {
                    // Akkaunt bloklangan mi?
                    if ($user['locked_until'] && new DateTime() < new DateTime($user['locked_until'])) {
                        $error = 'Akkaunt vaqtincha bloklangan. Iltimos keyinroq urinib ko\'ring.';
                        SecurityLogger::log('login_attempt_locked', $user['id'], $clientIP, 'high', 'Login attempt on locked account');
                    }
                    // Akkaunt faol mi?
                    else if (!$user['is_active']) {
                        $error = 'Akkaunt faol emas!';
                        SecurityLogger::log('login_attempt_inactive', $user['id'], $clientIP, 'medium', 'Login attempt on inactive account');
                    }
                    // Parolni tekshirish
                    else if (password_verify($password, $user['password_hash'])) {
                        // Muvaffaqiyatli kirish

                        // Failed attempts ni tozalash
                        $stmt = $db->prepare("
                            UPDATE users 
                            SET failed_login_attempts = 0, locked_until = NULL, last_login = NOW() 
                            WHERE id = ?
                        ");
                        $stmt->execute([$user['id']]);

                        // Session yaratish
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['username'] = $user['username'];
                        $_SESSION['role'] = $user['role'];
                        $_SESSION['login_time'] = time();

                        // Remember me
                        if ($remember) {
                            $token = bin2hex(random_bytes(32));
                            // Database ga remember token saqlash mumkin
                            setcookie('remember_token', $token, time() + (30 * 24 * 3600), '/', '', false, true);
                        }

                        // Rate limiter ni tozalash
                        $rateLimiter->clearAttempts($clientIP, 'login');

                        // Log
                        SecurityLogger::log('login_success', $user['id'], $clientIP, 'low', 'Successful login');

                        // Redirect
                        $redirect = $_GET['redirect'] ?? '../index.php';
                        header('Location: ' . $redirect);
                        exit;

                    } else {
                        // Noto'g'ri parol
                        $failedAttempts = $user['failed_login_attempts'] + 1;

                        // Failed attempts ni yangilash
                        $lockUntil = null;
                        if ($failedAttempts >= MAX_LOGIN_ATTEMPTS) {
                            $lockUntil = date('Y-m-d H:i:s', time() + ACCOUNT_LOCK_TIME);
                            $error = 'Juda ko\'p noto\'g\'ri urinish! Akkaunt ' . (ACCOUNT_LOCK_TIME / 60) . ' daqiqaga bloklandi.';
                        } else {
                            $remainingAttempts = MAX_LOGIN_ATTEMPTS - $failedAttempts;
                            $error = 'Noto\'g\'ri parol! Qolgan urinishlar: ' . $remainingAttempts;
                        }

                        $stmt = $db->prepare("
                            UPDATE users 
                            SET failed_login_attempts = ?, locked_until = ? 
                            WHERE id = ?
                        ");
                        $stmt->execute([$failedAttempts, $lockUntil, $user['id']]);

                        // Rate limiter
                        $rateLimiter->recordAttempt($clientIP, 'login');

                        // Log
                        SecurityLogger::log('login_failed', $user['id'], $clientIP, 'medium',
                            "Failed login attempt #{$failedAttempts}");
                    }
                } else {
                    // Foydalanuvchi topilmadi
                    $error = 'Foydalanuvchi nomi yoki parol noto\'g\'ri!';
                    $rateLimiter->recordAttempt($clientIP, 'login');
                    SecurityLogger::log('login_failed', null, $clientIP, 'medium', 'Login attempt with non-existent user');
                }

            } catch (PDOException $e) {
                error_log("Login error: " . $e->getMessage());
                $error = 'Tizimda xatolik yuz berdi. Iltimos keyinroq urinib ko\'ring.';
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kirish - Web Security</title>
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
            <a href="register.php" class="nav-link">Ro'yxatdan o'tish</a>
        </div>
    </div>
</nav>

<main class="main-content">
    <div class="container">
        <div class="form-container">
            <h2 style="text-align: center; color: #764ba2; margin-bottom: 2rem;">Tizimga Kirish</h2>

            <?php if ($error): ?>
                <div class="alert alert-error"><?= SecurityConfig::sanitizeInput($error) ?></div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success"><?= SecurityConfig::sanitizeInput($success) ?></div>
            <?php endif; ?>

            <form method="POST" action="" id="loginForm">
                <div class="form-group">
                    <label for="username">Foydalanuvchi nomi yoki Email:</label>
                    <input
                        type="text"
                        id="username"
                        name="username"
                        class="form-control"
                        required
                        value="<?= SecurityConfig::sanitizeInput($_POST['username'] ?? '') ?>"
                        autocomplete="username"
                    >
                </div>

                <div class="form-group">
                    <label for="password">Parol:</label>
                    <input
                        type="password"
                        id="password"
                        name="password"
                        class="form-control"
                        required
                        autocomplete="current-password"
                    >
                </div>

                <div class="form-group" style="display: flex; align-items: center; gap: 0.5rem;">
                    <input type="checkbox" id="remember" name="remember">
                    <label for="remember" style="margin: 0;">Meni eslab qol</label>
                </div>

                <button type="submit" class="btn btn-primary" style="width: 100%;">Kirish</button>
            </form>

            <div style="text-align: center; margin-top: 2rem;">
                <p>Akkauntingiz yo'qmi? <a href="register.php" style="color: #667eea;">Ro'yxatdan o'ting</a></p>
                <p><a href="password_reset.php" style="color: #667eea;">Parolni unutdingizmi?</a></p>
            </div>

            <!-- Test ma'lumotlari -->
            <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; margin-top: 2rem; font-size: 0.875rem;">
                <strong>Test uchun:</strong><br>
                Admin: <code>admin</code> / <code>password</code><br>
                User: <code>testuser</code> / <code>password</code>
            </div>
        </div>
    </div>
</main>

<script src="../assets/js/security.js"></script>
<script>
    // Login form uchun qo'shimcha validatsiya
    document.getElementById('loginForm').addEventListener('submit', function(e) {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        if (!username || !password) {
            e.preventDefault();
            alert('Barcha maydonlarni to\'ldiring!');
            return false;
        }

        // Security check
        if (username.length < 3) {
            e.preventDefault();
            alert('Foydalanuvchi nomi juda qisqa!');
            return false;
        }
    });
</script>
</body>
</html>