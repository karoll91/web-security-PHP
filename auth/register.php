<?php
/**
 * Ro'yxatdan o'tish sahifasi - Register
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

$error = '';
$success = '';

// CSRF token yaratish
$csrfToken = CSRFToken::generate();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF token tekshirish
    if (!CSRFToken::verify($_POST['csrf_token'] ?? '')) {
        $error = 'Xavfsizlik xatosi! Sahifani qaytadan yuklang.';
        SecurityLogger::log('csrf_token_invalid', null, null, 'high', 'Invalid CSRF token on registration');
    } else {
        $username = SecurityConfig::sanitizeInput($_POST['username'] ?? '');
        $email = SecurityConfig::sanitizeInput($_POST['email'] ?? '');
        $fullName = SecurityConfig::sanitizeInput($_POST['full_name'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        // Rate limiting tekshirish
        $clientIP = SecurityConfig::getClientIP();
        $rateLimiter = new RateLimiter();

        if ($rateLimiter->isBlocked($clientIP, 'register')) {
            $error = 'Juda ko\'p urinish! Iltimos 1 soatdan keyin qaytadan urinib ko\'ring.';
            SecurityLogger::log('register_blocked', null, $clientIP, 'high', 'Rate limit exceeded for registration');
        } else {
            // Ma'lumotlarni tekshirish
            $validationErrors = [];

            if (empty($username) || empty($email) || empty($fullName) || empty($password)) {
                $validationErrors[] = 'Barcha maydonlarni to\'ldiring!';
            }

            if (!SecurityConfig::validateInput($username, 'username')) {
                $validationErrors[] = 'Foydalanuvchi nomi 3-20 ta belgi (harf, raqam, _) bo\'lishi kerak!';
            }

            if (!SecurityConfig::validateInput($email, 'email')) {
                $validationErrors[] = 'Email manzil noto\'g\'ri!';
            }

            if (!SecurityConfig::isStrongPassword($password)) {
                $validationErrors[] = 'Parol kamida 8 ta belgi, katta va kichik harf, raqam bo\'lishi kerak!';
            }

            if ($password !== $confirmPassword) {
                $validationErrors[] = 'Parollar mos kelmaydi!';
            }

            if (!empty($validationErrors)) {
                $error = implode(' ', $validationErrors);
            } else {
                try {
                    $db = getDB();

                    // Username va email mavjudligini tekshirish
                    $stmt = $db->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
                    $stmt->execute([$username, $email]);
                    $existingUser = $stmt->fetch();

                    if ($existingUser) {
                        $error = 'Bu foydalanuvchi nomi yoki email manzil allaqachon mavjud!';
                        $rateLimiter->recordAttempt($clientIP, 'register');
                        SecurityLogger::log('register_duplicate', null, $clientIP, 'medium',
                            "Duplicate registration attempt: {$username}, {$email}");
                    } else {
                        // Parolni hash qilish
                        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

                        // Yangi foydalanuvchi yaratish
                        $stmt = $db->prepare("
                            INSERT INTO users (username, email, password_hash, full_name, created_at, is_active) 
                            VALUES (?, ?, ?, ?, NOW(), 1)
                        ");
                        $stmt->execute([$username, $email, $passwordHash, $fullName]);

                        $userId = $db->lastInsertId();

                        // Muvaffaqiyatli ro'yxatdan o'tish
                        $success = 'Muvaffaqiyatli ro\'yxatdan o\'tdingiz! Endi tizimga kirishingiz mumkin.';

                        // Rate limiter ni tozalash
                        $rateLimiter->clearAttempts($clientIP, 'register');

                        // Log
                        SecurityLogger::log('register_success', $userId, $clientIP, 'low',
                            "New user registered: {$username}");

                        // 3 soniyadan keyin login sahifasiga yo'naltirish
                        header("refresh:3;url=login.php");
                    }

                } catch (PDOException $e) {
                    error_log("Registration error: " . $e->getMessage());
                    $error = 'Tizimda xatolik yuz berdi. Iltimos keyinroq urinib ko\'ring.';
                    SecurityLogger::log('register_error', null, $clientIP, 'high', 'Database error during registration');
                }
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
    <title>Ro'yxatdan o'tish - Web Security</title>
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
        </div>
    </div>
</nav>

<main class="main-content">
    <div class="container">
        <div class="form-container">
            <h2 style="text-align: center; color: #764ba2; margin-bottom: 2rem;">Ro'yxatdan O'tish</h2>

            <?php if ($error): ?>
                <div class="alert alert-error"><?= SecurityConfig::sanitizeInput($error) ?></div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success">
                    <?= SecurityConfig::sanitizeInput($success) ?>
                    <br><small>3 soniyadan keyin login sahifasiga yo'naltirilasiz...</small>
                </div>
            <?php endif; ?>

            <?php if (!$success): ?>
                <form method="POST" action="" id="registerForm">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                    <div class="form-group">
                        <label for="full_name">To'liq ism:</label>
                        <input
                            type="text"
                            id="full_name"
                            name="full_name"
                            class="form-control"
                            required
                            value="<?= SecurityConfig::sanitizeInput($_POST['full_name'] ?? '') ?>"
                            autocomplete="name"
                        >
                    </div>

                    <div class="form-group">
                        <label for="username">Foydalanuvchi nomi:</label>
                        <input
                            type="text"
                            id="username"
                            name="username"
                            class="form-control"
                            required
                            value="<?= SecurityConfig::sanitizeInput($_POST['username'] ?? '') ?>"
                            pattern="[a-zA-Z0-9_]{3,20}"
                            title="3-20 ta belgi: harf, raqam yoki _"
                            autocomplete="username"
                        >
                        <small style="color: #666;">3-20 ta belgi (harf, raqam, _)</small>
                    </div>

                    <div class="form-group">
                        <label for="email">Email manzil:</label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            class="form-control"
                            required
                            value="<?= SecurityConfig::sanitizeInput($_POST['email'] ?? '') ?>"
                            autocomplete="email"
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

                    <div class="form-group" style="display: flex; align-items: center; gap: 0.5rem;">
                        <input type="checkbox" id="terms" name="terms" required>
                        <label for="terms" style="margin: 0;">Foydalanish shartlarini qabul qilaman</label>
                    </div>

                    <button type="submit" class="btn btn-primary" style="width: 100%;" data-original-text="Ro'yxatdan o'tish">
                        Ro'yxatdan o'tish
                    </button>
                </form>
            <?php endif; ?>

            <div style="text-align: center; margin-top: 2rem;">
                <p>Akkauntingiz bormi? <a href="login.php" style="color: #667eea;">Kirish</a></p>
            </div>
        </div>
    </div>
</main>

<script src="../assets/js/security.js"></script>
<script>
    // Registration form uchun qo'shimcha validatsiya
    document.getElementById('registerForm').addEventListener('submit', function(e) {
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm_password').value;
        const terms = document.getElementById('terms').checked;

        // Parol mosligini tekshirish
        if (password !== confirmPassword) {
            e.preventDefault();
            alert('Parollar mos kelmaydi!');
            return false;
        }

        // Shartlarni qabul qilishni tekshirish
        if (!terms) {
            e.preventDefault();
            alert('Foydalanish shartlarini qabul qilishingiz kerak!');
            return false;
        }

        // Parol kuchliligini tekshirish
        if (password.length < 8) {
            e.preventDefault();
            alert('Parol kamida 8 ta belgidan iborat bo\'lishi kerak!');
            return false;
        }
    });

    // Real-time parol mosligini tekshirish
    document.getElementById('confirm_password').addEventListener('input', function() {
        const password = document.getElementById('password').value;
        const confirmPassword = this.value;

        if (confirmPassword && password !== confirmPassword) {
            this.style.borderColor = '#e74c3c';
        } else {
            this.style.borderColor = '#ddd';
        }
    });
</script>
</body>
</html>