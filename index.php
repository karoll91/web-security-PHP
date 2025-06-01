<?php
/**
 * Bosh sahifa - Web Security Project
 */

require_once 'config/database.php';
require_once 'config/security.php';

// Foydalanuvchi login qilganmi tekshirish
$isLoggedIn = isset($_SESSION['user_id']);
$user = null;

if ($isLoggedIn) {
    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT username, full_name, role FROM users WHERE id = ? AND is_active = 1");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch();

        if (!$user) {
            // Foydalanuvchi topilmasa yoki faol emas
            session_destroy();
            $isLoggedIn = false;
        }
    } catch (PDOException $e) {
        error_log("User fetch error: " . $e->getMessage());
        $isLoggedIn = false;
    }
}
?>

<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Xavfsizlik Loyihasi</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
</head>
<body>
<nav class="navbar">
    <div class="nav-container">
        <div class="nav-brand">
            <h2>🛡️ Web Security</h2>
        </div>
        <div class="nav-menu">
            <?php if ($isLoggedIn): ?>
                <span class="welcome-user">Salom, <?= SecurityConfig::sanitizeInput($user['full_name']) ?>!</span>

                <?php if ($user['role'] === 'admin'): ?>
                    <a href="admin/dashboard.php" class="nav-link">Admin Panel</a>
                <?php endif; ?>

                <a href="user/profile.php" class="nav-link">Profil</a>
                <a href="auth/logout.php" class="nav-link logout">Chiqish</a>
            <?php else: ?>
                <a href="auth/login.php" class="nav-link">Kirish</a>
                <a href="auth/register.php" class="nav-link">Ro'yxatdan o'tish</a>
            <?php endif; ?>
        </div>
    </div>
</nav>

<main class="main-content">
    <div class="container">
        <section class="hero">
            <h1>Web Saytlar Xavfsizligini Ta'minlash</h1>
            <p class="hero-subtitle">Bitiruv malakaviy ishi - Axborot xavfsizligi mexanizmlari</p>
        </section>

        <?php if (!$isLoggedIn): ?>
            <section class="auth-section">
                <div class="auth-cards">
                    <div class="auth-card">
                        <h3>Kirish</h3>
                        <p>Mavjud akkauntingiz bilan kiring</p>
                        <a href="auth/login.php" class="btn btn-primary">Kirish</a>
                    </div>
                    <div class="auth-card">
                        <h3>Ro'yxatdan o'tish</h3>
                        <p>Yangi akkaunt yarating</p>
                        <a href="auth/register.php" class="btn btn-secondary">Ro'yxatdan o'tish</a>
                    </div>
                </div>
            </section>
        <?php endif; ?>

        <section class="features">
            <h2>Loyiha Xususiyatlari</h2>
            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">🔐</div>
                    <h3>Xavfsiz Autentifikatsiya</h3>
                    <p>Kuchli parol talabi, session xavfsizligi va brute force himoyasi</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">🛡️</div>
                    <h3>SQL Injection Himoyasi</h3>
                    <p>Prepared statements va ma'lumot validatsiyasi orqali himoya</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">🚫</div>
                    <h3>XSS Himoyasi</h3>
                    <p>Input sanitization va Content Security Policy</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">🔒</div>
                    <h3>CSRF Himoyasi</h3>
                    <p>Token-based himoya mexanizmi</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">📊</div>
                    <h3>Xavfsizlik Monitoring</h3>
                    <p>Real-time monitoring va log tizimi</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <h3>Rate Limiting</h3>
                    <p>So'rovlar cheklash va DDoS himoyasi</p>
                </div>
            </div>
        </section>

        <?php if ($isLoggedIn): ?>
            <section class="user-dashboard">
                <h2>Tizim Ma'lumotlari</h2>
                <div class="dashboard-cards">
                    <div class="dashboard-card">
                        <h4>Akkaunt holati</h4>
                        <p><strong>Foydalanuvchi:</strong> <?= SecurityConfig::sanitizeInput($user['username']) ?></p>
                        <p><strong>Rol:</strong> <?= ucfirst($user['role']) ?></p>
                        <p><strong>Oxirgi kirish:</strong> Hozir</p>
                    </div>

                    <div class="dashboard-card">
                        <h4>Xavfsizlik holati</h4>
                        <p>✅ HTTPS faol</p>
                        <p>✅ Session xavfsiz</p>
                        <p>✅ CSRF himoyasi</p>
                    </div>
                </div>
            </section>
        <?php endif; ?>

        <section class="demo-section">
            <h2>⚠️ Xavfsizlik Namunalari (Faqat test uchun!)</h2>
            <div class="demo-warning">
                <p><strong>Ogohlantirish:</strong> Quyidagi havolalar zaif kodlar namunasi bo'lib, faqat ta'lim maqsadida yaratilgan!</p>
            </div>
            <div class="demo-links">
                <a href="vulnerable/sql_injection.php" class="demo-link danger">SQL Injection Demo</a>
                <a href="vulnerable/xss_demo.php" class="demo-link danger">XSS Demo</a>
                <a href="vulnerable/csrf_demo.php" class="demo-link danger">CSRF Demo</a>
            </div>
        </section>
    </div>
</main>

<footer class="footer">
    <div class="container">
        <p>&copy; 2025 Web Security Project - Bitiruv malakaviy ishi</p>
    </div>
</footer>

<script src="assets/js/security.js"></script>
</body>
</html>