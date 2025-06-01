<?php
/**
 * Admin Dashboard - Boshqaruv paneli
 * Web Security Project
 */

require_once '../config/database.php';
require_once '../config/security.php';
require_once '../security/security_logger.php';
require_once '../security/rate_limiter.php';

// Admin huquqini tekshirish
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: ../auth/login.php');
    exit;
}

try {
    $db = getDB();

    // Statistikalarni olish

    // Foydalanuvchilar soni
    $stmt = $db->query("SELECT COUNT(*) as total, SUM(is_active) as active FROM users");
    $userStats = $stmt->fetch();

    // Oxirgi 24 soatdagi xavfsizlik hodisalari
    $securityStats = SecurityLogger::getStatistics(24);

    // Oxirgi faol foydalanuvchilar
    $stmt = $db->query("
        SELECT username, full_name, last_login 
        FROM users 
        WHERE is_active = 1 
        ORDER BY last_login DESC 
        LIMIT 10
    ");
    $recentUsers = $stmt->fetchAll();

    // Shubhali IP lar
    $suspiciousIPs = SecurityLogger::getSuspiciousIPs(24, 5);

    // Rate limit bloklari
    $rateLimiter = new RateLimiter();
    $activeBlocks = $rateLimiter->getActiveBlocks();

    // Oxirgi xavfsizlik hodisalari
    $recentEvents = SecurityLogger::getRecentEvents(60, ['medium', 'high']);

} catch (Exception $e) {
    error_log("Admin dashboard error: " . $e->getMessage());
    $error = "Ma'lumotlarni yuklashda xatolik yuz berdi.";
}
?>

<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Web Security</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <style>
        .dashboard {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem 20px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }

        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
        }

        .stat-card.danger {
            border-left: 5px solid #e74c3c;
        }

        .stat-card.warning {
            border-left: 5px solid #f39c12;
        }

        .stat-card.success {
            border-left: 5px solid #27ae60;
        }

        .stat-card.info {
            border-left: 5px solid #3498db;
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            color: #333;
        }

        .stat-label {
            color: #666;
            margin-top: 0.5rem;
        }

        .admin-section {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin: 2rem 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .admin-section h3 {
            color: #333;
            margin-bottom: 1rem;
            border-bottom: 2px solid #f1f1f1;
            padding-bottom: 0.5rem;
        }

        .log-item {
            padding: 0.75rem;
            border-left: 3px solid #ddd;
            margin: 0.5rem 0;
            background: #f8f9fa;
            border-radius: 0 8px 8px 0;
        }

        .log-item.high {
            border-left-color: #e74c3c;
            background: #ffeaea;
        }

        .log-item.medium {
            border-left-color: #f39c12;
            background: #fff8e1;
        }

        .log-item.low {
            border-left-color: #27ae60;
            background: #f1f8e9;
        }

        .quick-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }

        .action-btn {
            display: block;
            text-decoration: none;
            padding: 1rem;
            background: #667eea;
            color: white;
            border-radius: 8px;
            text-align: center;
            transition: background 0.3s ease;
        }

        .action-btn:hover {
            background: #5a6fd8;
            color: white;
        }

        .action-btn.danger {
            background: #e74c3c;
        }

        .action-btn.danger:hover {
            background: #c0392b;
        }
    </style>
</head>
<body>
<nav class="navbar">
    <div class="nav-container">
        <div class="nav-brand">
            <h2><a href="../index.php" style="text-decoration: none; color: inherit;">🛡️ Web Security - Admin</a></h2>
        </div>
        <div class="nav-menu">
            <a href="../index.php" class="nav-link">Bosh sahifa</a>
            <a href="users.php" class="nav-link">Foydalanuvchilar</a>
            <a href="logs.php" class="nav-link">Loglar</a>
            <a href="../user/profile.php" class="nav-link">Profil</a>
            <a href="../auth/logout.php" class="nav-link logout">Chiqish</a>
        </div>
    </div>
</nav>

<main class="main-content">
    <div class="dashboard">
        <h1 style="color: white; text-align: center; margin-bottom: 2rem;">
            🛡️ Admin Dashboard
        </h1>

        <?php if (isset($error)): ?>
            <div class="alert alert-error"><?= SecurityConfig::sanitizeInput($error) ?></div>
        <?php endif; ?>

        <!-- Statistikalar -->
        <div class="stats-grid">
            <div class="stat-card info">
                <div class="stat-number"><?= $userStats['total'] ?? 0 ?></div>
                <div class="stat-label">Jami foydalanuvchilar</div>
            </div>

            <div class="stat-card success">
                <div class="stat-number"><?= $userStats['active'] ?? 0 ?></div>
                <div class="stat-label">Faol foydalanuvchilar</div>
            </div>

            <div class="stat-card warning">
                <div class="stat-number"><?= count($suspiciousIPs) ?></div>
                <div class="stat-label">Shubhali IP lar</div>
            </div>

            <div class="stat-card danger">
                <div class="stat-number"><?= count($activeBlocks) ?></div>
                <div class="stat-label">Bloklangan IP lar</div>
            </div>
        </div>

        <!-- Tezkor harakatlar -->
        <div class="admin-section">
            <h3>⚡ Tezkor harakatlar</h3>
            <div class="quick-actions">
                <a href="users.php" class="action-btn">👥 Foydalanuvchilarni boshqarish</a>
                <a href="logs.php" class="action-btn">📊 Xavfsizlik loglari</a>
                <a href="logs.php?filter=high" class="action-btn danger">🚨 Yuqori xavfli hodisalar</a>
                <a href="#cleanup" class="action-btn" onclick="cleanupOldData()">🧹 Eski ma'lumotlarni tozalash</a>
            </div>
        </div>

        <!-- Oxirgi xavfsizlik hodisalari -->
        <div class="admin-section">
            <h3>🔍 Oxirgi xavfsizlik hodisalari (1 soat)</h3>
            <?php if (empty($recentEvents)): ?>
                <p style="color: #666;">Oxirgi soatda muhim hodisalar qayd etilmadi.</p>
            <?php else: ?>
                <?php foreach ($recentEvents as $event): ?>
                    <div class="log-item <?= $event['risk_level'] ?>">
                        <strong><?= SecurityConfig::sanitizeInput($event['action_type']) ?></strong>
                        <?php if ($event['username']): ?>
                            by <?= SecurityConfig::sanitizeInput($event['username']) ?>
                        <?php endif; ?>
                        <span style="float: right; color: #666;">
                                <?= SecurityConfig::sanitizeInput($event['ip_address']) ?> -
                                <?= date('H:i:s', strtotime($event['timestamp'])) ?>
                            </span>
                        <br>
                        <small><?= SecurityConfig::sanitizeInput($event['details']) ?></small>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>

            <?php if (count($recentEvents) >= 10): ?>
                <div style="text-align: center; margin-top: 1rem;">
                    <a href="logs.php" class="btn btn-primary">Barcha loglarni ko'rish</a>
                </div>
            <?php endif; ?>
        </div>

        <!-- Shubhali IP lar -->
        <?php if (!empty($suspiciousIPs)): ?>
            <div class="admin-section">
                <h3>⚠️ Shubhali IP manzillar (24 soat)</h3>
                <div class="table-container">
                    <table class="table">
                        <thead>
                        <tr>
                            <th>IP Manzil</th>
                            <th>Jami hodisalar</th>
                            <th>Yuqori xavfli</th>
                            <th>O'rta xavfli</th>
                            <th>Oxirgi faollik</th>
                            <th>Harakat</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($suspiciousIPs as $ip): ?>
                            <tr>
                                <td><?= SecurityConfig::sanitizeInput($ip['ip_address']) ?></td>
                                <td><span class="badge badge-info"><?= $ip['total_events'] ?></span></td>
                                <td>
                                    <?php if ($ip['high_risk_events'] > 0): ?>
                                        <span class="badge badge-danger"><?= $ip['high_risk_events'] ?></span>
                                    <?php else: ?>
                                        0
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($ip['medium_risk_events'] > 0): ?>
                                        <span class="badge badge-warning"><?= $ip['medium_risk_events'] ?></span>
                                    <?php else: ?>
                                        0
                                    <?php endif; ?>
                                </td>
                                <td><?= date('H:i', strtotime($ip['last_event'])) ?></td>
                                <td>
                                    <button onclick="blockIP('<?= $ip['ip_address'] ?>')" class="btn btn-danger" style="font-size: 0.8rem; padding: 0.25rem 0.5rem;">
                                        Bloklash
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>

        <!-- Faol bloklar -->
        <?php if (!empty($activeBlocks)): ?>
            <div class="admin-section">
                <h3>🚫 Faol bloklar</h3>
                <div class="table-container">
                    <table class="table">
                        <thead>
                        <tr>
                            <th>IP Manzil</th>
                            <th>Sabab</th>
                            <th>Urinishlar</th>
                            <th>Blok tugash vaqti</th>
                            <th>Harakat</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($activeBlocks as $block): ?>
                            <tr>
                                <td><?= SecurityConfig::sanitizeInput($block['ip_address']) ?></td>
                                <td><?= SecurityConfig::sanitizeInput($block['action_type']) ?></td>
                                <td><span class="badge badge-danger"><?= $block['attempts'] ?></span></td>
                                <td><?= date('d.m.Y H:i', strtotime($block['blocked_until'])) ?></td>
                                <td>
                                    <button onclick="unblockIP('<?= $block['ip_address'] ?>', '<?= $block['action_type'] ?>')"
                                            class="btn btn-secondary" style="font-size: 0.8rem; padding: 0.25rem 0.5rem;">
                                        Blokni olib tashlash
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>

        <!-- Oxirgi faol foydalanuvchilar -->
        <div class="admin-section">
            <h3>👥 Oxirgi faol foydalanuvchilar</h3>
            <div class="table-container">
                <table class="table">
                    <thead>
                    <tr>
                        <th>Foydalanuvchi nomi</th>
                        <th>To'liq ism</th>
                        <th>Oxirgi kirish</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($recentUsers as $user): ?>
                        <tr>
                            <td><?= SecurityConfig::sanitizeInput($user['username']) ?></td>
                            <td><?= SecurityConfig::sanitizeInput($user['full_name']) ?></td>
                            <td>
                                <?php if ($user['last_login']): ?>
                                    <?= date('d.m.Y H:i', strtotime($user['last_login'])) ?>
                                <?php else: ?>
                                    <span style="color: #666;">Hech qachon</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</main>

<script>
    // IP ni bloklash
    function blockIP(ip) {
        if (confirm(`${ip} manzilini bloklashni xohlaysizmi?`)) {
            // Bu yerda AJAX so'rovi yuborish mumkin
            alert(`${ip} bloklandi (demo)`);
            location.reload();
        }
    }

    // IP blokini olib tashlash
    function unblockIP(ip, actionType) {
        if (confirm(`${ip} manzili uchun ${actionType} blokini olib tashlashni xohlaysizmi?`)) {
            // Bu yerda AJAX so'rovi yuborish mumkin
            alert(`${ip} bloki olib tashlandi (demo)`);
            location.reload();
        }
    }

    // Eski ma'lumotlarni tozalash
    function cleanupOldData() {
        if (confirm('90 kundan eski loglarni tozalashni xohlaysizmi?')) {
            // Bu yerda AJAX so'rovi yuborish mumkin
            alert('Eski ma\'lumotlar tozalandi (demo)');
            location.reload();
        }
    }

    // Auto-refresh (har 30 soniyada)
    setInterval(function() {
        // Faqat oxirgi hodisalar bo'limini yangilash
        // location.reload();
    }, 30000);
</script>
</body>
</html>