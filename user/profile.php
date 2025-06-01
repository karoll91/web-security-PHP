<?php
/**
 * Foydalanuvchi profili sahifasi
 * Web Security Project
 */

require_once '../config/database.php';
require_once '../config/security.php';
require_once '../security/csrf_token.php';
require_once '../security/security_logger.php';

// Login tekshirish
if (!isset($_SESSION['user_id'])) {
    header('Location: ../auth/login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
}

$error = '';
$success = '';

// CSRF token
$csrfToken = CSRFToken::generate();

// Foydalanuvchi ma'lumotlarini olish
try {
    $db = getDB();
    $stmt = $db->prepare("
        SELECT username, email, full_name, created_at, last_login, role 
        FROM users 
        WHERE id = ?
    ");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();

    if (!$user) {
        session_destroy();
        header('Location: ../auth/login.php');
        exit;
    }

    // Foydalanuvchi faoliyat tarixini olish
    $activityLogs = SecurityLogger::getUserActivity($_SESSION['user_id'], 20);

} catch (PDOException $e) {
    error_log("Profile fetch error: " . $e->getMessage());
    $error = 'Ma\'lumotlarni yuklashda xatolik yuz berdi.';
    $user = null;
    $activityLogs = [];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF tekshirish
    if (!CSRFToken::verify($_POST['csrf_token'] ?? '')) {
        $error = 'Xavfsizlik xatosi! Sahifani qaytadan yuklang.';
        SecurityLogger::log('csrf_token_invalid', $_SESSION['user_id'], null, 'high', 'Invalid CSRF token on profile update');
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'update_profile') {
            // Profil ma'lumotlarini yangilash
            $fullName = SecurityConfig::sanitizeInput($_POST['full_name'] ?? '');
            $email = SecurityConfig::sanitizeInput($_POST['email'] ?? '');

            if (empty($fullName) || empty($email)) {
                $error = 'Barcha maydonlarni to\'ldiring!';
            } elseif (!SecurityConfig::validateInput($email, 'email')) {
                $error = 'Email manzil noto\'g\'ri!';
            } else {
                try {
                    // Email mavjudligini tekshirish (boshqa foydalanuvchilarda)
                    $stmt = $db->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                    $stmt->execute([$email, $_SESSION['user_id']]);
                    $existingUser = $stmt->fetch();

                    if ($existingUser) {
                        $error = 'Bu email manzil boshqa foydalanuvchi tomonidan ishlatilmoqda!';
                    } else {
                        // Ma'lumotlarni yangilash
                        $stmt = $db->prepare("
                            UPDATE users 
                            SET full_name = ?, email = ? 
                            WHERE id = ?
                        ");
                        $stmt->execute([$fullName, $email, $_SESSION['user_id']]);

                        $success = 'Profil ma\'lumotlari muvaffaqiyatli yangilandi!';

                        // User ma'lumotlarini yangilash
                        $user['full_name'] = $fullName;
                        $user['email'] = $email;

                        SecurityLogger::log('profile_updated', $_SESSION['user_id'], null, 'low',
                            "Profile updated: {$fullName}, {$email}");
                    }

                } catch (PDOException $e) {
                    error_log("Profile update error: " . $e->getMessage());
                    $error = 'Ma\'lumotlarni yangilashda xatolik yuz berdi.';
                }
            }
        }

        if ($action === 'change_password') {
            // Parolni o'zgartirish
            $currentPassword = $_POST['current_password'] ?? '';
            $newPassword = $_POST['new_password'] ?? '';
            $confirmPassword = $_POST['confirm_password'] ?? '';

            if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
                $error = 'Barcha parol maydonlarini to\'ldiring!';
            } elseif ($newPassword !== $confirmPassword) {
                $error = 'Yangi parollar mos kelmaydi!';
            } elseif (!SecurityConfig::isStrongPassword($newPassword)) {
                $error = 'Yangi parol kamida 8 ta belgi, katta va kichik harf, raqam bo\'lishi kerak!';
            } else {
                try {
                    // Joriy parolni tekshirish
                    $stmt = $db->prepare("SELECT password_hash FROM users WHERE id = ?");
                    $stmt->execute([$_SESSION['user_id']]);
                    $userPassword = $stmt->fetch();

                    if (!password_verify($currentPassword, $userPassword['password_hash'])) {
                        $error = 'Joriy parol noto\'g\'ri!';
                        SecurityLogger::log('password_change_failed', $_SESSION['user_id'], null, 'medium',
                            'Failed password change attempt - wrong current password');
                    } else {
                        // Yangi parolni o'rnatish
                        $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);

                        $stmt = $db->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
                        $stmt->execute([$newPasswordHash, $_SESSION['user_id']]);

                        $success = 'Parol muvaffaqiyatli o\'zgartirildi!';

                        SecurityLogger::log('password_changed', $_SESSION['user_id'], null, 'low',
                            'Password successfully changed');
                    }

                } catch (PDOException $e) {
                    error_log("Password change error: " . $e->getMessage());
                    $error = 'Parolni o\'zgartirishda xatolik yuz berdi.';
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
    <title>Profil - Web Security</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <style>
        .profile-container {
            max-width: 1000px;
            margin: 2rem auto;
            padding: 0 20px;
        }

        .profile-section {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin: 2rem 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .profile-header {
            text-align: center;
            padding: 2rem 0;
            border-bottom: 2px solid #f1f1f1;
            margin-bottom: 2rem;
        }

        .profile-avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1rem auto;
            font-size: 2.5rem;
            color: white;
        }

        .profile-tabs {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            border-bottom: 2px solid #f1f1f1;
        }

        .tab-button {
            padding: 0.75rem 1.5rem;
            border: none;
            background: none;
            border-bottom: 3px solid transparent;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
        }

        .tab-button.active {
            border-bottom-color: #667eea;
            color: #667eea;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin: 2rem 0;
        }

        .info-item {
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 8px;
        }

        .info-label {
            font-weight: bold;
            color: #666;
            margin-bottom: 0.5rem;
        }

        .info-value {
            color: #333;
        }

        .activity-item {
            padding: 1rem;
            border-left: 3px solid #ddd;
            margin: 0.5rem 0;
            background: #f8f9fa;
            border-radius: 0 8px 8px 0;
        }

        .activity-item.high {
            border-left-color: #e74c3c;
            background: #ffeaea;
        }

        .activity-item.medium {
            border-left-color: #f39c12;
            background: #fff8e1;
        }

        .activity-item.low {
            border-left-color: #27ae60;
            background: #f1f8e9;
        }

        .activity-meta {
            font-size: 0.875rem;
            color: #666;
            margin-top: 0.5rem;
        }

        @media (max-width: 768px) {
            .info-grid {
                grid-template-columns: 1fr;
            }

            .profile-tabs {
                flex-wrap: wrap;
            }
        }
    </style>
</head>
<body>
<nav class="navbar">
    <div class="nav-container">
        <div class="nav-brand">
            <h2><a href="../index.php" style="text-decoration: none; color: inherit;">🛡️ Web Security</a></h2>
        </div>
        <div class="nav-menu">
            <a href="../index.php" class="nav-link">Bosh sahifa</a>
            <?php if ($_SESSION['role'] === 'admin'): ?>
                <a href="../admin/dashboard.php" class="nav-link">Admin Panel</a>
            <?php endif; ?>
            <a href="../auth/logout.php" class="nav-link logout">Chiqish</a>
        </div>
    </div>
</nav>

<main class="main-content">
    <div class="profile-container">
        <?php if ($user): ?>
            <div class="profile-section">
                <div class="profile-header">
                    <div class="profile-avatar">
                        <?= strtoupper(substr($user['full_name'], 0, 1)) ?>
                    </div>
                    <h2><?= SecurityConfig::sanitizeInput($user['full_name']) ?></h2>
                    <p style="color: #666;">@<?= SecurityConfig::sanitizeInput($user['username']) ?></p>
                    <span class="badge badge-info"><?= ucfirst($user['role']) ?></span>
                </div>

                <?php if ($error): ?>
                    <div class="alert alert-error"><?= SecurityConfig::sanitizeInput($error) ?></div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <div class="alert alert-success"><?= SecurityConfig::sanitizeInput($success) ?></div>
                <?php endif; ?>

                <!-- Tabs -->
                <div class="profile-tabs">
                    <button class="tab-button active" onclick="showTab('info')">Ma'lumotlar</button>
                    <button class="tab-button" onclick="showTab('edit')">Tahrirlash</button>
                    <button class="tab-button" onclick="showTab('password')">Parol</button>
                    <button class="tab-button" onclick="showTab('activity')">Faollik tarixi</button>
                </div>
            </div>

            <!-- Ma'lumotlar tab -->
            <div id="info" class="tab-content active">
                <div class="profile-section">
                    <h3>📋 Profil ma'lumotlari</h3>
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-label">To'liq ism</div>
                            <div class="info-value"><?= SecurityConfig::sanitizeInput($user['full_name']) ?></div>
                        </div>

                        <div class="info-item">
                            <div class="info-label">Foydalanuvchi nomi</div>
                            <div class="info-value"><?= SecurityConfig::sanitizeInput($user['username']) ?></div>
                        </div>

                        <div class="info-item">
                            <div class="info-label">Email manzil</div>
                            <div class="info-value"><?= SecurityConfig::sanitizeInput($user['email']) ?></div>
                        </div>

                        <div class="info-item">
                            <div class="info-label">Rol</div>
                            <div class="info-value"><?= ucfirst($user['role']) ?></div>
                        </div>

                        <div class="info-item">
                            <div class="info-label">Ro'yxatdan o'tgan sana</div>
                            <div class="info-value"><?= date('d.m.Y H:i', strtotime($user['created_at'])) ?></div>
                        </div>

                        <div class="info-item">
                            <div class="info-label">Oxirgi kirish</div>
                            <div class="info-value">
                                <?php if ($user['last_login']): ?>
                                    <?= date('d.m.Y H:i', strtotime($user['last_login'])) ?>
                                <?php else: ?>
                                    Hech qachon
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tahrirlash tab -->
            <div id="edit" class="tab-content">
                <div class="profile-section">
                    <h3>✏️ Profil ma'lumotlarini tahrirlash</h3>

                    <form method="POST" action="">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <input type="hidden" name="action" value="update_profile">

                        <div class="form-group">
                            <label for="full_name">To'liq ism:</label>
                            <input
                                type="text"
                                id="full_name"
                                name="full_name"
                                class="form-control"
                                required
                                value="<?= SecurityConfig::sanitizeInput($user['full_name']) ?>"
                            >
                        </div>

                        <div class="form-group">
                            <label for="email">Email manzil:</label>
                            <input
                                type="email"
                                id="email"
                                name="email"
                                class="form-control"
                                required
                                value="<?= SecurityConfig::sanitizeInput($user['email']) ?>"
                            >
                        </div>

                        <div class="form-group">
                            <label>Foydalanuvchi nomi:</label>
                            <input
                                type="text"
                                class="form-control"
                                value="<?= SecurityConfig::sanitizeInput($user['username']) ?>"
                                disabled
                            >
                            <small style="color: #666;">Foydalanuvchi nomini o'zgartirib bo'lmaydi</small>
                        </div>

                        <button type="submit" class="btn btn-primary">Ma'lumotlarni saqlash</button>
                    </form>
                </div>
            </div>

            <!-- Parol tab -->
            <div id="password" class="tab-content">
                <div class="profile-section">
                    <h3>🔒 Parolni o'zgartirish</h3>

                    <form method="POST" action="" id="passwordForm">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <input type="hidden" name="action" value="change_password">

                        <div class="form-group">
                            <label for="current_password">Joriy parol:</label>
                            <input
                                type="password"
                                id="current_password"
                                name="current_password"
                                class="form-control"
                                required
                                autocomplete="current-password"
                            >
                        </div>

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
                            <label for="confirm_password">Yangi parolni tasdiqlang:</label>
                            <input
                                type="password"
                                id="confirm_password"
                                name="confirm_password"
                                class="form-control"
                                required
                                autocomplete="new-password"
                            >
                        </div>

                        <button type="submit" class="btn btn-primary">Parolni o'zgartirish</button>
                    </form>
                </div>
            </div>

            <!-- Faollik tarixi tab -->
            <div id="activity" class="tab-content">
                <div class="profile-section">
                    <h3>📊 Faollik tarixi</h3>

                    <?php if (empty($activityLogs)): ?>
                        <p style="color: #666;">Faollik tarixi mavjud emas.</p>
                    <?php else: ?>
                        <?php foreach ($activityLogs as $log): ?>
                            <div class="activity-item <?= $log['risk_level'] ?>">
                                <strong><?= SecurityConfig::sanitizeInput($log['action_type']) ?></strong>
                                <div class="activity-meta">
                                    <?= SecurityConfig::sanitizeInput($log['ip_address']) ?> -
                                    <?= date('d.m.Y H:i:s', strtotime($log['timestamp'])) ?>
                                    <?php if ($log['details']): ?>
                                        <br><small><?= SecurityConfig::sanitizeInput($log['details']) ?></small>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>

        <?php else: ?>
            <div class="profile-section">
                <div class="alert alert-error">Foydalanuvchi ma'lumotlari yuklanmadi.</div>
            </div>
        <?php endif; ?>
    </div>
</main>

<script src="../assets/js/security.js"></script>
<script>
    // Tab switching
    function showTab(tabName) {
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });

        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });

        document.getElementById(tabName).classList.add('active');
        event.target.classList.add('active');
    }

    // Password form validation
    document.getElementById('passwordForm')?.addEventListener('submit', function(e) {
        const newPassword = document.getElementById('new_password').value;
        const confirmPassword = document.getElementById('confirm_password').value;

        if (newPassword !== confirmPassword) {
            e.preventDefault();
            alert('Yangi parollar mos kelmaydi!');
            return false;
        }

        if (newPassword.length < 8) {
            e.preventDefault();
            alert('Yangi parol kamida 8 ta belgidan iborat bo\'lishi kerak!');
            return false;
        }
    });

    // Real-time password confirmation
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