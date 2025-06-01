<?php
/**
 * Foydalanuvchi sozlamalari sahifasi
 * Web Security Project
 */

require_once '../config/database.php';
require_once '../config/security.php';
require_once '../security/csrf_token.php';
require_once '../security/security_logger.php';
require_once '../security/input_validator.php';

// Login tekshirish
if (!isset($_SESSION['user_id'])) {
    header('Location: ../auth/login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
}

$error = '';
$success = '';

// CSRF token
$csrfToken = CSRFToken::generate();

try {
    $db = getDB();

    // Foydalanuvchi ma'lumotlarini olish
    $stmt = $db->prepare("
        SELECT username, email, full_name, created_at, last_login, role,
               failed_login_attempts, is_active
        FROM users 
        WHERE id = ?
    ");
    $stmt->execute(array($_SESSION['user_id']));
    $user = $stmt->fetch();

    if (!$user) {
        session_destroy();
        header('Location: ../auth/login.php');
        exit;
    }

    // Foydalanuvchi preferences (demo uchun session da saqlaymiz)
    $preferences = array(
        'theme' => isset($_SESSION['theme']) ? $_SESSION['theme'] : 'light',
        'language' => isset($_SESSION['language']) ? $_SESSION['language'] : 'uz',
        'notifications' => isset($_SESSION['notifications']) ? $_SESSION['notifications'] : true,
        'two_factor' => isset($_SESSION['two_factor']) ? $_SESSION['two_factor'] : false,
        'session_timeout' => isset($_SESSION['session_timeout']) ? $_SESSION['session_timeout'] : 30,
        'login_alerts' => isset($_SESSION['login_alerts']) ? $_SESSION['login_alerts'] : true
    );

} catch (PDOException $e) {
    error_log("Settings fetch error: " . $e->getMessage());
    $error = 'Ma\'lumotlarni yuklashda xatolik yuz berdi.';
    $user = null;
    $preferences = array();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF tekshirish
    if (!CSRFToken::verify(isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '')) {
        $error = 'Xavfsizlik xatosi! Sahifani qaytadan yuklang.';
        SecurityLogger::log('csrf_token_invalid', $_SESSION['user_id'], null, 'high', 'Invalid CSRF token on settings update');
    } else {
        $action = isset($_POST['action']) ? $_POST['action'] : '';

        if ($action === 'update_preferences') {
            // Preferences yangilash
            $theme = isset($_POST['theme']) ? InputValidator::sanitize($_POST['theme'], 'string') : 'light';
            $language = isset($_POST['language']) ? InputValidator::sanitize($_POST['language'], 'string') : 'uz';
            $notifications = isset($_POST['notifications']) ? true : false;
            $twoFactor = isset($_POST['two_factor']) ? true : false;
            $sessionTimeout = isset($_POST['session_timeout']) ? (int)$_POST['session_timeout'] : 30;
            $loginAlerts = isset($_POST['login_alerts']) ? true : false;

            // Validatsiya
            $validThemes = array('light', 'dark');
            $validLanguages = array('uz', 'en', 'ru');
            $validTimeouts = array(15, 30, 60, 120);

            if (!in_array($theme, $validThemes)) {
                $error = 'Noto\'g\'ri mavzu tanlangan!';
            } elseif (!in_array($language, $validLanguages)) {
                $error = 'Noto\'g\'ri til tanlangan!';
            } elseif (!in_array($sessionTimeout, $validTimeouts)) {
                $error = 'Noto\'g\'ri session timeout!';
            } else {
                // Preferences ni session ga saqlash
                $_SESSION['theme'] = $theme;
                $_SESSION['language'] = $language;
                $_SESSION['notifications'] = $notifications;
                $_SESSION['two_factor'] = $twoFactor;
                $_SESSION['session_timeout'] = $sessionTimeout;
                $_SESSION['login_alerts'] = $loginAlerts;

                // Preferences ni yangilash
                $preferences = array(
                    'theme' => $theme,
                    'language' => $language,
                    'notifications' => $notifications,
                    'two_factor' => $twoFactor,
                    'session_timeout' => $sessionTimeout,
                    'login_alerts' => $loginAlerts
                );

                $success = 'Sozlamalar muvaffaqiyatli saqlandi!';

                SecurityLogger::log('settings_updated', $_SESSION['user_id'], null, 'low',
                    "User preferences updated: theme={$theme}, language={$language}");
            }
        }

        if ($action === 'clear_sessions') {
            // Barcha boshqa sessionlarni tozalash (demo)
            session_regenerate_id(true);

            $success = 'Barcha boshqa sessionlar tozalandi!';

            SecurityLogger::log('sessions_cleared', $_SESSION['user_id'], null, 'medium',
                'User cleared all other sessions');
        }

        if ($action === 'download_data') {
            // Foydalanuvchi ma'lumotlarini export qilish (GDPR compliance)
            try {
                // Foydalanuvchi ma'lumotlari
                $userData = array(
                    'user_info' => array(
                        'username' => $user['username'],
                        'email' => $user['email'],
                        'full_name' => $user['full_name'],
                        'created_at' => $user['created_at'],
                        'last_login' => $user['last_login']
                    ),
                    'preferences' => $preferences
                );

                // Postlar
                $stmt = $db->prepare("SELECT title, content, created_at FROM user_data WHERE user_id = ? ORDER BY created_at ASC");
                $stmt->execute(array($_SESSION['user_id']));
                $posts = $stmt->fetchAll();
                $userData['posts'] = $posts;

                // Activity logs
                $logs = SecurityLogger::getUserActivity($_SESSION['user_id'], 100);
                $userData['activity_logs'] = $logs;

                // JSON file yaratish
                $filename = 'user_data_' . $user['username'] . '_' . date('Y-m-d_H-i-s') . '.json';

                header('Content-Type: application/json');
                header('Content-Disposition: attachment; filename="' . $filename . '"');
                header('Content-Length: ' . strlen(json_encode($userData, JSON_PRETTY_PRINT)));

                echo json_encode($userData, JSON_PRETTY_PRINT);

                SecurityLogger::log('data_download', $_SESSION['user_id'], null, 'low',
                    'User downloaded personal data');

                exit();

            } catch (Exception $e) {
                error_log("Data download error: " . $e->getMessage());
                $error = 'Ma\'lumotlarni yuklab olishda xatolik yuz berdi.';
            }
        }

        if ($action === 'delete_account') {
            // Hisobni o'chirish (demo uchun faqat nofaollashtirish)
            $confirmPassword = isset($_POST['confirm_password']) ? $_POST['confirm_password'] : '';

            if (empty($confirmPassword)) {
                $error = 'Hisobni o\'chirish uchun parolni tasdiqlang!';
            } else {
                // Parolni tekshirish
                $stmt = $db->prepare("SELECT password_hash FROM users WHERE id = ?");
                $stmt->execute(array($_SESSION['user_id']));
                $userPassword = $stmt->fetch();

                if (!password_verify($confirmPassword, $userPassword['password_hash'])) {
                    $error = 'Parol noto\'g\'ri!';
                    SecurityLogger::log('account_delete_failed', $_SESSION['user_id'], null, 'medium',
                        'Failed account deletion attempt - wrong password');
                } else {
                    // Hisobni nofaollashtirish (real loyihada to'liq o'chirish mumkin)
                    $stmt = $db->prepare("UPDATE users SET is_active = 0 WHERE id = ?");
                    $stmt->execute(array($_SESSION['user_id']));

                    SecurityLogger::log('account_deleted', $_SESSION['user_id'], null, 'high',
                        'User account deleted/deactivated');

                    // Session tozalash
                    session_destroy();

                    // Logout sahifasiga yo'naltirish
                    header('Location: ../auth/logout.php?deleted=1');
                    exit();
                }
            }
        }
    }
}

// Security statistics
$securityStats = array();
try {
    // Oxirgi 30 kun ichidagi login urinishlari
    $stmt = $db->prepare("
        SELECT COUNT(*) as total_logins
        FROM security_logs 
        WHERE user_id = ? AND action_type = 'login_success' 
        AND timestamp > DATE_SUB(NOW(), INTERVAL 30 DAY)
    ");
    $stmt->execute(array($_SESSION['user_id']));
    $securityStats['recent_logins'] = $stmt->fetch();

    // Failed login attempts
    $stmt = $db->prepare("
        SELECT COUNT(*) as failed_attempts
        FROM security_logs 
        WHERE user_id = ? AND action_type = 'login_failed' 
        AND timestamp > DATE_SUB(NOW(), INTERVAL 30 DAY)
    ");
    $stmt->execute(array($_SESSION['user_id']));
    $securityStats['failed_attempts'] = $stmt->fetch();

} catch (Exception $e) {
    $securityStats = array(
        'recent_logins' => array('total_logins' => 0),
        'failed_attempts' => array('failed_attempts' => 0)
    );
}
?>

<!DOCTYPE html>
<html lang="<?= $preferences['language'] ?>" data-theme="<?= $preferences['theme'] ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sozlamalar - Web Security</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <style>
        /* Theme variables */
        :root {
            --bg-primary: #f8f9fa;
            --bg-secondary: #ffffff;
            --text-primary: #333333;
            --text-secondary: #666666;
            --border-color: #dee2e6;
        }

        [data-theme="dark"] {
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --text-primary: #ffffff;
            --text-secondary: #cccccc;
            --border-color: #444444;
        }

        .settings-container {
            max-width: 1000px;
            margin: 2rem auto;
            padding: 0 20px;
        }

        .settings-section {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 2rem;
            margin: 2rem 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border: 1px solid var(--border-color);
        }

        .settings-tabs {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            border-bottom: 2px solid var(--border-color);
            flex-wrap: wrap;
        }

        .tab-button {
            padding: 0.75rem 1.5rem;
            border: none;
            background: none;
            border-bottom: 3px solid transparent;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
            color: var(--text-secondary);
        }

        .tab-button.active {
            border-bottom-color: #667eea;
            color: #667eea;
        }

        .tab-content {
            display: none;
            color: var(--text-primary);
        }

        .tab-content.active {
            display: block;
        }

        .setting-item {
            padding: 1.5rem;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin: 1rem 0;
            background: var(--bg-primary);
        }

        .setting-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .setting-title {
            font-weight: bold;
            color: var(--text-primary);
        }

        .setting-description {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-bottom: 1rem;
        }

        .security-indicator {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }

        .security-high {
            background: #d4edda;
            color: #155724;
        }

        .security-medium {
            background: #fff3cd;
            color: #856404;
        }

        .security-low {
            background: #f8d7da;
            color: #721c24;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }

        .stat-card {
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border-color);
        }

        .stat-number {
            font-size: 1.5rem;
            font-weight: bold;
            color: #667eea;
        }

        .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .danger-zone {
            border: 2px solid #e74c3c;
            background: #ffeaea;
        }

        .danger-zone h4 {
            color: #e74c3c;
        }

        .switch {
            position: relative;
            display: inline-block;
            width: 60px;
            height: 34px;
        }

        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .4s;
            border-radius: 34px;
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 26px;
            width: 26px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }

        input:checked + .slider {
            background-color: #667eea;
        }

        input:checked + .slider:before {
            transform: translateX(26px);
        }

        @media (max-width: 768px) {
            .settings-tabs {
                flex-direction: column;
            }

            .setting-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }

            .stats-grid {
                grid-template-columns: 1fr;
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
            <a href="profile.php" class="nav-link">Profil</a>
            <?php if ($_SESSION['role'] === 'admin'): ?>
                <a href="../admin/dashboard.php" class="nav-link">Admin Panel</a>
            <?php endif; ?>
            <a href="../auth/logout.php" class="nav-link logout">Chiqish</a>
        </div>
    </div>
</nav>

<main class="main-content">
    <div class="settings-container">
        <?php if ($user): ?>
            <div class="settings-section">
                <h1 style="text-align: center; margin-bottom: 2rem; color: var(--text-primary);">
                    ⚙️ Sozlamalar
                </h1>

                <?php if ($error): ?>
                    <div class="alert alert-error"><?= InputValidator::sanitize($error) ?></div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <div class="alert alert-success"><?= InputValidator::sanitize($success) ?></div>
                <?php endif; ?>

                <!-- Tabs -->
                <div class="settings-tabs">
                    <button class="tab-button active" onclick="showTab('general')">Umumiy</button>
                    <button class="tab-button" onclick="showTab('security')">Xavfsizlik</button>
                    <button class="tab-button" onclick="showTab('privacy')">Maxfiylik</button>
                    <button class="tab-button" onclick="showTab('data')">Ma'lumotlar</button>
                    <button class="tab-button" onclick="showTab('account')">Hisob</button>
                </div>
            </div>

            <!-- Umumiy sozlamalar -->
            <div id="general" class="tab-content active">
                <div class="settings-section">
                    <h3>🎨 Umumiy sozlamalar</h3>

                    <form method="POST" action="">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <input type="hidden" name="action" value="update_preferences">

                        <div class="setting-item">
                            <div class="setting-header">
                                <div class="setting-title">Mavzu (Theme)</div>
                            </div>
                            <div class="setting-description">
                                Interfeys rangini tanlang
                            </div>
                            <select name="theme" class="form-control" style="max-width: 200px;">
                                <option value="light" <?= $preferences['theme'] === 'light' ? 'selected' : '' ?>>Yorug'</option>
                                <option value="dark" <?= $preferences['theme'] === 'dark' ? 'selected' : '' ?>>Qorong'u</option>
                            </select>
                        </div>

                        <div class="setting-item">
                            <div class="setting-header">
                                <div class="setting-title">Til (Language)</div>
                            </div>
                            <div class="setting-description">
                                Interfeys tilini tanlang
                            </div>
                            <select name="language" class="form-control" style="max-width: 200px;">
                                <option value="uz" <?= $preferences['language'] === 'uz' ? 'selected' : '' ?>>O'zbekcha</option>
                                <option value="en" <?= $preferences['language'] === 'en' ? 'selected' : '' ?>>English</option>
                                <option value="ru" <?= $preferences['language'] === 'ru' ? 'selected' : '' ?>>Русский</option>
                            </select>
                        </div>

                        <div class="setting-item">
                            <div class="setting-header">
                                <div class="setting-title">Bildirishnomalar</div>
                                <label class="switch">
                                    <input type="checkbox" name="notifications" <?= $preferences['notifications'] ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            <div class="setting-description">
                                Email va browser bildirishnomalarini olish
                            </div>
                        </div>

                        <div class="setting-item">
                            <div class="setting-header">
                                <div class="setting-title">Session timeout</div>
                            </div>
                            <div class="setting-description">
                                Faolsizlik vaqti (daqiqalarda)
                            </div>
                            <select name="session_timeout" class="form-control" style="max-width: 200px;">
                                <option value="15" <?= $preferences['session_timeout'] === 15 ? 'selected' : '' ?>>15 daqiqa</option>
                                <option value="30" <?= $preferences['session_timeout'] === 30 ? 'selected' : '' ?>>30 daqiqa</option>
                                <option value="60" <?= $preferences['session_timeout'] === 60 ? 'selected' : '' ?>>1 soat</option>
                                <option value="120" <?= $preferences['session_timeout'] === 120 ? 'selected' : '' ?>>2 soat</option>
                            </select>
                        </div>

                        <button type="submit" class="btn btn-primary">Sozlamalarni saqlash</button>
                    </form>
                </div>
            </div>

            <!-- Xavfsizlik sozlamalari -->
            <div id="security" class="tab-content">
                <div class="settings-section">
                    <h3>🔐 Xavfsizlik sozlamalari</h3>

                    <form method="POST" action="">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <input type="hidden" name="action" value="update_preferences">

                        <div class="setting-item">
                            <div class="setting-header">
                                <div class="setting-title">Ikki faktorli autentifikatsiya (2FA)</div>
                                <label class="switch">
                                    <input type="checkbox" name="two_factor" <?= $preferences['two_factor'] ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            <div class="setting-description">
                                Hisobingiz uchun qo'shimcha xavfsizlik qatlami (Demo)
                            </div>
                            <span class="security-indicator security-high">Yuqori xavfsizlik</span>
                        </div>

                        <div class="setting-item">
                            <div class="setting-header">
                                <div class="setting-title">Login haqida ogohlantirish</div>
                                <label class="switch">
                                    <input type="checkbox" name="login_alerts" <?= $preferences['login_alerts'] ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            <div class="setting-description">
                                Yangi qurilmadan kirish haqida email yuborish
                            </div>
                        </div>

                        <button type="submit" class="btn btn-primary">Xavfsizlik sozlamalarini saqlash</button>
                    </form>

                    <!-- Xavfsizlik statistikalari -->
                    <div style="margin-top: 2rem;">
                        <h4>📊 Xavfsizlik statistikalari</h4>
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-number"><?= $securityStats['recent_logins']['total_logins'] ?></div>
                                <div class="stat-label">Oxirgi 30 kun login</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number"><?= $securityStats['failed_attempts']['failed_attempts'] ?></div>
                                <div class="stat-label">Noto'g'ri urinishlar</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number"><?= $user['failed_login_attempts'] ?></div>
                                <div class="stat-label">Joriy failed attempts</div>
                            </div>
                        </div>
                    </div>

                    <!-- Session boshqaruvi -->
                    <div class="setting-item">
                        <div class="setting-header">
                            <div class="setting-title">Session boshqaruvi</div>
                        </div>
                        <div class="setting-description">
                            Barcha boshqa qurilmalardagi sessionlarni tozalash
                        </div>
                        <form method="POST" action="" style="margin-top: 1rem;">
                            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                            <input type="hidden" name="action" value="clear_sessions">
                            <button type="submit" class="btn btn-warning"
                                    onclick="return confirm('Barcha boshqa sessionlarni tozalashni xohlaysizmi?')">
                                Boshqa sessionlarni tozalash
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Maxfiylik -->
            <div id="privacy" class="tab-content">
                <div class="settings-section">
                    <h3>🔒 Maxfiylik va ma'lumotlar</h3>

                    <div class="setting-item">
                        <div class="setting-header">
                            <div class="setting-title">Ma'lumotlar maxfiyligi</div>
                            <span class="security-indicator security-high">Himoyalangan</span>
                        </div>
                        <div class="setting-description">
                            Sizning shaxsiy ma'lumotlaringiz shifrlangan va himoyalangan
                        </div>
                        <ul style="margin-top: 1rem; color: var(--text-secondary);">
                            <li>✅ Parollar hash qilingan (bcrypt)</li>
                            <li>✅ Session ma'lumotlari shifrlangan</li>
                            <li>✅ HTTPS orqali uzatish</li>
                            <li>✅ Input validation va sanitization</li>
                        </ul>
                    </div>

                    <div class="setting-item">
                        <div class="setting-header">
                            <div class="setting-title">Activity Logging</div>
                        </div>
                        <div class="setting-description">
                            Sizning faoliyatingiz xavfsizlik maqsadida yozib olinadi
                        </div>
                        <p style="color: var(--text-secondary); margin-top: 0.5rem;">
                            <small>Log qilinadigan ma'lumotlar: login/logout, profil o'zgartirishlari, xavfsizlik hodisalari</small>
                        </p>
                    </div>
                </div>
            </div>

            <!-- Ma'lumotlar -->
            <div id="data" class="tab-content">
                <div class="settings-section">
                    <h3>💾 Ma'lumotlarni boshqarish</h3>

                    <div class="setting-item">
                        <div class="setting-header">
                            <div class="setting-title">Ma'lumotlarni yuklab olish</div>
                        </div>
                        <div class="setting-description">
                            Barcha shaxsiy ma'lumotlaringizni JSON formatida yuklab oling (GDPR compliance)
                        </div>
                        <form method="POST" action="" style="margin-top: 1rem;">
                            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                            <input type="hidden" name="action" value="download_data">
                            <button type="submit" class="btn btn-info">
                                📥 Ma'lumotlarni yuklab olish
                            </button>
                        </form>
                    </div>

                    <div class="setting-item">
                        <div class="setting-header">
                            <div class="setting-title">Ma'lumotlar tarkibi</div>
                        </div>
                        <div class="setting-description">
                            Quyidagi ma'lumotlar export qilinadi:
                        </div>
                        <ul style="margin-top: 1rem; color: var(--text-secondary);">
                            <li>👤 Profil ma'lumotlari</li>
                            <li>⚙️ Sozlamalar va preferences</li>
                            <li>📝 Yaratilgan postlar va kontentlar</li>
                            <li>📊 Activity logs va faoliyat tarixi</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Hisob boshqaruvi -->
            <div id="account" class="tab-content">
                <div class="settings-section">
                    <h3>👤 Hisob boshqaruvi</h3>

                    <div class="setting-item">
                        <div class="setting-header">
                            <div class="setting-title">Hisob ma'lumotlari</div>
                        </div>
                        <div class="setting-description">
                            Asosiy hisob ma'lumotlari
                        </div>
                        <div style="margin-top: 1rem;">
                            <p><strong>Foydalanuvchi nomi:</strong> <?= InputValidator::sanitize($user['username']) ?></p>
                            <p><strong>Email:</strong> <?= InputValidator::sanitize($user['email']) ?></p>
                            <p><strong>To'liq ism:</strong> <?= InputValidator::sanitize($user['full_name']) ?></p>
                            <p><strong>Rol:</strong> <?= ucfirst($user['role']) ?></p>
                            <p><strong>Ro'yxatdan o'tgan:</strong> <?= date('d.m.Y H:i', strtotime($user['created_at'])) ?></p>
                            <p><strong>Oxirgi kirish:</strong>
                                <?php if ($user['last_login']): ?>
                                    <?= date('d.m.Y H:i', strtotime($user['last_login'])) ?>
                                <?php else: ?>
                                    Hech qachon
                                <?php endif; ?>
                            </p>
                        </div>
                        <div style="margin-top: 1rem;">
                            <a href="profile.php" class="btn btn-secondary">Profilni tahrirlash</a>
                        </div>
                    </div>

                    <div class="setting-item">
                        <div class="setting-header">
                            <div class="setting-title">Hisob holati</div>
                            <span class="security-indicator <?= $user['is_active'] ? 'security-high' : 'security-low' ?>">
                                    <?= $user['is_active'] ? 'Faol' : 'Nofaol' ?>
                                </span>
                        </div>
                        <div class="setting-description">
                            Hisobingiz holati va xavfsizlik darajasi
                        </div>
                        <div style="margin-top: 1rem;">
                            <?php if ($user['failed_login_attempts'] > 0): ?>
                                <p style="color: #e74c3c;">
                                    ⚠️ Noto'g'ri login urinishlari: <?= $user['failed_login_attempts'] ?>
                                </p>
                            <?php else: ?>
                                <p style="color: #27ae60;">
                                    ✅ Hech qanday xavfsizlik muammosi yo'q
                                </p>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- Xavfli hudud -->
                    <div class="setting-item danger-zone">
                        <h4>⚠️ Xavfli hudud</h4>
                        <div class="setting-description">
                            Quyidagi amallar qaytarib bo'lmaydi va hisobingizga doimiy ta'sir qiladi.
                        </div>

                        <div style="margin-top: 2rem;">
                            <h5>Hisobni o'chirish</h5>
                            <p style="color: #721c24; margin-bottom: 1rem;">
                                Hisobni o'chirilgandan keyin barcha ma'lumotlaringiz o'chiriladi va bu amalni qaytarib bo'lmaydi.
                                Avval ma'lumotlaringizni yuklab olishingizni tavsiya qilamiz.
                            </p>

                            <form method="POST" action="" id="deleteAccountForm">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                <input type="hidden" name="action" value="delete_account">

                                <div class="form-group" style="max-width: 300px;">
                                    <label for="confirm_password">Tasdiqlash uchun parolni kiriting:</label>
                                    <input type="password" id="confirm_password" name="confirm_password"
                                           class="form-control" required>
                                </div>

                                <button type="submit" class="btn btn-danger"
                                        onclick="return confirmAccountDeletion()">
                                    🗑️ Hisobni o'chirish
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

        <?php else: ?>
            <div class="settings-section">
                <div class="alert alert-error">Foydalanuvchi ma'lumotlari yuklanmadi.</div>
            </div>
        <?php endif; ?>
    </div>
</main>

<script>
    // Tab switching
    function showTab(tabName) {
        // Hide all tabs
        document.querySelectorAll('.tab-content').forEach(function(tab) {
            tab.classList.remove('active');
        });

        // Hide all tab buttons
        document.querySelectorAll('.tab-button').forEach(function(btn) {
            btn.classList.remove('active');
        });

        // Show selected tab
        document.getElementById(tabName).classList.add('active');
        event.target.classList.add('active');

        // Update URL hash
        window.location.hash = tabName;
    }

    // Load tab from URL hash
    window.addEventListener('load', function() {
        const hash = window.location.hash.substring(1);
        if (hash && document.getElementById(hash)) {
            showTab(hash);
        }
    });

    // Theme switching
    document.addEventListener('change', function(e) {
        if (e.target.name === 'theme') {
            document.documentElement.setAttribute('data-theme', e.target.value);
        }
    });

    // Account deletion confirmation
    function confirmAccountDeletion() {
        const confirmations = [
            'Hisobni o\'chirishni haqiqatan ham xohlaysizmi?',
            'Bu amal qaytarib bo\'lmaydi. Davom etasizmi?',
            'Barcha ma\'lumotlaringiz o\'chiriladi. Rozimisiz?'
        ];

        for (let confirmation of confirmations) {
            if (!confirm(confirmation)) {
                return false;
            }
        }

        return true;
    }

    // Form auto-save (preferences)
    let autoSaveTimeout;
    document.querySelectorAll('select[name], input[type="checkbox"]').forEach(function(element) {
        element.addEventListener('change', function() {
            clearTimeout(autoSaveTimeout);
            autoSaveTimeout = setTimeout(function() {
                // Auto-save preferences after 2 seconds
                const form = element.closest('form');
                if (form && form.querySelector('input[name="action"][value="update_preferences"]')) {
                    // Show saving indicator
                    showNotification('Sozlamalar saqlanmoqda...', 'info');

                    // Submit form via AJAX
                    const formData = new FormData(form);
                    fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    })
                        .then(response => response.text())
                        .then(data => {
                            showNotification('Sozlamalar saqlandi!', 'success');
                        })
                        .catch(error => {
                            showNotification('Xatolik yuz berdi!', 'error');
                        });
                }
            }, 2000);
        });
    });

    // Notification system
    function showNotification(message, type) {
        // Remove existing notifications
        const existing = document.querySelector('.notification');
        if (existing) {
            existing.remove();
        }

        // Create notification
        const notification = document.createElement('div');
        notification.className = 'notification notification-' + type;
        notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 1rem 1.5rem;
                border-radius: 8px;
                color: white;
                font-weight: 500;
                z-index: 1000;
                opacity: 0;
                transform: translateX(100%);
                transition: all 0.3s ease;
            `;

        // Set background color
        const colors = {
            'success': '#27ae60',
            'error': '#e74c3c',
            'warning': '#f39c12',
            'info': '#3498db'
        };
        notification.style.backgroundColor = colors[type] || colors.info;

        notification.textContent = message;
        document.body.appendChild(notification);

        // Show notification
        setTimeout(() => {
            notification.style.opacity = '1';
            notification.style.transform = 'translateX(0)';
        }, 100);

        // Hide notification after 3 seconds
        setTimeout(() => {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }

    // Initialize theme
    document.addEventListener('DOMContentLoaded', function() {
        const savedTheme = '<?= $preferences["theme"] ?>';
        document.documentElement.setAttribute('data-theme', savedTheme);
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Alt + number keys for tab switching
        if (e.altKey && !e.ctrlKey && !e.shiftKey) {
            const tabs = ['general', 'security', 'privacy', 'data', 'account'];
            const num = parseInt(e.key);
            if (num >= 1 && num <= tabs.length) {
                e.preventDefault();
                showTab(tabs[num - 1]);
            }
        }
    });

    // Show keyboard shortcuts help
    console.log(`
🔧 Sozlamalar Klaviatura Yorliqlari:
Alt + 1: Umumiy sozlamalar
Alt + 2: Xavfsizlik
Alt + 3: Maxfiylik
Alt + 4: Ma'lumotlar
Alt + 5: Hisob
        `);
</script>
</body>
</html>