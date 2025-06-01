<?php
/**
 * Admin Users - Foydalanuvchilarni boshqarish
 * Web Security Project
 */

require_once '../config/database.php';
require_once '../config/security.php';
require_once '../security/security_logger.php';
require_once '../security/csrf_token.php';

// Admin huquqini tekshirish
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: ../auth/login.php');
    exit;
}

$error = '';
$success = '';

// CSRF token
$csrfToken = CSRFToken::generate();

// Filtrlar
$filters = [
    'role' => $_GET['role'] ?? '',
    'status' => $_GET['status'] ?? '',
    'search' => $_GET['search'] ?? ''
];

// Sahifalash
$page = max(1, (int)($_GET['page'] ?? 1));
$limit = 20;
$offset = ($page - 1) * $limit;

try {
    $db = getDB();

    // POST actions
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!CSRFToken::verify($_POST['csrf_token'] ?? '')) {
            $error = 'Xavfsizlik xatosi! Sahifani qaytadan yuklang.';
        }
    }

    // Filtrlar uchun SQL qurilishi
    $whereConditions = ['1=1'];
    $params = [];

    if (!empty($filters['role'])) {
        $whereConditions[] = "role = ?";
        $params[] = $filters['role'];
    }

    if (!empty($filters['status'])) {
        if ($filters['status'] === 'active') {
            $whereConditions[] = "is_active = 1";
        } elseif ($filters['status'] === 'inactive') {
            $whereConditions[] = "is_active = 0";
        } elseif ($filters['status'] === 'locked') {
            $whereConditions[] = "locked_until > NOW()";
        }
    }

    if (!empty($filters['search'])) {
        $whereConditions[] = "(username LIKE ? OR email LIKE ? OR full_name LIKE ?)";
        $searchParam = '%' . $filters['search'] . '%';
        $params[] = $searchParam;
        $params[] = $searchParam;
        $params[] = $searchParam;
    }

    $whereClause = implode(' AND ', $whereConditions);

    // Jami foydalanuvchilar soni
    $countSql = "SELECT COUNT(*) as total FROM users WHERE {$whereClause}";
    $stmt = $db->prepare($countSql);
    $stmt->execute($params);
    $totalUsers = $stmt->fetch()['total'];
    $totalPages = ceil($totalUsers / $limit);

    // Foydalanuvchilarni olish
    $sql = "
        SELECT 
            id, username, email, full_name, role, created_at, last_login, 
            is_active, failed_login_attempts, locked_until
        FROM users 
        WHERE {$whereClause}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    ";
    $params[] = $limit;
    $params[] = $offset;

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $users = $stmt->fetchAll();

    // Statistikalar
    $stmt = $db->query("
        SELECT 
            COUNT(*) as total_users,
            SUM(is_active) as active_users,
            SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_users,
            SUM(CASE WHEN locked_until > NOW() THEN 1 ELSE 0 END) as locked_users
        FROM users
    ");
    $userStats = $stmt->fetch();

} catch (Exception $e) {
    error_log("Admin users error: " . $e->getMessage());
    $error = "Foydalanuvchilarni yuklashda xatolik yuz berdi.";
    $users = [];
    $userStats = [];
    $totalUsers = 0;
    $totalPages = 0;
}
?>

<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Foydalanuvchilar - Admin</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <style>
        .admin-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem 20px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }

        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
        }

        .stat-card.primary {
            border-left: 5px solid #3498db;
        }

        .stat-card.success {
            border-left: 5px solid #27ae60;
        }

        .stat-card.warning {
            border-left: 5px solid #f39c12;
        }

        .stat-card.danger {
            border-left: 5px solid #e74c3c;
        }

        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            color: #333;
        }

        .stat-label {
            color: #666;
            margin-top: 0.5rem;
            font-size: 0.9rem;
        }

        .filters-section {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin: 2rem 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .users-section {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin: 2rem 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .user-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1rem 0;
            border-left: 4px solid #ddd;
            transition: all 0.3s ease;
        }

        .user-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }

        .user-card.admin {
            border-left-color: #3498db;
            background: #e8f4fd;
        }

        .user-card.inactive {
            border-left-color: #e74c3c;
            background: #ffeaea;
        }

        .user-card.locked {
            border-left-color: #f39c12;
            background: #fff8e1;
        }

        .user-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .user-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .user-actions {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        .user-actions button,
        .user-actions select {
            font-size: 0.8rem;
            padding: 0.25rem 0.5rem;
        }

        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 0.5rem;
            margin: 2rem 0;
        }

        .pagination a, .pagination span {
            padding: 0.5rem 1rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            text-decoration: none;
            color: #333;
        }

        .pagination a:hover {
            background: #667eea;
            color: white;
        }

        .pagination .current {
            background: #667eea;
            color: white;
        }

        .filter-button {
            background: #667eea;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }

        .filter-button:hover {
            background: #5a6fd8;
            color: white;
        }

        .clear-filters {
            background: #6c757d;
        }

        .clear-filters:hover {
            background: #545b62;
        }

        @media (max-width: 768px) {
            .filters-grid {
                grid-template-columns: 1fr;
            }

            .user-header {
                flex-direction: column;
                align-items: flex-start;
            }

            .user-info {
                grid-template-columns: 1fr;
            }

            .user-actions {
                width: 100%;
                justify-content: flex-start;
            }
        }
    </style>
</head>
<body>
<nav class="navbar">
    <div class="nav-container">
        <div class="nav-brand">
            <h2><a href="../index.php" style="text-decoration: none; color: inherit;">🛡️ Web Security - Users</a></h2>
        </div>
        <div class="nav-menu">
            <a href="../index.php" class="nav-link">Bosh sahifa</a>
            <a href="dashboard.php" class="nav-link">Dashboard</a>
            <a href="logs.php" class="nav-link">Loglar</a>
            <a href="../auth/logout.php" class="nav-link logout">Chiqish</a>
        </div>
    </div>
</nav>

<main class="main-content">
    <div class="admin-container">
        <h1 style="color: white; text-align: center; margin-bottom: 2rem;">
            👥 Foydalanuvchilarni Boshqarish
        </h1>

        <?php if ($error): ?>
            <div class="alert alert-error"><?= SecurityConfig::sanitizeInput($error) ?></div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success"><?= SecurityConfig::sanitizeInput($success) ?></div>
        <?php endif; ?>

        <!-- Statistikalar -->
        <div class="stats-grid">
            <div class="stat-card primary">
                <div class="stat-number"><?= $userStats['total_users'] ?? 0 ?></div>
                <div class="stat-label">Jami foydalanuvchilar</div>
            </div>

            <div class="stat-card success">
                <div class="stat-number"><?= $userStats['active_users'] ?? 0 ?></div>
                <div class="stat-label">Faol foydalanuvchilar</div>
            </div>

            <div class="stat-card warning">
                <div class="stat-number"><?= $userStats['admin_users'] ?? 0 ?></div>
                <div class="stat-label">Adminlar</div>
            </div>

            <div class="stat-card danger">
                <div class="stat-number"><?= $userStats['locked_users'] ?? 0 ?></div>
                <div class="stat-label">Bloklangan hisoblar</div>
            </div>
        </div>

        <!-- Filtrlar -->
        <div class="filters-section">
            <h3>🔍 Filtrlar</h3>

            <form method="GET" action="">
                <div class="filters-grid">
                    <div class="form-group">
                        <label for="role">Rol:</label>
                        <select id="role" name="role" class="form-control">
                            <option value="">Barchasi</option>
                            <option value="user" <?= $filters['role'] === 'user' ? 'selected' : '' ?>>User</option>
                            <option value="admin" <?= $filters['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="status">Holat:</label>
                        <select id="status" name="status" class="form-control">
                            <option value="">Barchasi</option>
                            <option value="active" <?= $filters['status'] === 'active' ? 'selected' : '' ?>>Faol</option>
                            <option value="inactive" <?= $filters['status'] === 'inactive' ? 'selected' : '' ?>>Nofaol</option>
                            <option value="locked" <?= $filters['status'] === 'locked' ? 'selected' : '' ?>>Bloklangan</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="search">Qidirish:</label>
                        <input type="text" id="search" name="search" class="form-control"
                               value="<?= SecurityConfig::sanitizeInput($filters['search']) ?>"
                               placeholder="Ism, email yoki username...">
                    </div>
                </div>

                <div style="display: flex; gap: 1rem; margin-top: 1rem;">
                    <button type="submit" class="filter-button">Filtrlarni qo'llash</button>
                    <a href="?" class="filter-button clear-filters">Filtrlarni tozalash</a>
                </div>
            </form>

            <!-- Tezkor filtrlar -->
            <div style="margin-top: 1rem;">
                <strong>Tezkor filtrlar:</strong>
                <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.5rem;">
                    <a href="?role=admin" class="btn btn-primary" style="font-size: 0.8rem; padding: 0.25rem 0.5rem;">Adminlar</a>
                    <a href="?status=inactive" class="btn btn-danger" style="font-size: 0.8rem; padding: 0.25rem 0.5rem;">Nofaol</a>
                    <a href="?status=locked" class="btn btn-warning" style="font-size: 0.8rem; padding: 0.25rem 0.5rem;">Bloklangan</a>
                </div>
            </div>
        </div>

        <!-- Foydalanuvchilar ro'yxati -->
        <div class="users-section">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <h3>👤 Foydalanuvchilar ro'yxati</h3>
                <span style="color: #666;">
                        Jami: <?= $totalUsers ?> ta foydalanuvchi
                        (<?= $page ?>/<?= $totalPages ?> sahifa)
                    </span>
            </div>

            <?php if (empty($users)): ?>
                <p style="color: #666; text-align: center; padding: 2rem;">
                    Filtr shartlariga mos foydalanuvchilar topilmadi.
                </p>
            <?php else: ?>
                <?php foreach ($users as $user): ?>
                    <?php
                    $cardClass = '';
                    if ($user['role'] === 'admin') $cardClass = 'admin';
                    elseif (!$user['is_active']) $cardClass = 'inactive';
                    elseif ($user['locked_until'] && strtotime($user['locked_until']) > time()) $cardClass = 'locked';
                    ?>

                    <div class="user-card <?= $cardClass ?>">
                        <div class="user-header">
                            <div>
                                <h4 style="margin: 0; color: #333;">
                                    <?= SecurityConfig::sanitizeInput($user['full_name']) ?>
                                    <small style="color: #666;">(@<?= SecurityConfig::sanitizeInput($user['username']) ?>)</small>
                                </h4>
                                <div style="margin-top: 0.5rem;">
                                        <span class="badge badge-<?= $user['role'] === 'admin' ? 'primary' : 'info' ?>">
                                            <?= ucfirst($user['role']) ?>
                                        </span>

                                    <?php if ($user['is_active']): ?>
                                        <span class="badge badge-success">Faol</span>
                                    <?php else: ?>
                                        <span class="badge badge-danger">Nofaol</span>
                                    <?php endif; ?>

                                    <?php if ($user['locked_until'] && strtotime($user['locked_until']) > time()): ?>
                                        <span class="badge badge-warning">Bloklangan</span>
                                    <?php endif; ?>

                                    <?php if ($user['id'] === $_SESSION['user_id']): ?>
                                        <span class="badge badge-info">Siz</span>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>

                        <div class="user-info">
                            <div>
                                <strong>Email:</strong><br>
                                <?= SecurityConfig::sanitizeInput($user['email']) ?>
                            </div>

                            <div>
                                <strong>Ro'yxatdan o'tgan:</strong><br>
                                <?= date('d.m.Y H:i', strtotime($user['created_at'])) ?>
                            </div>

                            <div>
                                <strong>Oxirgi kirish:</strong><br>
                                <?php if ($user['last_login']): ?>
                                    <?= date('d.m.Y H:i', strtotime($user['last_login'])) ?>
                                <?php else: ?>
                                    <span style="color: #666;">Hech qachon</span>
                                <?php endif; ?>
                            </div>

                            <div>
                                <strong>Login urinishlari:</strong><br>
                                <?php if ($user['failed_login_attempts'] > 0): ?>
                                    <span style="color: #e74c3c;"><?= $user['failed_login_attempts'] ?> ta</span>
                                <?php else: ?>
                                    <span style="color: #27ae60;">0</span>
                                <?php endif; ?>
                            </div>
                        </div>

                        <?php if ($user['id'] !== $_SESSION['user_id']): ?>
                            <div class="user-actions">
                                <!-- Status o'zgartirish -->
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                    <input type="hidden" name="action" value="toggle_status">
                                    <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                    <button type="submit" class="btn <?= $user['is_active'] ? 'btn-warning' : 'btn-success' ?>"
                                            onclick="return confirm('Foydalanuvchi holatini o\'zgartirishni xohlaysizmi?')">
                                        <?= $user['is_active'] ? 'Nofaollashtirish' : 'Faollashtirish' ?>
                                    </button>
                                </form>

                                <!-- Rol o'zgartirish -->
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                    <input type="hidden" name="action" value="change_role">
                                    <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                    <select name="new_role" onchange="if(confirm('Rolni o\'zgartirishni xohlaysizmi?')) this.form.submit();">
                                        <option value="">Rol o'zgartirish</option>
                                        <option value="user" <?= $user['role'] === 'user' ? 'disabled' : '' ?>>User</option>
                                        <option value="admin" <?= $user['role'] === 'admin' ? 'disabled' : '' ?>>Admin</option>
                                    </select>
                                </form>

                                <!-- Qulfdan chiqarish -->
                                <?php if ($user['locked_until'] && strtotime($user['locked_until']) > time()): ?>
                                    <form method="POST" style="display: inline;">
                                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                        <input type="hidden" name="action" value="unlock_account">
                                        <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                        <button type="submit" class="btn btn-info"
                                                onclick="return confirm('Hisobni qulfdan chiqarishni xohlaysizmi?')">
                                            Qulfdan chiqarish
                                        </button>
                                    </form>
                                <?php endif; ?>

                                <!-- Parolni tiklash -->
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                    <input type="hidden" name="action" value="reset_password">
                                    <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                    <button type="submit" class="btn btn-secondary"
                                            onclick="return confirm('Foydalanuvchi parolini tiklashni xohlaysizmi?')">
                                        Parolni tiklash
                                    </button>
                                </form>

                                <!-- Faollik tarixi -->
                                <a href="logs.php?user_id=<?= $user['id'] ?>" class="btn btn-info">
                                    Faollik tarixi
                                </a>
                            </div>
                        <?php else: ?>
                            <div class="user-actions">
                                <span style="color: #666; font-style: italic;">Bu sizning hisobingiz</span>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>

            <!-- Sahifalash -->
            <?php if ($totalPages > 1): ?>
                <div class="pagination">
                    <?php if ($page > 1): ?>
                        <a href="?<?= http_build_query(array_merge($filters, ['page' => 1])) ?>"><<</a>
                        <a href="?<?= http_build_query(array_merge($filters, ['page' => $page - 1])) ?>"><</a>
                    <?php endif; ?>

                    <?php
                    $start = max(1, $page - 2);
                    $end = min($totalPages, $page + 2);
                    ?>

                    <?php for ($i = $start; $i <= $end; $i++): ?>
                        <?php if ($i === $page): ?>
                            <span class="current"><?= $i ?></span>
                        <?php else: ?>
                            <a href="?<?= http_build_query(array_merge($filters, ['page' => $i])) ?>"><?= $i ?></a>
                        <?php endif; ?>
                    <?php endfor; ?>

                    <?php if ($page < $totalPages): ?>
                        <a href="?<?= http_build_query(array_merge($filters, ['page' => $page + 1])) ?>">></a>
                        <a href="?<?= http_build_query(array_merge($filters, ['page' => $totalPages])) ?>">>></a>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</main>

<script>
    // Form validation
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            const action = this.querySelector('input[name="action"]')?.value;

            if (action === 'change_role') {
                const select = this.querySelector('select[name="new_role"]');
                if (!select.value) {
                    e.preventDefault();
                    return false;
                }
            }
        });
    });
</script>
</body>
</html> else {
$action = $_POST['action'] ?? '';
$userId = (int)($_POST['user_id'] ?? 0);

if ($action === 'toggle_status' && $userId > 0) {
// Foydalanuvchi holatini o'zgartirish
if ($userId === $_SESSION['user_id']) {
$error = 'O\'z hisobingiz holatini o\'zgartira olmaysiz!';
} else {
$stmt = $db->prepare("UPDATE users SET is_active = !is_active WHERE id = ?");
$stmt->execute([$userId]);

$stmt = $db->prepare("SELECT username, is_active FROM users WHERE id = ?");
$stmt->execute([$userId]);
$user = $stmt->fetch();

$newStatus = $user['is_active'] ? 'faollashtirildi' : 'nofaollashtirildi';
$success = "Foydalanuvchi {$user['username']} {$newStatus}.";

SecurityLogger::log('user_status_changed', $_SESSION['user_id'], null, 'medium',
"User {$user['username']} status changed to " . ($user['is_active'] ? 'active' : 'inactive'));
}
}

if ($action === 'change_role' && $userId > 0) {
// Foydalanuvchi rolini o'zgartirish
$newRole = $_POST['new_role'] ?? '';

if ($userId === $_SESSION['user_id']) {
$error = 'O\'z rolingizni o\'zgartira olmaysiz!';
} elseif (!in_array($newRole, ['user', 'admin'])) {
$error = 'Noto\'g\'ri rol!';
} else {
$stmt = $db->prepare("UPDATE users SET role = ? WHERE id = ?");
$stmt->execute([$newRole, $userId]);

$stmt = $db->prepare("SELECT username FROM users WHERE id = ?");
$stmt->execute([$userId]);
$user = $stmt->fetch();

$success = "Foydalanuvchi {$user['username']} roli {$newRole} ga o'zgartirildi.";

SecurityLogger::log('user_role_changed', $_SESSION['user_id'], null, 'high',
"User {$user['username']} role changed to {$newRole}");
}
}

if ($action === 'unlock_account' && $userId > 0) {
// Hisobni qulfdan chiqarish
$stmt = $db->prepare("
UPDATE users
SET failed_login_attempts = 0, locked_until = NULL
WHERE id = ?
");
$stmt->execute([$userId]);

$stmt = $db->prepare("SELECT username FROM users WHERE id = ?");
$stmt->execute([$userId]);
$user = $stmt->fetch();

$success = "Foydalanuvchi {$user['username']} hisobi qulfdan chiqarildi.";

SecurityLogger::log('account_unlocked', $_SESSION['user_id'], null, 'medium',
"User {$user['username']} account unlocked by admin");
}

if ($action === 'reset_password' && $userId > 0) {
// Parolni tiklash (admin tomonidan)
$newPassword = 'password123'; // Demo uchun oddiy parol
$passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);

$stmt = $db->prepare("
UPDATE users
SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL
WHERE id = ?
");
$stmt->execute([$passwordHash, $userId]);

$stmt = $db->prepare("SELECT username FROM users WHERE id = ?");
$stmt->execute([$userId]);
$user = $stmt->fetch();

$success = "Foydalanuvchi {$user['username']} paroli tiklandi. Yangi parol: {$newPassword}";

SecurityLogger::log('password_reset_by_admin', $_SESSION['user_id'], null, 'high',
"User {$user['username']} password reset by admin");
}
}