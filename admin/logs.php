<?php
/**
 * Admin Logs - Xavfsizlik loglari
 * Web Security Project
 */

require_once '../config/database.php';
require_once '../config/security.php';
require_once '../security/security_logger.php';

// Admin huquqini tekshirish
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: ../auth/login.php');
    exit;
}

// Filtrlar
$filters = [
    'action_type' => $_GET['action_type'] ?? '',
    'risk_level' => $_GET['risk_level'] ?? '',
    'ip_address' => $_GET['ip_address'] ?? '',
    'user_id' => $_GET['user_id'] ?? '',
    'date_from' => $_GET['date_from'] ?? '',
    'date_to' => $_GET['date_to'] ?? '',
    'search' => $_GET['search'] ?? ''
];

// Sahifalash
$page = max(1, (int)($_GET['page'] ?? 1));
$limit = 50;
$offset = ($page - 1) * $limit;

try {
    $db = getDB();

    // Filtrlar uchun SQL qurilishi
    $whereConditions = ['1=1'];
    $params = [];

    if (!empty($filters['action_type'])) {
        $whereConditions[] = "sl.action_type = ?";
        $params[] = $filters['action_type'];
    }

    if (!empty($filters['risk_level'])) {
        $whereConditions[] = "sl.risk_level = ?";
        $params[] = $filters['risk_level'];
    }

    if (!empty($filters['ip_address'])) {
        $whereConditions[] = "sl.ip_address = ?";
        $params[] = $filters['ip_address'];
    }

    if (!empty($filters['user_id'])) {
        $whereConditions[] = "sl.user_id = ?";
        $params[] = $filters['user_id'];
    }

    if (!empty($filters['date_from'])) {
        $whereConditions[] = "sl.timestamp >= ?";
        $params[] = $filters['date_from'] . ' 00:00:00';
    }

    if (!empty($filters['date_to'])) {
        $whereConditions[] = "sl.timestamp <= ?";
        $params[] = $filters['date_to'] . ' 23:59:59';
    }

    if (!empty($filters['search'])) {
        $whereConditions[] = "(sl.details LIKE ? OR u.username LIKE ?)";
        $searchParam = '%' . $filters['search'] . '%';
        $params[] = $searchParam;
        $params[] = $searchParam;
    }

    $whereClause = implode(' AND ', $whereConditions);

    // Jami yozuvlar soni
    $countSql = "
        SELECT COUNT(*) as total
        FROM security_logs sl
        LEFT JOIN users u ON sl.user_id = u.id
        WHERE {$whereClause}
    ";
    $stmt = $db->prepare($countSql);
    $stmt->execute($params);
    $totalLogs = $stmt->fetch()['total'];
    $totalPages = ceil($totalLogs / $limit);

    // Loglarni olish
    $sql = "
        SELECT sl.*, u.username
        FROM security_logs sl
        LEFT JOIN users u ON sl.user_id = u.id
        WHERE {$whereClause}
        ORDER BY sl.timestamp DESC
        LIMIT ? OFFSET ?
    ";
    $params[] = $limit;
    $params[] = $offset;

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $logs = $stmt->fetchAll();

    // Statistikalar
    $stats = SecurityLogger::getStatistics(24);

    // Action types va risk levels ro'yxati
    $stmt = $db->query("SELECT DISTINCT action_type FROM security_logs ORDER BY action_type");
    $actionTypes = $stmt->fetchAll(PDO::FETCH_COLUMN);

    $riskLevels = ['low', 'medium', 'high'];

} catch (Exception $e) {
    error_log("Admin logs error: " . $e->getMessage());
    $error = "Loglarni yuklashda xatolik yuz berdi.";
    $logs = [];
    $stats = [];
    $actionTypes = [];
    $totalLogs = 0;
    $totalPages = 0;
}
?>

<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xavfsizlik Loglari - Admin</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <style>
        .admin-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem 20px;
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
            font-size: 2rem;
            font-weight: bold;
            color: #333;
        }

        .stat-label {
            color: #666;
            margin-top: 0.5rem;
            font-size: 0.9rem;
        }

        .logs-section {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin: 2rem 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .log-item {
            padding: 1rem;
            border-left: 4px solid #ddd;
            margin: 0.5rem 0;
            background: #f8f9fa;
            border-radius: 0 8px 8px 0;
            transition: all 0.3s ease;
        }

        .log-item:hover {
            transform: translateX(5px);
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
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

        .log-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .log-action {
            font-weight: bold;
            color: #333;
        }

        .log-meta {
            font-size: 0.875rem;
            color: #666;
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .log-details {
            margin-top: 0.5rem;
            color: #555;
            font-size: 0.9rem;
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

        .export-buttons {
            display: flex;
            gap: 1rem;
            margin: 1rem 0;
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

            .log-header {
                flex-direction: column;
                align-items: flex-start;
            }

            .log-meta {
                flex-direction: column;
                gap: 0.25rem;
            }
        }
    </style>
</head>
<body>
<nav class="navbar">
    <div class="nav-container">
        <div class="nav-brand">
            <h2><a href="../index.php" style="text-decoration: none; color: inherit;">🛡️ Web Security - Logs</a></h2>
        </div>
        <div class="nav-menu">
            <a href="../index.php" class="nav-link">Bosh sahifa</a>
            <a href="dashboard.php" class="nav-link">Dashboard</a>
            <a href="users.php" class="nav-link">Foydalanuvchilar</a>
            <a href="../auth/logout.php" class="nav-link logout">Chiqish</a>
        </div>
    </div>
</nav>

<main class="main-content">
    <div class="admin-container">
        <h1 style="color: white; text-align: center; margin-bottom: 2rem;">
            📊 Xavfsizlik Loglari
        </h1>

        <?php if (isset($error)): ?>
            <div class="alert alert-error"><?= SecurityConfig::sanitizeInput($error) ?></div>
        <?php endif; ?>

        <!-- Statistikalar -->
        <?php if (!empty($stats)): ?>
            <div class="stats-grid">
                <?php
                $highRiskCount = 0;
                $mediumRiskCount = 0;
                $lowRiskCount = 0;
                $totalEvents = 0;

                foreach ($stats as $stat) {
                    $totalEvents += $stat['count'];
                    switch ($stat['risk_level']) {
                        case 'high': $highRiskCount += $stat['count']; break;
                        case 'medium': $mediumRiskCount += $stat['count']; break;
                        case 'low': $lowRiskCount += $stat['count']; break;
                    }
                }
                ?>

                <div class="stat-card info">
                    <div class="stat-number"><?= $totalEvents ?></div>
                    <div class="stat-label">Jami hodisalar (24 soat)</div>
                </div>

                <div class="stat-card danger">
                    <div class="stat-number"><?= $highRiskCount ?></div>
                    <div class="stat-label">Yuqori xavfli</div>
                </div>

                <div class="stat-card warning">
                    <div class="stat-number"><?= $mediumRiskCount ?></div>
                    <div class="stat-label">O'rta xavfli</div>
                </div>

                <div class="stat-card success">
                    <div class="stat-number"><?= $lowRiskCount ?></div>
                    <div class="stat-label">Past xavfli</div>
                </div>
            </div>
        <?php endif; ?>

        <!-- Filtrlar -->
        <div class="filters-section">
            <h3>🔍 Filtrlar</h3>

            <form method="GET" action="">
                <div class="filters-grid">
                    <div class="form-group">
                        <label for="action_type">Harakat turi:</label>
                        <select id="action_type" name="action_type" class="form-control">
                            <option value="">Barchasi</option>
                            <?php foreach ($actionTypes as $type): ?>
                                <option value="<?= SecurityConfig::sanitizeInput($type) ?>"
                                    <?= $filters['action_type'] === $type ? 'selected' : '' ?>>
                                    <?= SecurityConfig::sanitizeInput($type) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="risk_level">Xavf darajasi:</label>
                        <select id="risk_level" name="risk_level" class="form-control">
                            <option value="">Barchasi</option>
                            <?php foreach ($riskLevels as $level): ?>
                                <option value="<?= $level ?>"
                                    <?= $filters['risk_level'] === $level ? 'selected' : '' ?>>
                                    <?= ucfirst($level) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="ip_address">IP manzil:</label>
                        <input type="text" id="ip_address" name="ip_address" class="form-control"
                               value="<?= SecurityConfig::sanitizeInput($filters['ip_address']) ?>"
                               placeholder="192.168.1.1">
                    </div>

                    <div class="form-group">
                        <label for="user_id">Foydalanuvchi ID:</label>
                        <input type="number" id="user_id" name="user_id" class="form-control"
                               value="<?= SecurityConfig::sanitizeInput($filters['user_id']) ?>"
                               placeholder="1">
                    </div>

                    <div class="form-group">
                        <label for="date_from">Sanadan:</label>
                        <input type="date" id="date_from" name="date_from" class="form-control"
                               value="<?= SecurityConfig::sanitizeInput($filters['date_from']) ?>">
                    </div>

                    <div class="form-group">
                        <label for="date_to">Sanagacha:</label>
                        <input type="date" id="date_to" name="date_to" class="form-control"
                               value="<?= SecurityConfig::sanitizeInput($filters['date_to']) ?>">
                    </div>
                </div>

                <div class="form-group">
                    <label for="search">Qidirish (tafsilotlar va foydalanuvchi nomi):</label>
                    <input type="text" id="search" name="search" class="form-control"
                           value="<?= SecurityConfig::sanitizeInput($filters['search']) ?>"
                           placeholder="Qidiruv so'zi...">
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
                    <a href="?risk_level=high" class="btn btn-danger" style="font-size: 0.8rem; padding: 0.25rem 0.5rem;">Yuqori xavfli</a>
                    <a href="?action_type=login_failed" class="btn btn-warning" style="font-size: 0.8rem; padding: 0.25rem 0.5rem;">Login xatolari</a>
                    <a href="?action_type=csrf_attack_prevented" class="btn btn-info" style="font-size: 0.8rem; padding: 0.25rem 0.5rem;">CSRF hujumlar</a>
                    <a href="?date_from=<?= date('Y-m-d') ?>" class="btn btn-secondary" style="font-size: 0.8rem; padding: 0.25rem 0.5rem;">Bugun</a>
                </div>
            </div>
        </div>

        <!-- Export tugmalari -->
        <div class="export-buttons">
            <a href="?<?= http_build_query(array_merge($filters, ['export' => 'csv'])) ?>" class="filter-button">
                📄 CSV Export
            </a>
            <button onclick="printLogs()" class="filter-button">🖨️ Chop etish</button>
        </div>

        <!-- Loglar ro'yxati -->
        <div class="logs-section">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <h3>📋 Loglar ro'yxati</h3>
                <span style="color: #666;">
                        Jami: <?= $totalLogs ?> ta yozuv
                        (<?= $page ?>/<?= $totalPages ?> sahifa)
                    </span>
            </div>

            <?php if (empty($logs)): ?>
                <p style="color: #666; text-align: center; padding: 2rem;">
                    Filtr shartlariga mos loglar topilmadi.
                </p>
            <?php else: ?>
                <?php foreach ($logs as $log): ?>
                    <div class="log-item <?= $log['risk_level'] ?>">
                        <div class="log-header">
                            <div class="log-action">
                                <?= SecurityConfig::sanitizeInput($log['action_type']) ?>
                            </div>
                            <div class="badge badge-<?= $log['risk_level'] === 'high' ? 'danger' : ($log['risk_level'] === 'medium' ? 'warning' : 'success') ?>">
                                <?= ucfirst($log['risk_level']) ?>
                            </div>
                        </div>

                        <div class="log-meta">
                                <span>
                                    👤 <?= $log['username'] ? SecurityConfig::sanitizeInput($log['username']) : 'Guest' ?>
                                    <?php if ($log['user_id']): ?>
                                        (ID: <?= $log['user_id'] ?>)
                                    <?php endif; ?>
                                </span>
                            <span>🌐 <?= SecurityConfig::sanitizeInput($log['ip_address']) ?></span>
                            <span>🕒 <?= date('d.m.Y H:i:s', strtotime($log['timestamp'])) ?></span>
                        </div>

                        <?php if ($log['details']): ?>
                            <div class="log-details">
                                <?= SecurityConfig::sanitizeInput($log['details']) ?>
                            </div>
                        <?php endif; ?>

                        <?php if ($log['user_agent']): ?>
                            <div class="log-details" style="font-size: 0.8rem; color: #999; margin-top: 0.25rem;">
                                🖥️ <?= SecurityConfig::sanitizeInput(substr($log['user_agent'], 0, 100)) ?>
                                <?php if (strlen($log['user_agent']) > 100): ?>...<?php endif; ?>
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
    // Auto-refresh har 30 soniyada (agar filtr yo'q bo'lsa)
    <?php if (empty(array_filter($filters))): ?>
    setInterval(function() {
        if (document.hidden) return; // Sahifa ko'rinmasa refresh qilmaymiz
        location.reload();
    }, 30000);
    <?php endif; ?>

    // Print function
    function printLogs() {
        window.print();
    }

    // CSV export
    <?php if (isset($_GET['export']) && $_GET['export'] === 'csv'): ?>
    <?php
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="security_logs_' . date('Y-m-d_H-i-s') . '.csv"');

    $output = SecurityLogger::exportLogs($filters, 'csv');
    echo $output;
    exit;
    ?>
    <?php endif; ?>
</script>
</body>
</html>