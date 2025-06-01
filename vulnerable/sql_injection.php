<?php
/**
 * SQL Injection Demo - Zaif va Xavfsiz kod namunalari
 * Web Security Project
 * ⚠️ FAQAT TA'LIM MAQSADIDA!
 */

require_once '../config/database.php';
require_once '../config/security.php';

// Bu sahifa faqat login qilgan foydalanuvchilar uchun
if (!isset($_SESSION['user_id'])) {
    header('Location: ../auth/login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
}

$vulnerableResult = '';
$secureResult = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $searchTerm = $_POST['search'] ?? '';
    $demoType = $_POST['demo_type'] ?? 'vulnerable';

    if (!empty($searchTerm)) {
        try {
            $db = getDB();

            if ($demoType === 'vulnerable') {
                // ⚠️ ZAIF KOD - SQL Injection ga qarshi himoyasiz
                $query = "SELECT username, full_name, email FROM users WHERE username LIKE '%{$searchTerm}%' OR full_name LIKE '%{$searchTerm}%'";
                $stmt = $db->query($query);
                $vulnerableResult = $stmt->fetchAll();

                // Qo'shimcha debug ma'lumoti
                $vulnerableQuery = $query;

            } else {
                // ✅ XAVFSIZ KOD - Prepared statements
                $query = "SELECT username, full_name, email FROM users WHERE username LIKE ? OR full_name LIKE ?";
                $searchParam = "%{$searchTerm}%";
                $stmt = $db->prepare($query);
                $stmt->execute([$searchParam, $searchParam]);
                $secureResult = $stmt->fetchAll();

                $secureQuery = $query . " [Parameters: '$searchParam', '$searchParam']";
            }

        } catch (PDOException $e) {
            $error = "Ma'lumotlar bazasi xatosi: " . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Demo - Web Security</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <style>
        .demo-container {
            max-width: 1000px;
            margin: 2rem auto;
            padding: 0 20px;
        }

        .demo-section {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin: 2rem 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .vulnerable {
            border-left: 5px solid #e74c3c;
        }

        .secure {
            border-left: 5px solid #27ae60;
        }

        .code-block {
            background: #f4f4f4;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
        }

        .vulnerable-code {
            background: #ffeaea;
            border-color: #e74c3c;
        }

        .secure-code {
            background: #eafaf1;
            border-color: #27ae60;
        }

        .attack-examples {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }

        .results-table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }

        .results-table th,
        .results-table td {
            border: 1px solid #ddd;
            padding: 0.5rem;
            text-align: left;
        }

        .results-table th {
            background: #f8f9fa;
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
            <a href="../user/profile.php" class="nav-link">Profil</a>
            <a href="../auth/logout.php" class="nav-link logout">Chiqish</a>
        </div>
    </div>
</nav>

<main class="main-content">
    <div class="demo-container">
        <div class="demo-section">
            <h1>🚨 SQL Injection Demo</h1>
            <div class="alert alert-warning">
                <strong>Ogohlantirish:</strong> Bu sahifa faqat ta'lim maqsadida yaratilgan.
                Real loyihalarda zaif kodlardan foydalanmang!
            </div>

            <h3>Test qilish uchun form:</h3>
            <form method="POST" style="margin: 2rem 0;">
                <div class="form-group">
                    <label for="search">Qidiruv (foydalanuvchi nomi yoki ism):</label>
                    <input
                        type="text"
                        id="search"
                        name="search"
                        class="form-control"
                        value="<?= SecurityConfig::sanitizeInput($_POST['search'] ?? '') ?>"
                        placeholder="admin yoki ' OR 1=1 --"
                    >
                </div>

                <div class="form-group">
                    <label>Demo turi:</label>
                    <div style="display: flex; gap: 1rem; margin-top: 0.5rem;">
                        <label style="display: flex; align-items: center; gap: 0.5rem;">
                            <input type="radio" name="demo_type" value="vulnerable"
                                <?= ($_POST['demo_type'] ?? 'vulnerable') === 'vulnerable' ? 'checked' : '' ?>>
                            <span style="color: #e74c3c;">Zaif kod</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 0.5rem;">
                            <input type="radio" name="demo_type" value="secure"
                                <?= ($_POST['demo_type'] ?? '') === 'secure' ? 'checked' : '' ?>>
                            <span style="color: #27ae60;">Xavfsiz kod</span>
                        </label>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary">Qidirish</button>
            </form>

            <?php if ($error): ?>
                <div class="alert alert-error"><?= SecurityConfig::sanitizeInput($error) ?></div>
            <?php endif; ?>
        </div>

        <!-- Zaif kod namunasi -->
        <div class="demo-section vulnerable">
            <h2>❌ Zaif kod (SQL Injection ga qarshi himoyasiz)</h2>

            <div class="code-block vulnerable-code">
<pre>// ZAIF KOD - Ishlatmang!
$searchTerm = $_POST['search'];
$query = "SELECT username, full_name, email FROM users
          WHERE username LIKE '%{$searchTerm}%'
          OR full_name LIKE '%{$searchTerm}%'";
$stmt = $db->query($query);</pre>
            </div>

            <h4>Muammo:</h4>
            <ul>
                <li>Foydalanuvchi kiritgan ma'lumot to'g'ridan-to'g'ri SQL so'roviga qo'shiladi</li>
                <li>Hujumchi maxsus belgilar orqali SQL kodini o'zgartirishi mumkin</li>
                <li>Ma'lumotlar bazasiga ruxsatsiz kirish imkoniyati</li>
            </ul>

            <?php if (isset($vulnerableQuery)): ?>
                <h4>Bajarilgan so'rov:</h4>
                <div class="code-block">
                    <?= htmlspecialchars($vulnerableQuery) ?>
                </div>
            <?php endif; ?>

            <?php if ($vulnerableResult): ?>
                <h4>Natija:</h4>
                <table class="results-table">
                    <thead>
                    <tr>
                        <th>Foydalanuvchi nomi</th>
                        <th>To'liq ism</th>
                        <th>Email</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($vulnerableResult as $row): ?>
                        <tr>
                            <td><?= SecurityConfig::sanitizeInput($row['username']) ?></td>
                            <td><?= SecurityConfig::sanitizeInput($row['full_name']) ?></td>
                            <td><?= SecurityConfig::sanitizeInput($row['email']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <!-- Xavfsiz kod namunasi -->
        <div class="demo-section secure">
            <h2>✅ Xavfsiz kod (Prepared Statements)</h2>

            <div class="code-block secure-code">
<pre>// XAVFSIZ KOD - Ishlatish kerak!
$searchTerm = $_POST['search'];
$query = "SELECT username, full_name, email FROM users
          WHERE username LIKE ? OR full_name LIKE ?";
$searchParam = "%{$searchTerm}%";
$stmt = $db->prepare($query);
$stmt->execute([$searchParam, $searchParam]);</pre>
            </div>

            <h4>Afzalliklar:</h4>
            <ul>
                <li>Prepared statements ma'lumot va kodni ajratadi</li>
                <li>SQL Injection hujumlaridan himoyalaydi</li>
                <li>Ma'lumotlar xavfsiz ravishda parametr sifatida uzatiladi</li>
            </ul>

            <?php if (isset($secureQuery)): ?>
                <h4>Bajarilgan so'rov:</h4>
                <div class="code-block">
                    <?= htmlspecialchars($secureQuery) ?>
                </div>
            <?php endif; ?>

            <?php if ($secureResult): ?>
                <h4>Natija:</h4>
                <table class="results-table">
                    <thead>
                    <tr>
                        <th>Foydalanuvchi nomi</th>
                        <th>To'liq ism</th>
                        <th>Email</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($secureResult as $row): ?>
                        <tr>
                            <td><?= SecurityConfig::sanitizeInput($row['username']) ?></td>
                            <td><?= SecurityConfig::sanitizeInput($row['full_name']) ?></td>
                            <td><?= SecurityConfig::sanitizeInput($row['email']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <!-- Hujum namunalari -->
        <div class="demo-section">
            <h2>🎯 SQL Injection hujum namunalari</h2>
            <div class="attack-examples">
                <h4>Quyidagi matnlarni "Zaif kod" rejimida sinab ko'ring:</h4>
                <ul>
                    <li><code>' OR 1=1 --</code> - Barcha yozuvlarni ko'rsatish</li>
                    <li><code>' UNION SELECT username, password_hash, email FROM users --</code> - Parol hash larini olish</li>
                    <li><code>' OR username='admin' --</code> - Admin ma'lumotlarini olish</li>
                    <li><code>'; DROP TABLE users; --</code> - Jadval o'chirish (haqiqiy bazada sinab ko'rmang!)</li>
                </ul>
                <p><strong>Eslatma:</strong> "Xavfsiz kod" rejimida bu hujumlar ishlamaydi.</p>
            </div>
        </div>

        <!-- Himoya usullari -->
        <div class="demo-section">
            <h2>🛡️ SQL Injection dan himoyalanish usullari</h2>
            <ol>
                <li><strong>Prepared Statements</strong> - Eng yaxshi himoya usuli</li>
                <li><strong>Input Validation</strong> - Kiruvchi ma'lumotlarni tekshirish</li>
                <li><strong>Escaping</strong> - Maxsus belgilarni qochirish</li>
                <li><strong>Least Privilege</strong> - Ma'lumotlar bazasi foydalanuvchisiga minimal huquq berish</li>
                <li><strong>Error Handling</strong> - Xato xabarlarini yashirish</li>
            </ol>
        </div>
    </div>
</main>

<script>
    // Form yuborishdan oldin ogohlantirish
    document.querySelector('form').addEventListener('submit', function(e) {
        const demoType = document.querySelector('input[name="demo_type"]:checked').value;
        const searchTerm = document.getElementById('search').value;

        if (demoType === 'vulnerable' && searchTerm.includes('DROP')) {
            if (!confirm('Bu hujum ma\'lumotlar bazasiga zarar yetkazishi mumkin. Davom etasizmi?')) {
                e.preventDefault();
            }
        }
    });
</script>
</body>
</html>