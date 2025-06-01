<?php
/**
 * XSS Demo - Cross-Site Scripting namunalari
 * Web Security Project
 * ⚠️ FAQAT TA'LIM MAQSADIDA!
 */

require_once '../config/database.php';
require_once '../config/security.php';
require_once '../security/security_logger.php';

// Bu sahifa faqat login qilgan foydalanuvchilar uchun
if (!isset($_SESSION['user_id'])) {
    header('Location: ../auth/login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
}

$vulnerableOutput = '';
$secureOutput = '';
$reflectedXSS = '';
$storedXSS = '';

// Stored XSS uchun ma'lumotlar bazasidan olish
try {
    $db = getDB();
    $stmt = $db->prepare("SELECT title, content, created_at FROM user_data WHERE user_id = ? ORDER BY created_at DESC LIMIT 5");
    $stmt->execute([$_SESSION['user_id']]);
    $userPosts = $stmt->fetchAll();
} catch (PDOException $e) {
    $userPosts = [];
    error_log("XSS demo error: " . $e->getMessage());
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'reflected') {
        // Reflected XSS test
        $userInput = $_POST['user_input'] ?? '';
        $demoType = $_POST['demo_type'] ?? 'vulnerable';

        if ($demoType === 'vulnerable') {
            // ⚠️ ZAIF KOD - XSS ga qarshi himoyasiz
            $vulnerableOutput = "Siz kiritdingiz: " . $userInput;
        } else {
            // ✅ XAVFSIZ KOD - HTML encoding
            $secureOutput = "Siz kiritdingiz: " . htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
        }

        // Log qilish
        SecurityLogger::log('xss_test', $_SESSION['user_id'], null, 'low',
            "XSS demo test: {$demoType} - " . substr($userInput, 0, 100));
    }

    if ($action === 'stored') {
        // Stored XSS test
        $title = $_POST['title'] ?? '';
        $content = $_POST['content'] ?? '';
        $storeType = $_POST['store_type'] ?? 'vulnerable';

        try {
            if ($storeType === 'vulnerable') {
                // ⚠️ ZAIF KOD - Ma'lumotni tozalamasdan saqlash
                $stmt = $db->prepare("INSERT INTO user_data (user_id, title, content) VALUES (?, ?, ?)");
                $stmt->execute([$_SESSION['user_id'], $title, $content]);
            } else {
                // ✅ XAVFSIZ KOD - Ma'lumotni tozalab saqlash
                $cleanTitle = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
                $cleanContent = htmlspecialchars($content, ENT_QUOTES, 'UTF-8');
                $stmt = $db->prepare("INSERT INTO user_data (user_id, title, content) VALUES (?, ?, ?)");
                $stmt->execute([$_SESSION['user_id'], $cleanTitle, $cleanContent]);
            }

            // Sahifani qayta yuklash
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;

        } catch (PDOException $e) {
            error_log("Stored XSS demo error: " . $e->getMessage());
        }
    }
}
?>

<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Demo - Web Security</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <style>
        .demo-container {
            max-width: 1200px;
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

        .output-box {
            border: 2px solid #ddd;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            min-height: 50px;
            background: #fff;
        }

        .vulnerable-output {
            border-color: #e74c3c;
            background: #ffeaea;
        }

        .secure-output {
            border-color: #27ae60;
            background: #eafaf1;
        }

        .attack-examples {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }

        .post-item {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            background: #f8f9fa;
        }

        .post-title {
            font-weight: bold;
            color: #333;
            margin-bottom: 0.5rem;
        }

        .post-content {
            color: #666;
            line-height: 1.5;
        }

        .post-meta {
            font-size: 0.8rem;
            color: #999;
            margin-top: 0.5rem;
        }

        .demo-tabs {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .tab-button {
            padding: 0.75rem 1.5rem;
            border: none;
            background: #f8f9fa;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .tab-button.active {
            background: #667eea;
            color: white;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
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
            <h1>🕷️ XSS (Cross-Site Scripting) Demo</h1>
            <div class="alert alert-warning">
                <strong>Ogohlantirish:</strong> Bu sahifa faqat ta'lim maqsadida yaratilgan.
                Real loyihalarda zaif kodlardan foydalanmang!
            </div>

            <!-- Tabs -->
            <div class="demo-tabs">
                <button class="tab-button active" onclick="showTab('reflected')">Reflected XSS</button>
                <button class="tab-button" onclick="showTab('stored')">Stored XSS</button>
                <button class="tab-button" onclick="showTab('prevention')">Himoya usullari</button>
            </div>
        </div>

        <!-- Reflected XSS -->
        <div id="reflected" class="tab-content active">
            <div class="demo-section">
                <h2>🔄 Reflected XSS Demo</h2>
                <p>Reflected XSS - foydalanuvchi kiritgan ma'lumot darhol sahifaga qaytarilganda yuz beradi.</p>

                <form method="POST" style="margin: 2rem 0;">
                    <input type="hidden" name="action" value="reflected">

                    <div class="form-group">
                        <label for="user_input">Test uchun matn kiriting:</label>
                        <input
                            type="text"
                            id="user_input"
                            name="user_input"
                            class="form-control"
                            placeholder="Salom yoki <script>alert('XSS')</script>"
                            value="<?= SecurityConfig::sanitizeInput($_POST['user_input'] ?? '') ?>"
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

                    <button type="submit" class="btn btn-primary">Test qilish</button>
                </form>

                <?php if ($vulnerableOutput): ?>
                    <div class="demo-section vulnerable">
                        <h3>❌ Zaif kod natijasi:</h3>
                        <div class="output-box vulnerable-output">
                            <?= $vulnerableOutput ?> <!-- XSS zaiflik! -->
                        </div>
                        <div class="code-block vulnerable-code">
<pre>// ZAIF KOD - Ishlatmang!
echo "Siz kiritdingiz: " . $_POST['user_input'];</pre>
                        </div>
                    </div>
                <?php endif; ?>

                <?php if ($secureOutput): ?>
                    <div class="demo-section secure">
                        <h3>✅ Xavfsiz kod natijasi:</h3>
                        <div class="output-box secure-output">
                            <?= $secureOutput ?>
                        </div>
                        <div class="code-block secure-code">
<pre>// XAVFSIZ KOD - Ishlatish kerak!
echo "Siz kiritdingiz: " . htmlspecialchars($_POST['user_input'], ENT_QUOTES, 'UTF-8');</pre>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Stored XSS -->
        <div id="stored" class="tab-content">
            <div class="demo-section">
                <h2>💾 Stored XSS Demo</h2>
                <p>Stored XSS - zararli kod ma'lumotlar bazasiga saqlanib, keyinchalik boshqa foydalanuvchilarga ko'rsatilganda yuz beradi.</p>

                <form method="POST" style="margin: 2rem 0;">
                    <input type="hidden" name="action" value="stored">

                    <div class="form-group">
                        <label for="title">Post sarlavhasi:</label>
                        <input
                            type="text"
                            id="title"
                            name="title"
                            class="form-control"
                            placeholder="Mening postim yoki <img src=x onerror=alert('XSS')>"
                            required
                        >
                    </div>

                    <div class="form-group">
                        <label for="content">Post matni:</label>
                        <textarea
                            id="content"
                            name="content"
                            class="form-control"
                            rows="3"
                            placeholder="Bu mening test postim yoki <script>alert('Stored XSS!')</script>"
                            required
                        ></textarea>
                    </div>

                    <div class="form-group">
                        <label>Saqlash turi:</label>
                        <div style="display: flex; gap: 1rem; margin-top: 0.5rem;">
                            <label style="display: flex; align-items: center; gap: 0.5rem;">
                                <input type="radio" name="store_type" value="vulnerable" checked>
                                <span style="color: #e74c3c;">Zaif saqlash</span>
                            </label>
                            <label style="display: flex; align-items: center; gap: 0.5rem;">
                                <input type="radio" name="store_type" value="secure">
                                <span style="color: #27ae60;">Xavfsiz saqlash</span>
                            </label>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary">Post yaratish</button>
                </form>
            </div>

            <!-- Saqlangan postlar -->
            <div class="demo-section">
                <h3>📝 Sizning postlaringiz:</h3>
                <?php if (empty($userPosts)): ?>
                    <p style="color: #666;">Hozircha postlaringiz yo'q.</p>
                <?php else: ?>
                    <?php foreach ($userPosts as $post): ?>
                        <div class="post-item">
                            <div class="post-title">
                                <?= $post['title'] ?> <!-- Bu yerda XSS zaiflik bo'lishi mumkin! -->
                            </div>
                            <div class="post-content">
                                <?= $post['content'] ?> <!-- Bu yerda ham XSS zaiflik bo'lishi mumkin! -->
                            </div>
                            <div class="post-meta">
                                <?= date('d.m.Y H:i', strtotime($post['created_at'])) ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>

        <!-- Himoya usullari -->
        <div id="prevention" class="tab-content">
            <div class="demo-section">
                <h2>🛡️ XSS dan himoyalanish usullari</h2>

                <h3>1. Input Encoding/Escaping</h3>
                <div class="code-block secure-code">
<pre>// PHP da
$safe_output = htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// JavaScript da
function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}</pre>
                </div>

                <h3>2. Content Security Policy (CSP)</h3>
                <div class="code-block secure-code">
<pre>// HTTP Header
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';

// Meta tag
&lt;meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self';"&gt;</pre>
                </div>

                <h3>3. Input Validation</h3>
                <div class="code-block secure-code">
<pre>// Faqat ruxsat etilgan belgilarni qabul qilish
function validateInput($input) {
    // Faqat harflar, raqamlar va ba'zi belgilar
    return preg_match('/^[a-zA-Z0-9\s\-_.,!?]+$/', $input);
}

// HTML teglarini olib tashlash
$clean_input = strip_tags($user_input);</pre>
                </div>

                <h3>4. HTTP-only Cookies</h3>
                <div class="code-block secure-code">
<pre>// Cookie'larni JavaScript orqali o'qishni taqiqlash
setcookie('session_id', $session_id, [
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Strict'
]);</pre>
                </div>
            </div>

            <!-- Hujum namunalari -->
            <div class="demo-section">
                <h3>🎯 XSS hujum namunalari</h3>
                <div class="attack-examples">
                    <h4>Quyidagi kodlarni "Zaif kod" rejimida sinab ko'ring:</h4>
                    <ul>
                        <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> - Oddiy XSS</li>
                        <li><code>&lt;img src=x onerror=alert('XSS')&gt;</code> - Image tag orqali</li>
                        <li><code>&lt;svg onload=alert('XSS')&gt;</code> - SVG tag orqali</li>
                        <li><code>javascript:alert('XSS')</code> - JavaScript protokoli</li>
                        <li><code>&lt;iframe src="javascript:alert('XSS')"&gt;</code> - iFrame orqali</li>
                    </ul>
                    <p><strong>Eslatma:</strong> "Xavfsiz kod" rejimida bu hujumlar ishlamaydi.</p>
                </div>
            </div>
        </div>
    </div>
</main>

<script>
    // Tab switching
    function showTab(tabName) {
        // Hide all tabs
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });

        // Hide all tab buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });

        // Show selected tab
        document.getElementById(tabName).classList.add('active');
        event.target.classList.add('active');
    }

    // Form validation
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            const demoType = this.querySelector('input[name="demo_type"]:checked')?.value ||
                this.querySelector('input[name="store_type"]:checked')?.value;

            if (demoType === 'vulnerable') {
                const userInput = this.querySelector('input[name="user_input"]')?.value ||
                    this.querySelector('input[name="title"]')?.value ||
                    this.querySelector('textarea[name="content"]')?.value;

                if (userInput && (userInput.includes('<script>') || userInput.includes('javascript:'))) {
                    if (!confirm('Bu kod XSS hujumi bo\'lishi mumkin. Davom etasizmi?')) {
                        e.preventDefault();
                    }
                }
            }
        });
    });
</script>
</body>
</html>