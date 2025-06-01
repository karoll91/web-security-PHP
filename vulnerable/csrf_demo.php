<?php
/**
 * CSRF Demo - Cross-Site Request Forgery namunalari
 * Web Security Project
 * ⚠️ FAQAT TA'LIM MAQSADIDA!
 */

require_once '../config/database.php';
require_once '../config/security.php';
require_once '../security/csrf_token.php';
require_once '../security/security_logger.php';

// Bu sahifa faqat login qilgan foydalanuvchilar uchun
if (!isset($_SESSION['user_id'])) {
    header('Location: ../auth/login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
}

$message = '';
$messageType = '';

// CSRF token yaratish
$csrfToken = CSRFToken::generate();

// Foydalanuvchi ma'lumotlarini olish
try {
    $db = getDB();
    $stmt = $db->prepare("SELECT username, email, full_name FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $currentUser = $stmt->fetch();
} catch (PDOException $e) {
    error_log("CSRF demo user fetch error: " . $e->getMessage());
    $currentUser = ['username' => 'unknown', 'email' => 'unknown', 'full_name' => 'Unknown'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'change_email_vulnerable') {
        // ⚠️ ZAIF KOD - CSRF himoyasiz
        $newEmail = SecurityConfig::sanitizeInput($_POST['new_email'] ?? '');

        if (SecurityConfig::validateInput($newEmail, 'email')) {
            try {
                $stmt = $db->prepare("UPDATE users SET email = ? WHERE id = ?");
                $stmt->execute([$newEmail, $_SESSION['user_id']]);

                $message = "Email manzil o'zgartirildi (CSRF himoyasiz): {$newEmail}";
                $messageType = 'warning';

                SecurityLogger::log('csrf_vulnerable_email_change', $_SESSION['user_id'], null, 'high',
                    "Email changed without CSRF protection: {$newEmail}");

                // Ma'lumotni yangilash
                $currentUser['email'] = $newEmail;

            } catch (PDOException $e) {
                $message = "Xatolik yuz berdi: " . $e->getMessage();
                $messageType = 'error';
            }
        } else {
            $message = "Email manzil noto'g'ri!";
            $messageType = 'error';
        }
    }

    if ($action === 'change_email_secure') {
        // ✅ XAVFSIZ KOD - CSRF token bilan
        if (!CSRFToken::verify($_POST['csrf_token'] ?? '')) {
            $message = "CSRF token noto'g'ri! Hujum oldini olindi.";
            $messageType = 'error';

            SecurityLogger::log('csrf_attack_prevented', $_SESSION['user_id'], null, 'high',
                'CSRF attack prevented on email change');
        } else {
            $newEmail = SecurityConfig::sanitizeInput($_POST['new_email'] ?? '');

            if (SecurityConfig::validateInput($newEmail, 'email')) {
                try {
                    $stmt = $db->prepare("UPDATE users SET email = ? WHERE id = ?");
                    $stmt->execute([$newEmail, $_SESSION['user_id']]);

                    $message = "Email manzil xavfsiz o'zgartirildi: {$newEmail}";
                    $messageType = 'success';

                    SecurityLogger::log('email_changed_secure', $_SESSION['user_id'], null, 'low',
                        "Email changed securely with CSRF protection: {$newEmail}");

                    // Ma'lumotni yangilash
                    $currentUser['email'] = $newEmail;

                } catch (PDOException $e) {
                    $message = "Xatolik yuz berdi: " . $e->getMessage();
                    $messageType = 'error';
                }
            } else {
                $message = "Email manzil noto'g'ri!";
                $messageType = 'error';
            }
        }
    }

    if ($action === 'delete_account_vulnerable') {
        // ⚠️ ZAIF KOD - Hisobni o'chirish (demo uchun faqat log)
        $message = "Hisob o'chirildi (CSRF himoyasiz) - DEMO REJIM!";
        $messageType = 'warning';

        SecurityLogger::log('csrf_vulnerable_account_delete', $_SESSION['user_id'], null, 'high',
            'Account deletion attempt without CSRF protection (demo)');
    }

    if ($action === 'delete_account_secure') {
        // ✅ XAVFSIZ KOD - CSRF token bilan
        if (!CSRFToken::verify($_POST['csrf_token'] ?? '')) {
            $message = "CSRF token noto'g'ri! Hujum oldini olindi.";
            $messageType = 'error';

            SecurityLogger::log('csrf_attack_prevented', $_SESSION['user_id'], null, 'high',
                'CSRF attack prevented on account deletion');
        } else {
            $message = "Hisob xavfsiz o'chirildi - DEMO REJIM!";
            $messageType = 'success';

            SecurityLogger::log('account_delete_secure', $_SESSION['user_id'], null, 'medium',
                'Account deletion with CSRF protection (demo)');
        }
    }
}
?>

<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSRF Demo - Web Security</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <meta name="csrf-token" content="<?= $csrfToken ?>">
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

        .attack-demo {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }

        .user-info {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }

        .form-row {
            display: flex;
            gap: 1rem;
            align-items: end;
        }

        .form-row .form-group {
            flex: 1;
        }

        .external-site {
            background: #ffe6e6;
            border: 2px dashed #e74c3c;
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1rem 0;
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
            <h1>🎭 CSRF (Cross-Site Request Forgery) Demo</h1>
            <div class="alert alert-warning">
                <strong>Ogohlantirish:</strong> Bu sahifa faqat ta'lim maqsadida yaratilgan.
                Real loyihalarda zaif kodlardan foydalanmang!
            </div>

            <!-- Current user info -->
            <div class="user-info">
                <h4>Joriy foydalanuvchi ma'lumotlari:</h4>
                <p><strong>Foydalanuvchi nomi:</strong> <?= SecurityConfig::sanitizeInput($currentUser['username']) ?></p>
                <p><strong>Email:</strong> <?= SecurityConfig::sanitizeInput($currentUser['email']) ?></p>
                <p><strong>To'liq ism:</strong> <?= SecurityConfig::sanitizeInput($currentUser['full_name']) ?></p>
            </div>

            <?php if ($message): ?>
                <div class="alert alert-<?= $messageType ?>">
                    <?= SecurityConfig::sanitizeInput($message) ?>
                </div>
            <?php endif; ?>

            <!-- Tabs -->
            <div class="demo-tabs">
                <button class="tab-button active" onclick="showTab('vulnerable')">Zaif kod</button>
                <button class="tab-button" onclick="showTab('secure')">Xavfsiz kod</button>
                <button class="tab-button" onclick="showTab('attack')">Hujum simulyatsiyasi</button>
                <button class="tab-button" onclick="showTab('prevention')">Himoya usullari</button>
            </div>
        </div>

        <!-- Zaif kod -->
        <div id="vulnerable" class="tab-content active">
            <div class="demo-section vulnerable">
                <h2>❌ Zaif kod (CSRF himoyasiz)</h2>

                <h3>Email manzilni o'zgartirish:</h3>
                <form method="POST" style="margin: 1rem 0;">
                    <input type="hidden" name="action" value="change_email_vulnerable">
                    <div class="form-row">
                        <div class="form-group">
                            <label for="new_email_vuln">Yangi email manzil:</label>
                            <input
                                type="email"
                                id="new_email_vuln"
                                name="new_email"
                                class="form-control"
                                placeholder="yangi@email.com"
                                required
                            >
                        </div>
                        <button type="submit" class="btn btn-danger">O'zgartirish (Zaif)</button>
                    </div>
                </form>

                <div class="code-block vulnerable-code">
<pre>// ZAIF KOD - CSRF himoyasiz
if ($_POST['action'] === 'change_email') {
    $newEmail = $_POST['new_email'];
    $stmt = $db->prepare("UPDATE users SET email = ? WHERE id = ?");
    $stmt->execute([$newEmail, $_SESSION['user_id']]);
    echo "Email o'zgartirildi!";
}</pre>
                </div>

                <h3>Hisobni o'chirish:</h3>
                <form method="POST" style="margin: 1rem 0;">
                    <input type="hidden" name="action" value="delete_account_vulnerable">
                    <button type="submit" class="btn btn-danger" onclick="return confirm('Hisobni o\'chirishni xohlaysizmi?')">
                        Hisobni o'chirish (Zaif)
                    </button>
                </form>

                <div class="alert alert-error">
                    <strong>Muammo:</strong> Bu formalar CSRF token ishlatmaydi, shuning uchun tashqi saytlardan
                    avtomatik so'rovlar yuborish mumkin!
                </div>
            </div>
        </div>

        <!-- Xavfsiz kod -->
        <div id="secure" class="tab-content">
            <div class="demo-section secure">
                <h2>✅ Xavfsiz kod (CSRF token bilan)</h2>

                <h3>Email manzilni o'zgartirish:</h3>
                <form method="POST" style="margin: 1rem 0;">
                    <input type="hidden" name="action" value="change_email_secure">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <div class="form-row">
                        <div class="form-group">
                            <label for="new_email_secure">Yangi email manzil:</label>
                            <input
                                type="email"
                                id="new_email_secure"
                                name="new_email"
                                class="form-control"
                                placeholder="yangi@email.com"
                                required
                            >
                        </div>
                        <button type="submit" class="btn btn-success">O'zgartirish (Xavfsiz)</button>
                    </div>
                </form>

                <div class="code-block secure-code">
<pre>// XAVFSIZ KOD - CSRF token bilan
if ($_POST['action'] === 'change_email') {
    if (!CSRFToken::verify($_POST['csrf_token'])) {
        die('CSRF token noto\'g\'ri!');
    }

    $newEmail = $_POST['new_email'];
    $stmt = $db->prepare("UPDATE users SET email = ? WHERE id = ?");
    $stmt->execute([$newEmail, $_SESSION['user_id']]);
    echo "Email xavfsiz o'zgartirildi!";
}</pre>
                </div>

                <h3>Hisobni o'chirish:</h3>
                <form method="POST" style="margin: 1rem 0;">
                    <input type="hidden" name="action" value="delete_account_secure">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <button type="submit" class="btn btn-success" onclick="return confirm('Hisobni o\'chirishni xohlaysizmi?')">
                        Hisobni o'chirish (Xavfsiz)
                    </button>
                </form>

                <div class="alert alert-success">
                    <strong>Himoya:</strong> Bu formalar CSRF token ishlatadi, shuning uchun faqat
                    haqiqiy foydalanuvchi so'rovlari qabul qilinadi!
                </div>
            </div>
        </div>

        <!-- Hujum simulyatsiyasi -->
        <div id="attack" class="tab-content">
            <div class="demo-section">
                <h2>⚔️ CSRF Hujum Simulyatsiyasi</h2>
                <p>Quyidagi kod tashqi saytda bo'lishi mumkin va foydalanuvchi uni ochganda avtomatik ishga tushadi:</p>

                <div class="external-site">
                    <h4>🌐 Tashqi sayt (hacker.com)</h4>
                    <p>Bu sayt foydalanuvchi bilmagan holda CSRF hujumini amalga oshiradi:</p>

                    <!-- Bu form yashirin bo'lishi mumkin -->
                    <form id="csrf-attack-form" method="POST" action="<?= $_SERVER['PHP_SELF'] ?>" style="border: 2px solid #e74c3c; padding: 1rem; border-radius: 8px;">
                        <input type="hidden" name="action" value="change_email_vulnerable">
                        <input type="hidden" name="new_email" value="hacker@evil.com">

                        <p><strong>Yashirin CSRF hujumi:</strong></p>
                        <p>Email avtomatik o'zgartiriladi: <code>hacker@evil.com</code></p>
                        <button type="submit" class="btn btn-danger">Hujumni amalga oshirish</button>
                    </form>

                    <div class="code-block vulnerable-code" style="margin-top: 1rem;">
<pre><!-- Tashqi saytdagi yashirin form -->
&lt;form method="POST" action="http://yoursite.com/csrf_demo.php"&gt;
    &lt;input type="hidden" name="action" value="change_email_vulnerable"&gt;
    &lt;input type="hidden" name="new_email" value="hacker@evil.com"&gt;
&lt;/form&gt;

&lt;script&gt;
// Sahifa yuklanganda avtomatik yuborish
document.forms[0].submit();
&lt;/script&gt;</pre>
                    </div>
                </div>

                <div class="alert alert-info">
                    <strong>Eslatma:</strong> Bu hujum faqat "Zaif kod" bo'limidagi formalarga ta'sir qiladi.
                    "Xavfsiz kod" CSRF token talab qilgani uchun himoyalangan.
                </div>
            </div>

            <!-- Avtomatik hujum -->
            <div class="demo-section">
                <h3>🤖 Avtomatik CSRF hujumi</h3>
                <p>Quyidagi tugma bosilganda JavaScript orqali yashirin hujum amalga oshiriladi:</p>

                <button onclick="performCSRFAttack()" class="btn btn-warning">
                    Avtomatik hujumni boshlash
                </button>

                <div class="code-block" style="margin-top: 1rem;">
<pre id="attack-log" style="height: 200px; overflow-y: auto; background: #000; color: #0f0; padding: 1rem;">
Hujum logi bu yerda ko'rsatiladi...
</pre>
                </div>
            </div>
        </div>

        <!-- Himoya usullari -->
        <div id="prevention" class="tab-content">
            <div class="demo-section">
                <h2>🛡️ CSRF dan himoyalanish usullari</h2>

                <h3>1. CSRF Token</h3>
                <div class="code-block secure-code">
<pre>// Token yaratish
$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;

// HTML formada
echo '&lt;input type="hidden" name="csrf_token" value="' . $csrf_token . '"&gt;';

// Tekshirish
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('CSRF token noto\'g\'ri!');
}</pre>
                </div>

                <h3>2. SameSite Cookie</h3>
                <div class="code-block secure-code">
<pre>// Cookie sozlamasi
setcookie('session_id', $session_id, [
    'samesite' => 'Strict', // yoki 'Lax'
    'secure' => true,
    'httponly' => true
]);</pre>
                </div>

                <h3>3. Referer Header tekshirish</h3>
                <div class="code-block secure-code">
<pre>// Referer tekshirish
$allowed_origins = ['https://yoursite.com', 'https://www.yoursite.com'];
$referer = $_SERVER['HTTP_REFERER'] ?? '';

if (!in_array(parse_url($referer, PHP_URL_HOST), $allowed_origins)) {
    die('Noto\'g\'ri referer!');
}</pre>
                </div>

                <h3>4. Custom Header talab qilish</h3>
                <div class="code-block secure-code">
<pre>// JavaScript da
fetch('/api/endpoint', {
    method: 'POST',
    headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRF-Token': csrfToken
    },
    body: formData
});

// PHP da
if (!isset($_SERVER['HTTP_X_REQUESTED_WITH'])) {
    die('AJAX so\'rov talab qilinadi!');
}</pre>
                </div>

                <h3>5. Double Submit Cookie</h3>
                <div class="code-block secure-code">
<pre>// Cookie va form fieldda bir xil token
setcookie('csrf_token', $token, ['samesite' => 'Strict']);

// Tekshirish
if ($_COOKIE['csrf_token'] !== $_POST['csrf_token']) {
    die('CSRF token mos kelmaydi!');
}</pre>
                </div>
            </div>
        </div>
    </div>
</main>

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

    // CSRF hujumini simulyatsiya qilish
    function performCSRFAttack() {
        const log = document.getElementById('attack-log');
        log.innerHTML = '';

        function addLog(message) {
            log.innerHTML += new Date().toLocaleTimeString() + ': ' + message + '\n';
            log.scrollTop = log.scrollHeight;
        }

        addLog('🔴 CSRF hujumi boshlandi...');
        addLog('🔍 Maqsadli saytni tekshirish...');

        setTimeout(() => {
            addLog('📝 Yashirin forma yaratilmoqda...');

            // Yashirin forma yaratish
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = window.location.href;
            form.style.display = 'none';

            // Hidden inputlar
            const actionInput = document.createElement('input');
            actionInput.type = 'hidden';
            actionInput.name = 'action';
            actionInput.value = 'change_email_vulnerable';
            form.appendChild(actionInput);

            const emailInput = document.createElement('input');
            emailInput.type = 'hidden';
            emailInput.name = 'new_email';
            emailInput.value = 'attacker@evil.com';
            form.appendChild(emailInput);

            document.body.appendChild(form);

            addLog('⚡ Forma yaratildi va yuborilmoqda...');

            setTimeout(() => {
                if (confirm('Haqiqiy CSRF hujumini amalga oshirasizmi? (Bu sizning email manzilingizni o\'zgartiradi!)')) {
                    form.submit();
                } else {
                    addLog('❌ Hujum foydalanuvchi tomonidan to\'xtatildi');
                    addLog('ℹ️  Haqiqiy hujumda foydalanuvchi bilmaydi!');
                }
            }, 1000);

        }, 1500);
    }

    // Form submission warning
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            const action = this.querySelector('input[name="action"]')?.value;

            if (action && action.includes('vulnerable')) {
                if (!confirm('Bu zaif kod! Davom etasizmi?')) {
                    e.preventDefault();
                }
            }
        });
    });
</script>
</body>
</html>