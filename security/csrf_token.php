<?php
/**
 * CSRF Token - Cross-Site Request Forgery himoyasi
 * Web Security Project
 */

class CSRFToken {
    private static $db;

    public static function init() {
        self::$db = getDB();
    }

    /**
     * Yangi CSRF token yaratish
     */
    public static function generate($userId = null) {
        if (!self::$db) {
            self::init();
        }

        // Foydalanuvchi ID ni olish
        if (!$userId && isset($_SESSION['user_id'])) {
            $userId = $_SESSION['user_id'];
        }

        // Session-based token (guest foydalanuvchilar uchun)
        if (!$userId) {
            return self::generateSessionToken();
        }

        try {
            // Eski tokenlarni tozalash
            self::cleanupExpiredTokens($userId);

            // Yangi token yaratish
            $token = bin2hex(random_bytes(32));
            $expiresAt = date('Y-m-d H:i:s', time() + CSRF_TOKEN_EXPIRE);

            // Ma'lumotlar bazasiga saqlash
            $stmt = self::$db->prepare("
                INSERT INTO csrf_tokens (user_id, token, expires_at) 
                VALUES (?, ?, ?)
            ");
            $stmt->execute([$userId, $token, $expiresAt]);

            return $token;

        } catch (PDOException $e) {
            error_log("CSRF token generation error: " . $e->getMessage());
            // Fallback - session token
            return self::generateSessionToken();
        }
    }

    /**
     * Session-based token yaratish (guest uchun)
     */
    private static function generateSessionToken() {
        if (!isset($_SESSION['csrf_tokens'])) {
            $_SESSION['csrf_tokens'] = [];
        }

        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_tokens'][$token] = time() + CSRF_TOKEN_EXPIRE;

        // Eski tokenlarni tozalash
        foreach ($_SESSION['csrf_tokens'] as $t => $expires) {
            if ($expires < time()) {
                unset($_SESSION['csrf_tokens'][$t]);
            }
        }

        return $token;
    }

    /**
     * CSRF token ni tekshirish
     */
    public static function verify($token, $userId = null) {
        if (empty($token)) {
            return false;
        }

        if (!self::$db) {
            self::init();
        }

        // Foydalanuvchi ID ni olish
        if (!$userId && isset($_SESSION['user_id'])) {
            $userId = $_SESSION['user_id'];
        }

        // Session-based token tekshirish (guest uchun)
        if (!$userId) {
            return self::verifySessionToken($token);
        }

        try {
            // Ma'lumotlar bazasidan tekshirish
            $stmt = self::$db->prepare("
                SELECT id FROM csrf_tokens 
                WHERE user_id = ? AND token = ? AND expires_at > NOW()
            ");
            $stmt->execute([$userId, $token]);
            $result = $stmt->fetch();

            if ($result) {
                // Ishlatilgan tokenni o'chirish (one-time use)
                $stmt = self::$db->prepare("DELETE FROM csrf_tokens WHERE id = ?");
                $stmt->execute([$result['id']]);
                return true;
            }

            return false;

        } catch (PDOException $e) {
            error_log("CSRF token verification error: " . $e->getMessage());
            // Fallback - session token
            return self::verifySessionToken($token);
        }
    }

    /**
     * Session-based token ni tekshirish
     */
    private static function verifySessionToken($token) {
        if (!isset($_SESSION['csrf_tokens'][$token])) {
            return false;
        }

        $expires = $_SESSION['csrf_tokens'][$token];
        if ($expires < time()) {
            unset($_SESSION['csrf_tokens'][$token]);
            return false;
        }

        // One-time use
        unset($_SESSION['csrf_tokens'][$token]);
        return true;
    }

    /**
     * Muddati o'tgan tokenlarni tozalash
     */
    public static function cleanupExpiredTokens($userId = null) {
        if (!self::$db) {
            self::init();
        }

        try {
            if ($userId) {
                $stmt = self::$db->prepare("
                    DELETE FROM csrf_tokens 
                    WHERE user_id = ? AND expires_at < NOW()
                ");
                $stmt->execute([$userId]);
            } else {
                $stmt = self::$db->prepare("
                    DELETE FROM csrf_tokens 
                    WHERE expires_at < NOW()
                ");
                $stmt->execute();
            }

        } catch (PDOException $e) {
            error_log("CSRF token cleanup error: " . $e->getMessage());
        }
    }

    /**
     * Form uchun hidden input yaratish
     */
    public static function getHiddenInput($userId = null) {
        $token = self::generate($userId);
        return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
    }

    /**
     * Meta tag yaratish (AJAX uchun)
     */
    public static function getMetaTag($userId = null) {
        $token = self::generate($userId);
        return '<meta name="csrf-token" content="' . htmlspecialchars($token) . '">';
    }

    /**
     * JavaScript o'zgaruvchisi yaratish
     */
    public static function getJavaScriptVariable($userId = null) {
        $token = self::generate($userId);
        return '<script>window.csrfToken = "' . htmlspecialchars($token) . '";</script>';
    }

    /**
     * AJAX uchun token olish (API endpoint)
     */
    public static function getTokenForAjax() {
        header('Content-Type: application/json');

        $userId = $_SESSION['user_id'] ?? null;
        $token = self::generate($userId);

        echo json_encode([
            'success' => true,
            'token' => $token,
            'expires_in' => CSRF_TOKEN_EXPIRE
        ]);
    }

    /**
     * Foydalanuvchining barcha tokenlarini o'chirish (logout da)
     */
    public static function clearUserTokens($userId) {
        if (!self::$db) {
            self::init();
        }

        try {
            $stmt = self::$db->prepare("DELETE FROM csrf_tokens WHERE user_id = ?");
            $stmt->execute([$userId]);

            // Session tokenlarini ham tozalash
            if (isset($_SESSION['csrf_tokens'])) {
                unset($_SESSION['csrf_tokens']);
            }

        } catch (PDOException $e) {
            error_log("CSRF clear user tokens error: " . $e->getMessage());
        }
    }

    /**
     * Token statistikalarini olish (admin uchun)
     */
    public static function getTokenStatistics() {
        if (!self::$db) {
            self::init();
        }

        try {
            $stmt = self::$db->prepare("
                SELECT 
                    COUNT(*) as total_tokens,
                    COUNT(DISTINCT user_id) as unique_users,
                    SUM(CASE WHEN expires_at > NOW() THEN 1 ELSE 0 END) as active_tokens,
                    SUM(CASE WHEN expires_at <= NOW() THEN 1 ELSE 0 END) as expired_tokens
                FROM csrf_tokens
            ");
            $stmt->execute();
            return $stmt->fetch();

        } catch (PDOException $e) {
            error_log("CSRF token statistics error: " . $e->getMessage());
            return [
                'total_tokens' => 0,
                'unique_users' => 0,
                'active_tokens' => 0,
                'expired_tokens' => 0
            ];
        }
    }

    /**
     * Middleware - forma yuborishdan oldin tekshirish
     */
    public static function validateRequest() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';

            if (!self::verify($token)) {
                http_response_code(403);
                die('CSRF token invalid. Please refresh the page and try again.');
            }
        }
    }
}

// Avtomatik tozalash (har safar class yuklanganda)
if (rand(1, 100) === 1) { // 1% ehtimol bilan
    CSRFToken::cleanupExpiredTokens();
}

// AJAX token endpoint
if (basename($_SERVER['PHP_SELF']) === 'csrf_token.php' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    require_once '../config/database.php';
    require_once '../config/security.php';
    CSRFToken::getTokenForAjax();
    exit;
}
?>