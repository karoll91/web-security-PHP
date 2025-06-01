<?php
/**
 * Xavfsizlik sozlamalari
 * Web Security Project
 */

// Session sozlamalari - xavfsizlik uchun
ini_set('session.cookie_httponly', 1); // JavaScript orqali cookie'ga kirish taqiqlash
ini_set('session.cookie_secure', 0);   // HTTPS uchun 1 ga o'zgartiring
ini_set('session.use_strict_mode', 1); // Session ID xavfsizligini oshirish
ini_set('session.cookie_samesite', 'Strict'); // CSRF himoyasi

// Xatoliklarni yashirish (production uchun)
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/../logs/errors.log');

// Security constants
define('CSRF_TOKEN_EXPIRE', 3600); // 1 soat
define('MAX_LOGIN_ATTEMPTS', 5);
define('ACCOUNT_LOCK_TIME', 900); // 15 daqiqa
define('SESSION_TIMEOUT', 1800); // 30 daqiqa
define('RATE_LIMIT_WINDOW', 300); // 5 daqiqa

class SecurityConfig {

    /**
     * Xavfsizlik headerlari o'rnatish
     */
    public static function setSecurityHeaders() {
        // XSS himoyasi
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY'); // Clickjacking himoyasi
        header('X-XSS-Protection: 1; mode=block');

        // Content Security Policy (CSP)
        $csp = "default-src 'self'; ";
        $csp .= "script-src 'self' 'unsafe-inline'; ";
        $csp .= "style-src 'self' 'unsafe-inline'; ";
        $csp .= "img-src 'self' data: https:; ";
        $csp .= "font-src 'self'; ";
        $csp .= "connect-src 'self'; ";
        $csp .= "frame-ancestors 'none';";

        header('Content-Security-Policy: ' . $csp);

        // Referrer Policy
        header('Referrer-Policy: strict-origin-when-cross-origin');

        // Strict Transport Security (HTTPS uchun)
        // header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }

    /**
     * Sessionni xavfsiz boshlash
     */
    public static function startSecureSession() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        // Session hijacking himoyasi
        if (!isset($_SESSION['created'])) {
            $_SESSION['created'] = time();
        } else if (time() - $_SESSION['created'] > SESSION_TIMEOUT) {
            session_destroy();
            session_start();
        }

        // Session fixation himoyasi
        if (!isset($_SESSION['regenerated'])) {
            session_regenerate_id(true);
            $_SESSION['regenerated'] = time();
        } else if (time() - $_SESSION['regenerated'] > 300) { // Har 5 daqiqada
            session_regenerate_id(true);
            $_SESSION['regenerated'] = time();
        }
    }

    /**
     * Ma'lumotni tozalash (XSS himoyasi)
     */
    public static function sanitizeInput($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);
        }

        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
        return $data;
    }

    /**
     * Ma'lumotni tekshirish
     */
    public static function validateInput($data, $type) {
        switch ($type) {
            case 'email':
                return filter_var($data, FILTER_VALIDATE_EMAIL) !== false;
            case 'username':
                return preg_match('/^[a-zA-Z0-9_]{3,20}$/', $data);
            case 'password':
                return strlen($data) >= 6; // Minimal parol uzunligi
            case 'text':
                return strlen(trim($data)) > 0;
            default:
                return false;
        }
    }

    /**
     * Kuchli parol tekshirish
     */
    public static function isStrongPassword($password) {
        // Kamida 8 ta belgi, katta va kichik harf, raqam
        $uppercase = preg_match('@[A-Z]@', $password);
        $lowercase = preg_match('@[a-z]@', $password);
        $number = preg_match('@[0-9]@', $password);
        $specialChars = preg_match('@[^\w]@', $password);

        return strlen($password) >= 8 && $uppercase && $lowercase && $number;
    }

    /**
     * IP manzilni olish
     */
    public static function getClientIP() {
        $ipKeys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];

        foreach ($ipKeys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP,
                            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    /**
     * User Agent olish
     */
    public static function getUserAgent() {
        return $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    }
}

// Xavfsizlik sozlamalarini qo'llash
SecurityConfig::setSecurityHeaders();
SecurityConfig::startSecureSession();
?>