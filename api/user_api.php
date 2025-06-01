<?php
/**
 * User API - Foydalanuvchi API endpointlari
 * Web Security Project
 */

require_once '../config/database.php';
require_once '../config/security.php';
require_once '../security/csrf_token.php';
require_once '../security/security_logger.php';
require_once '../security/rate_limiter.php';

// API response headers
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// CORS headers (agar kerak bo'lsa)
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-CSRF-Token');

// OPTIONS request uchun
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Error handling function
function apiError($message, $code = 400, $details = null) {
    http_response_code($code);
    $response = array(
        'success' => false,
        'error' => $message,
        'timestamp' => date('c')
    );
    if ($details) {
        $response['details'] = $details;
    }
    echo json_encode($response);
    exit();
}

// Success response function
function apiSuccess($data = null, $message = 'Success') {
    $response = array(
        'success' => true,
        'message' => $message,
        'timestamp' => date('c')
    );
    if ($data !== null) {
        $response['data'] = $data;
    }
    echo json_encode($response);
    exit();
}

// Rate limiting
$clientIP = SecurityConfig::getClientIP();
$rateLimiter = new RateLimiter();

if ($rateLimiter->isBlocked($clientIP, 'api')) {
    SecurityLogger::log('api_rate_limited', null, $clientIP, 'high', 'API rate limit exceeded');
    apiError('Too many requests. Please try again later.', 429);
}

// Login tekshirish (ba'zi endpointlar uchun)
function requireAuth() {
    if (!isset($_SESSION['user_id'])) {
        apiError('Authentication required', 401);
    }
}

// Admin huquqi tekshirish
function requireAdmin() {
    requireAuth();
    if ($_SESSION['role'] !== 'admin') {
        apiError('Admin access required', 403);
    }
}

// CSRF token tekshirish (POST/PUT/DELETE uchun)
function checkCSRF() {
    if (in_array($_SERVER['REQUEST_METHOD'], array('POST', 'PUT', 'DELETE'))) {
        $token = null;

        // Header dan olish
        if (isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
            $token = $_SERVER['HTTP_X_CSRF_TOKEN'];
        }
        // POST dan olish
        elseif (isset($_POST['csrf_token'])) {
            $token = $_POST['csrf_token'];
        }
        // JSON dan olish
        else {
            $input = json_decode(file_get_contents('php://input'), true);
            if (isset($input['csrf_token'])) {
                $token = $input['csrf_token'];
            }
        }

        if (!CSRFToken::verify($token)) {
            SecurityLogger::log('api_csrf_invalid', isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null,
                $GLOBALS['clientIP'], 'high', 'Invalid CSRF token in API request');
            apiError('Invalid CSRF token', 403);
        }
    }
}

// URL routing
$request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
$path = parse_url($request_uri, PHP_URL_PATH);
$path_parts = explode('/', trim($path, '/'));

// API version va endpoint olish
$endpoint = '';
if (count($path_parts) >= 2) {
    $endpoint = $path_parts[count($path_parts) - 1]; // Oxirgi qism
}

$method = $_SERVER['REQUEST_METHOD'];

// Rate limiting yozish
$rateLimiter->recordAttempt($clientIP, 'api');

try {
    $db = getDB();

    // API Endpoints
    switch ($endpoint) {

        // GET /api/user_api.php/profile - Profil ma'lumotlari
        case 'profile':
            if ($method === 'GET') {
                requireAuth();

                $stmt = $db->prepare("
                    SELECT id, username, email, full_name, role, created_at, last_login 
                    FROM users 
                    WHERE id = ?
                ");
                $stmt->execute(array($_SESSION['user_id']));
                $user = $stmt->fetch();

                if (!$user) {
                    apiError('User not found', 404);
                }

                // Parolni yashirish
                unset($user['password_hash']);

                apiSuccess($user, 'Profile retrieved successfully');

            } elseif ($method === 'PUT') {
                // PUT /api/user_api.php/profile - Profilni yangilash
                requireAuth();
                checkCSRF();

                $input = json_decode(file_get_contents('php://input'), true);

                $fullName = isset($input['full_name']) ? SecurityConfig::sanitizeInput($input['full_name']) : '';
                $email = isset($input['email']) ? SecurityConfig::sanitizeInput($input['email']) : '';

                if (empty($fullName) || empty($email)) {
                    apiError('Full name and email are required');
                }

                if (!SecurityConfig::validateInput($email, 'email')) {
                    apiError('Invalid email format');
                }

                // Email mavjudligini tekshirish
                $stmt = $db->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                $stmt->execute(array($email, $_SESSION['user_id']));
                if ($stmt->fetch()) {
                    apiError('Email already exists');
                }

                // Yangilash
                $stmt = $db->prepare("UPDATE users SET full_name = ?, email = ? WHERE id = ?");
                $stmt->execute(array($fullName, $email, $_SESSION['user_id']));

                SecurityLogger::log('profile_updated_api', $_SESSION['user_id'], $clientIP, 'low',
                    "Profile updated via API: {$fullName}, {$email}");

                apiSuccess(null, 'Profile updated successfully');
            }
            break;

        // POST /api/user_api.php/change-password - Parolni o'zgartirish
        case 'change-password':
            if ($method === 'POST') {
                requireAuth();
                checkCSRF();

                $input = json_decode(file_get_contents('php://input'), true);

                $currentPassword = isset($input['current_password']) ? $input['current_password'] : '';
                $newPassword = isset($input['new_password']) ? $input['new_password'] : '';

                if (empty($currentPassword) || empty($newPassword)) {
                    apiError('Current password and new password are required');
                }

                if (!SecurityConfig::isStrongPassword($newPassword)) {
                    apiError('Password must be at least 8 characters with uppercase, lowercase, and numbers');
                }

                // Joriy parolni tekshirish
                $stmt = $db->prepare("SELECT password_hash FROM users WHERE id = ?");
                $stmt->execute(array($_SESSION['user_id']));
                $user = $stmt->fetch();

                if (!password_verify($currentPassword, $user['password_hash'])) {
                    SecurityLogger::log('api_password_change_failed', $_SESSION['user_id'], $clientIP, 'medium',
                        'Failed password change via API - wrong current password');
                    apiError('Current password is incorrect');
                }

                // Yangi parolni o'rnatish
                $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
                $stmt = $db->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
                $stmt->execute(array($newPasswordHash, $_SESSION['user_id']));

                SecurityLogger::log('password_changed_api', $_SESSION['user_id'], $clientIP, 'low',
                    'Password changed via API');

                apiSuccess(null, 'Password changed successfully');
            }
            break;

        // GET /api/user_api.php/activity - Foydalanuvchi faoliyati
        case 'activity':
            if ($method === 'GET') {
                requireAuth();

                $limit = isset($_GET['limit']) ? min(100, max(1, (int)$_GET['limit'])) : 20;

                $logs = SecurityLogger::getUserActivity($_SESSION['user_id'], $limit);

                // Ma'lumotlarni formatlash
                $formattedLogs = array();
                foreach ($logs as $log) {
                    $formattedLogs[] = array(
                        'action_type' => $log['action_type'],
                        'ip_address' => $log['ip_address'],
                        'risk_level' => $log['risk_level'],
                        'details' => $log['details'],
                        'timestamp' => $log['timestamp']
                    );
                }

                apiSuccess($formattedLogs, 'Activity logs retrieved successfully');
            }
            break;

        // GET /api/user_api.php/csrf-token - CSRF token olish
        case 'csrf-token':
            if ($method === 'GET') {
                $token = CSRFToken::generate(isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null);
                apiSuccess(array(
                    'token' => $token,
                    'expires_in' => CSRF_TOKEN_EXPIRE
                ), 'CSRF token generated');
            }
            break;

        // POST /api/user_api.php/extend-session - Session uzaytirish
        case 'extend-session':
            if ($method === 'POST') {
                requireAuth();

                // Session ni yangilash
                $_SESSION['last_activity'] = time();
                session_regenerate_id(false);

                SecurityLogger::log('session_extended_api', $_SESSION['user_id'], $clientIP, 'low',
                    'Session extended via API');

                apiSuccess(array(
                    'expires_in' => SESSION_TIMEOUT
                ), 'Session extended successfully');
            }
            break;

        // GET /api/user_api.php/check-auth - Autentifikatsiya holati
        case 'check-auth':
            if ($method === 'GET') {
                if (isset($_SESSION['user_id'])) {
                    $stmt = $db->prepare("SELECT username, role FROM users WHERE id = ? AND is_active = 1");
                    $stmt->execute(array($_SESSION['user_id']));
                    $user = $stmt->fetch();

                    if ($user) {
                        apiSuccess(array(
                            'authenticated' => true,
                            'user' => array(
                                'id' => $_SESSION['user_id'],
                                'username' => $user['username'],
                                'role' => $user['role']
                            )
                        ), 'User is authenticated');
                    } else {
                        // Session mavjud lekin user yo'q/nofaol
                        session_destroy();
                        apiSuccess(array('authenticated' => false), 'User not authenticated');
                    }
                } else {
                    apiSuccess(array('authenticated' => false), 'User not authenticated');
                }
            }
            break;

        // Admin endpoints
        case 'admin-stats':
            if ($method === 'GET') {
                requireAdmin();

                // Foydalanuvchilar statistikasi
                $stmt = $db->query("
                    SELECT 
                        COUNT(*) as total_users,
                        SUM(is_active) as active_users,
                        SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_users,
                        SUM(CASE WHEN locked_until > NOW() THEN 1 ELSE 0 END) as locked_users
                    FROM users
                ");
                $userStats = $stmt->fetch();

                // Xavfsizlik statistikasi
                $securityStats = SecurityLogger::getStatistics(24);

                // Shubhali IP lar
                $suspiciousIPs = SecurityLogger::getSuspiciousIPs(24, 5);

                apiSuccess(array(
                    'users' => $userStats,
                    'security' => $securityStats,
                    'suspicious_ips' => $suspiciousIPs
                ), 'Admin statistics retrieved');
            }
            break;

        default:
            // API dokumentatsiyasi
            if (empty($endpoint) && $method === 'GET') {
                $documentation = array(
                    'name' => 'Web Security User API',
                    'version' => '1.0',
                    'endpoints' => array(
                        'GET /profile' => 'Get user profile',
                        'PUT /profile' => 'Update user profile',
                        'POST /change-password' => 'Change user password',
                        'GET /activity' => 'Get user activity logs',
                        'GET /csrf-token' => 'Get CSRF token',
                        'POST /extend-session' => 'Extend user session',
                        'GET /check-auth' => 'Check authentication status',
                        'GET /admin-stats' => 'Get admin statistics (admin only)'
                    ),
                    'authentication' => 'Session-based authentication required for most endpoints',
                    'csrf' => 'CSRF token required for POST/PUT/DELETE requests',
                    'rate_limiting' => 'API calls are rate limited per IP address'
                );

                apiSuccess($documentation, 'API documentation');
            } else {
                apiError('Endpoint not found', 404);
            }
            break;
    }

} catch (PDOException $e) {
    error_log("User API database error: " . $e->getMessage());
    SecurityLogger::log('api_database_error', isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null,
        $clientIP, 'high', 'Database error in User API: ' . $e->getMessage());
    apiError('Database error occurred', 500);

} catch (Exception $e) {
    error_log("User API general error: " . $e->getMessage());
    SecurityLogger::log('api_general_error', isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null,
        $clientIP, 'high', 'General error in User API: ' . $e->getMessage());
    apiError('An error occurred', 500);
}
?>