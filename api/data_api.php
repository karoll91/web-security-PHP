<?php
/**
 * Data API - Ma'lumotlar API endpointlari
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

// CORS headers
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

// Login tekshirish
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

// CSRF token tekshirish
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
                $GLOBALS['clientIP'], 'high', 'Invalid CSRF token in Data API request');
            apiError('Invalid CSRF token', 403);
        }
    }
}

// URL routing
$request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
$path = parse_url($request_uri, PHP_URL_PATH);
$path_parts = explode('/', trim($path, '/'));

$endpoint = '';
if (count($path_parts) >= 2) {
    $endpoint = $path_parts[count($path_parts) - 1];
}

$method = $_SERVER['REQUEST_METHOD'];

// Rate limiting yozish
$rateLimiter->recordAttempt($clientIP, 'api');

try {
    $db = getDB();

    // API Endpoints
    switch ($endpoint) {

        // GET /api/data_api.php/posts - Foydalanuvchi postlari
        case 'posts':
            if ($method === 'GET') {
                requireAuth();

                $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
                $limit = isset($_GET['limit']) ? min(50, max(1, (int)$_GET['limit'])) : 10;
                $offset = ($page - 1) * $limit;

                // Jami postlar soni
                $stmt = $db->prepare("SELECT COUNT(*) as total FROM user_data WHERE user_id = ?");
                $stmt->execute(array($_SESSION['user_id']));
                $total = $stmt->fetch();
                $total = $total['total'];

                // Foydalanuvchilar ro'yxati
                $stmt = $db->prepare("
                    SELECT id, username, email, full_name, role, created_at, last_login, is_active 
                    FROM users 
                    ORDER BY created_at DESC 
                    LIMIT ? OFFSET ?
                ");
                $stmt->execute(array($limit, $offset));
                $users = $stmt->fetchAll();

                apiSuccess(array(
                    'users' => $users,
                    'pagination' => array(
                        'current_page' => $page,
                        'total_pages' => ceil($total / $limit),
                        'total_items' => $total,
                        'items_per_page' => $limit
                    )
                ), 'Users retrieved successfully');
            }
            break;

        // GET /api/data_api.php/stats - Umumiy statistikalar
        case 'stats':
            if ($method === 'GET') {
                requireAuth();

                // Foydalanuvchi statistikasi
                $stmt = $db->prepare("SELECT COUNT(*) as total_posts FROM user_data WHERE user_id = ?");
                $stmt->execute(array($_SESSION['user_id']));
                $userStats = $stmt->fetch();

                // Oxirgi faollik
                $logs = SecurityLogger::getUserActivity($_SESSION['user_id'], 5);

                apiSuccess(array(
                    'user_stats' => array(
                        'total_posts' => $userStats['total_posts'],
                        'last_login' => isset($_SESSION['login_time']) ? date('c', $_SESSION['login_time']) : null
                    ),
                    'recent_activity' => $logs
                ), 'Statistics retrieved successfully');
            }
            break;

        // GET /api/data_api.php/export - Ma'lumotlarni export qilish
        case 'export':
            if ($method === 'GET') {
                requireAuth();

                $format = isset($_GET['format']) ? $_GET['format'] : 'json';

                // Foydalanuvchi postlarini olish
                $stmt = $db->prepare("
                    SELECT title, content, created_at 
                    FROM user_data 
                    WHERE user_id = ? 
                    ORDER BY created_at ASC
                ");
                $stmt->execute(array($_SESSION['user_id']));
                $posts = $stmt->fetchAll();

                if ($format === 'csv') {
                    header('Content-Type: text/csv');
                    header('Content-Disposition: attachment; filename="user_data_export_' . date('Y-m-d') . '.csv"');

                    $output = "Title,Content,Created At\n";
                    foreach ($posts as $post) {
                        $output .= '"' . str_replace('"', '""', $post['title']) . '",';
                        $output .= '"' . str_replace('"', '""', $post['content']) . '",';
                        $output .= '"' . $post['created_at'] . '"' . "\n";
                    }

                    echo $output;

                    SecurityLogger::log('data_export_csv', $_SESSION['user_id'], $clientIP, 'low',
                        'User data exported as CSV');
                    exit();

                } else {
                    // JSON export
                    SecurityLogger::log('data_export_json', $_SESSION['user_id'], $clientIP, 'low',
                        'User data exported as JSON');

                    apiSuccess(array(
                        'export_format' => 'json',
                        'export_date' => date('c'),
                        'total_items' => count($posts),
                        'data' => $posts
                    ), 'Data exported successfully');
                }
            }
            break;

        // POST /api/data_api.php/backup - Ma'lumotlarni backup qilish
        case 'backup':
            if ($method === 'POST') {
                requireAuth();
                checkCSRF();

                // Foydalanuvchi barcha ma'lumotlarini olish
                $stmt = $db->prepare("
                    SELECT u.username, u.email, u.full_name, u.created_at as user_created_at,
                           d.title, d.content, d.created_at as post_created_at
                    FROM users u
                    LEFT JOIN user_data d ON u.id = d.user_id
                    WHERE u.id = ?
                    ORDER BY d.created_at ASC
                ");
                $stmt->execute(array($_SESSION['user_id']));
                $backupData = $stmt->fetchAll();

                // Backup ma'lumotini formatlash
                $backup = array(
                    'backup_date' => date('c'),
                    'user_info' => array(
                        'username' => $backupData[0]['username'],
                        'email' => $backupData[0]['email'],
                        'full_name' => $backupData[0]['full_name'],
                        'created_at' => $backupData[0]['user_created_at']
                    ),
                    'posts' => array()
                );

                foreach ($backupData as $row) {
                    if ($row['title']) {
                        $backup['posts'][] = array(
                            'title' => $row['title'],
                            'content' => $row['content'],
                            'created_at' => $row['post_created_at']
                        );
                    }
                }

                SecurityLogger::log('data_backup', $_SESSION['user_id'], $clientIP, 'low',
                    'User data backup created');

                apiSuccess($backup, 'Backup created successfully');
            }
            break;

        // POST /api/data_api.php/validate - Ma'lumotlarni validatsiya qilish
        case 'validate':
            if ($method === 'POST') {
                $input = json_decode(file_get_contents('php://input'), true);

                $type = isset($input['type']) ? $input['type'] : '';
                $value = isset($input['value']) ? $input['value'] : '';

                $isValid = false;
                $message = '';

                switch ($type) {
                    case 'email':
                        $isValid = SecurityConfig::validateInput($value, 'email');
                        $message = $isValid ? 'Valid email format' : 'Invalid email format';
                        break;

                    case 'username':
                        $isValid = SecurityConfig::validateInput($value, 'username');
                        $message = $isValid ? 'Valid username format' : 'Invalid username format (3-20 chars, letters, numbers, underscore)';
                        break;

                    case 'password':
                        $isValid = SecurityConfig::isStrongPassword($value);
                        $message = $isValid ? 'Strong password' : 'Password must be at least 8 characters with uppercase, lowercase, and numbers';
                        break;

                    default:
                        apiError('Invalid validation type');
                }

                apiSuccess(array(
                    'type' => $type,
                    'value' => substr($value, 0, 50), // Qisqartirib ko'rsatish
                    'is_valid' => $isValid,
                    'message' => $message
                ), 'Validation completed');
            }
            break;

        default:
            // API dokumentatsiyasi
            if (empty($endpoint) && $method === 'GET') {
                $documentation = array(
                    'name' => 'Web Security Data API',
                    'version' => '1.0',
                    'endpoints' => array(
                        'GET /posts' => 'Get user posts with pagination',
                        'POST /posts' => 'Create new post',
                        'GET /post/{id}' => 'Get specific post',
                        'PUT /post/{id}' => 'Update specific post',
                        'DELETE /post/{id}' => 'Delete specific post',
                        'GET /search' => 'Search posts',
                        'GET /stats' => 'Get user statistics',
                        'GET /export' => 'Export user data (JSON/CSV)',
                        'POST /backup' => 'Create data backup',
                        'POST /validate' => 'Validate input data',
                        'GET /admin-logs' => 'Get security logs (admin only)',
                        'GET /admin-users' => 'Get users list (admin only)'
                    ),
                    'authentication' => 'Session-based authentication required',
                    'csrf' => 'CSRF token required for POST/PUT/DELETE requests',
                    'rate_limiting' => 'API calls are rate limited per IP address',
                    'pagination' => 'Use page and limit parameters for pagination',
                    'security' => 'All input data is sanitized and validated'
                );

                apiSuccess($documentation, 'Data API documentation');
            } else {
                apiError('Endpoint not found', 404);
            }
            break;
    }

} catch (PDOException $e) {
    error_log("Data API database error: " . $e->getMessage());
    SecurityLogger::log('api_database_error', isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null,
        $clientIP, 'high', 'Database error in Data API: ' . $e->getMessage());
    apiError('Database error occurred', 500);

} catch (Exception $e) {
    error_log("Data API general error: " . $e->getMessage());
    SecurityLogger::log('api_general_error', isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null,
        $clientIP, 'high', 'General error in Data API: ' . $e->getMessage());
    apiError('An error occurred', 500);
}
?>['total'];

// Postlarni olish
$stmt = $db->prepare("
SELECT id, title, content, created_at
FROM user_data
WHERE user_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?
");
$stmt->execute(array($_SESSION['user_id'], $limit, $offset));
$posts = $stmt->fetchAll();

apiSuccess(array(
'posts' => $posts,
'pagination' => array(
'current_page' => $page,
'total_pages' => ceil($total / $limit),
'total_items' => $total,
'items_per_page' => $limit
)
), 'Posts retrieved successfully');

} elseif ($method === 'POST') {
// POST /api/data_api.php/posts - Yangi post yaratish
requireAuth();
checkCSRF();

$input = json_decode(file_get_contents('php://input'), true);

$title = isset($input['title']) ? SecurityConfig::sanitizeInput($input['title']) : '';
$content = isset($input['content']) ? SecurityConfig::sanitizeInput($input['content']) : '';
$secure = isset($input['secure']) ? (bool)$input['secure'] : true;

if (empty($title) || empty($content)) {
apiError('Title and content are required');
}

// Xavfsizlik tekshirish
if ($secure) {
// XSS himoyasi
$title = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
$content = htmlspecialchars($content, ENT_QUOTES, 'UTF-8');
}

// Post yaratish
$stmt = $db->prepare("INSERT INTO user_data (user_id, title, content) VALUES (?, ?, ?)");
$stmt->execute(array($_SESSION['user_id'], $title, $content));
$postId = $db->lastInsertId();

SecurityLogger::log('post_created_api', $_SESSION['user_id'], $clientIP, 'low',
"Post created via API: {$title}");

apiSuccess(array(
'post_id' => $postId,
'title' => $title,
'content' => $content
), 'Post created successfully');
}
break;

// GET/PUT/DELETE /api/data_api.php/post/{id} - Alohida post bilan ishlash
case (preg_match('/^post\/(\d+)$/', $endpoint, $matches) ? true : false):
$postId = isset($matches[1]) ? (int)$matches[1] : 0;

if ($method === 'GET') {
requireAuth();

$stmt = $db->prepare("
SELECT id, title, content, created_at
FROM user_data
WHERE id = ? AND user_id = ?
");
$stmt->execute(array($postId, $_SESSION['user_id']));
$post = $stmt->fetch();

if (!$post) {
apiError('Post not found', 404);
}

apiSuccess($post, 'Post retrieved successfully');

} elseif ($method === 'PUT') {
requireAuth();
checkCSRF();

$input = json_decode(file_get_contents('php://input'), true);

$title = isset($input['title']) ? SecurityConfig::sanitizeInput($input['title']) : '';
$content = isset($input['content']) ? SecurityConfig::sanitizeInput($input['content']) : '';
$secure = isset($input['secure']) ? (bool)$input['secure'] : true;

if (empty($title) || empty($content)) {
apiError('Title and content are required');
}

// Post mavjudligini tekshirish
$stmt = $db->prepare("SELECT id FROM user_data WHERE id = ? AND user_id = ?");
$stmt->execute(array($postId, $_SESSION['user_id']));
if (!$stmt->fetch()) {
apiError('Post not found', 404);
}

// Xavfsizlik
if ($secure) {
$title = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
$content = htmlspecialchars($content, ENT_QUOTES, 'UTF-8');
}

// Post yangilash
$stmt = $db->prepare("UPDATE user_data SET title = ?, content = ? WHERE id = ? AND user_id = ?");
$stmt->execute(array($title, $content, $postId, $_SESSION['user_id']));

SecurityLogger::log('post_updated_api', $_SESSION['user_id'], $clientIP, 'low',
"Post updated via API: {$postId}");

apiSuccess(null, 'Post updated successfully');

} elseif ($method === 'DELETE') {
requireAuth();
checkCSRF();

// Post mavjudligini tekshirish
$stmt = $db->prepare("SELECT id FROM user_data WHERE id = ? AND user_id = ?");
$stmt->execute(array($postId, $_SESSION['user_id']));
if (!$stmt->fetch()) {
apiError('Post not found', 404);
}

// Post o'chirish
$stmt = $db->prepare("DELETE FROM user_data WHERE id = ? AND user_id = ?");
$stmt->execute(array($postId, $_SESSION['user_id']));

SecurityLogger::log('post_deleted_api', $_SESSION['user_id'], $clientIP, 'low',
"Post deleted via API: {$postId}");

apiSuccess(null, 'Post deleted successfully');
}
break;

// GET /api/data_api.php/search - Post qidirish
case 'search':
if ($method === 'GET') {
requireAuth();

$query = isset($_GET['q']) ? SecurityConfig::sanitizeInput($_GET['q']) : '';
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$limit = isset($_GET['limit']) ? min(50, max(1, (int)$_GET['limit'])) : 10;
$offset = ($page - 1) * $limit;

if (strlen($query) < 2) {
apiError('Search query must be at least 2 characters');
}

$searchParam = '%' . $query . '%';

// Jami natijalar soni
$stmt = $db->prepare("
SELECT COUNT(*) as total
FROM user_data
WHERE user_id = ? AND (title LIKE ? OR content LIKE ?)
");
$stmt->execute(array($_SESSION['user_id'], $searchParam, $searchParam));
$total = $stmt->fetch();
$total = $total['total'];

// Qidiruv natijalari
$stmt = $db->prepare("
SELECT id, title, content, created_at
FROM user_data
WHERE user_id = ? AND (title LIKE ? OR content LIKE ?)
ORDER BY created_at DESC
LIMIT ? OFFSET ?
");
$stmt->execute(array($_SESSION['user_id'], $searchParam, $searchParam, $limit, $offset));
$results = $stmt->fetchAll();

SecurityLogger::log('search_api', $_SESSION['user_id'], $clientIP, 'low',
"Search performed via API: {$query}");

apiSuccess(array(
'query' => $query,
'results' => $results,
'pagination' => array(
'current_page' => $page,
'total_pages' => ceil($total / $limit),
'total_items' => $total,
'items_per_page' => $limit
)
), 'Search completed successfully');
}
break;

// Admin endpoints
case 'admin-logs':
if ($method === 'GET') {
requireAdmin();

$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$limit = isset($_GET['limit']) ? min(100, max(1, (int)$_GET['limit'])) : 20;
$riskLevel = isset($_GET['risk_level']) ? $_GET['risk_level'] : '';
$actionType = isset($_GET['action_type']) ? $_GET['action_type'] : '';

$filters = array();
if (!empty($riskLevel)) $filters['risk_level'] = $riskLevel;
if (!empty($actionType)) $filters['action_type'] = $actionType;

$offset = ($page - 1) * $limit;
$logs = SecurityLogger::getLogs($limit, $offset, $filters);

apiSuccess(array(
'logs' => $logs,
'pagination' => array(
'current_page' => $page,
'items_per_page' => $limit
),
'filters' => $filters
), 'Logs retrieved successfully');
}
break;

case 'admin-users':
if ($method === 'GET') {
requireAdmin();

$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$limit = isset($_GET['limit']) ? min(100, max(1, (int)$_GET['limit'])) : 20;
$offset = ($page - 1) * $limit;

// Jami foydalanuvchilar
$stmt = $db->query("SELECT COUNT(*) as total FROM users");
$total = $stmt->fetch();
$total = $total