<?php
/**
 * Logout - Tizimdan chiqish
 * Web Security Project
 */

require_once '../config/database.php';
require_once '../config/security.php';
require_once '../security/security_logger.php';
require_once '../security/csrf_token.php';

// Foydalanuvchi login qilganmi tekshirish
if (!isset($_SESSION['user_id'])) {
    header('Location: ../index.php');
    exit;
}

$userId = $_SESSION['user_id'];
$username = $_SESSION['username'] ?? 'Unknown';

// Log qilish
SecurityLogger::log('logout', $userId, null, 'low', "User logged out: {$username}");

// CSRF tokenlarini tozalash
CSRFToken::clearUserTokens($userId);

// Session ma'lumotlarini to'liq tozalash
session_unset();
session_destroy();

// Yangi session boshlash (xavfsizlik uchun)
session_start();
session_regenerate_id(true);

// Remember me cookie ni o'chirish (agar mavjud bo'lsa)
if (isset($_COOKIE['remember_token'])) {
    setcookie('remember_token', '', time() - 3600, '/', '', false, true);
}

// Cache control headerlar
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Logout muvaffaqiyatli bajarilganligi haqida xabar
$_SESSION['logout_message'] = 'Tizimdan muvaffaqiyatli chiqdingiz!';

// Login sahifasiga yo'naltirish
header('Location: ../index.php');
exit;
?>