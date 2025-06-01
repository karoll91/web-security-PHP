<?php
/**
 * Ma'lumotlar bazasi ulanish konfiguratsiyasi
 * Web Security Project
 */

// Ma'lumotlar bazasi sozlamalari
define('DB_HOST', 'localhost');
define('DB_NAME', 'web_security_db');
define('DB_USER', 'root');
define('DB_PASS', '12345');
define('DB_CHARSET', 'utf8mb4');

class Database {
    private static $instance = null;
    private $connection;

    private function __construct() {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false, // SQL Injection himoyasi uchun
                PDO::MYSQL_ATTR_FOUND_ROWS => true
            ];

            $this->connection = new PDO($dsn, DB_USER, DB_PASS, $options);

            // Xavfsizlik uchun qo'shimcha sozlamalar
            $this->connection->exec("SET sql_mode = 'STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION'");

        } catch (PDOException $e) {
            // Xato ma'lumotlarini yashirish (production uchun)
            error_log("Database connection error: " . $e->getMessage());
            die("Ma'lumotlar bazasiga ulanishda xatolik yuz berdi.");
        }
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getConnection() {
        return $this->connection;
    }

    // Clone va unserialize metodlarini bloklash (Singleton pattern)
    private function __clone() {}
    private function __wakeup() {}
}

// Global funksiya - oson foydalanish uchun
function getDB() {
    return Database::getInstance()->getConnection();
}

// Test ulanish
try {
    $db = getDB();
    // echo "Ma'lumotlar bazasi muvaffaqiyatli ulandi!";
} catch (Exception $e) {
    error_log("Database test connection failed: " . $e->getMessage());
}
?>