<?php
/**
 * Xavfsizlik Logger - Barcha xavfsizlik hodisalarini yozib olish
 * Web Security Project
 */

class SecurityLogger {
    private static $db;
    private static $logFile;

    public static function init() {
        self::$db = getDB();
        self::$logFile = __DIR__ . '/../logs/security.log';

        // Log fayl katalogini yaratish
        $logDir = dirname(self::$logFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
    }

    /**
     * Xavfsizlik hodisasini yozib olish
     */
    public static function log($actionType, $userId = null, $ipAddress = null, $riskLevel = 'low', $details = '') {
        // Initializatsiya
        if (!self::$db) {
            self::init();
        }

        $ipAddress = $ipAddress ?: SecurityConfig::getClientIP();
        $userAgent = SecurityConfig::getUserAgent();

        try {
            // Ma'lumotlar bazasiga yozish
            $stmt = self::$db->prepare("
                INSERT INTO security_logs 
                (user_id, action_type, ip_address, user_agent, risk_level, details, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, NOW())
            ");
            $stmt->execute([$userId, $actionType, $ipAddress, $userAgent, $riskLevel, $details]);

            // Fayl logiga ham yozish
            self::writeToFile($actionType, $userId, $ipAddress, $riskLevel, $details);

            // Yuqori xavfli hodisalar uchun qo'shimcha ishlov
            if ($riskLevel === 'high') {
                self::handleHighRiskEvent($actionType, $userId, $ipAddress, $details);
            }

            return true;
        } catch (PDOException $e) {
            error_log("Security logger error: " . $e->getMessage());
            // Agar database ishlamasa, hech bo'lmaganda faylga yozamiz
            self::writeToFile($actionType, $userId, $ipAddress, $riskLevel, $details);
            return false;
        }
    }

    /**
     * Faylga yozish
     */
    private static function writeToFile($actionType, $userId, $ipAddress, $riskLevel, $details) {
        $timestamp = date('Y-m-d H:i:s');
        $userInfo = $userId ? "User:{$userId}" : 'Guest';

        $logEntry = sprintf(
            "[%s] %s | %s | %s | %s | %s\n",
            $timestamp,
            strtoupper($riskLevel),
            $actionType,
            $userInfo,
            $ipAddress,
            $details
        );

        file_put_contents(self::$logFile, $logEntry, FILE_APPEND | LOCK_EX);
    }

    /**
     * Yuqori xavfli hodisalarni boshqarish
     */
    private static function handleHighRiskEvent($actionType, $userId, $ipAddress, $details) {
        // Email yuborish, admin ga xabar berish va boshqalar

        // Kritik hodisalar uchun alohida fayl
        $criticalLogFile = __DIR__ . '/../logs/critical_security.log';
        $timestamp = date('Y-m-d H:i:s');

        $criticalEntry = sprintf(
            "[%s] CRITICAL: %s | User:%s | IP:%s | %s\n",
            $timestamp,
            $actionType,
            $userId ?: 'Unknown',
            $ipAddress,
            $details
        );

        file_put_contents($criticalLogFile, $criticalEntry, FILE_APPEND | LOCK_EX);

        // Real loyihada bu yerda email yuborish yoki SMS jo'natish mumkin
        error_log("CRITICAL SECURITY EVENT: {$actionType} from {$ipAddress}");
    }

    /**
     * Loglarni olish (admin panel uchun)
     */
    public static function getLogs($limit = 100, $offset = 0, $filters = []) {
        try {
            $sql = "
                SELECT sl.*, u.username 
                FROM security_logs sl
                LEFT JOIN users u ON sl.user_id = u.id
                WHERE 1=1
            ";
            $params = [];

            // Filtrlar
            if (!empty($filters['action_type'])) {
                $sql .= " AND sl.action_type = ?";
                $params[] = $filters['action_type'];
            }

            if (!empty($filters['risk_level'])) {
                $sql .= " AND sl.risk_level = ?";
                $params[] = $filters['risk_level'];
            }

            if (!empty($filters['ip_address'])) {
                $sql .= " AND sl.ip_address = ?";
                $params[] = $filters['ip_address'];
            }

            if (!empty($filters['user_id'])) {
                $sql .= " AND sl.user_id = ?";
                $params[] = $filters['user_id'];
            }

            if (!empty($filters['date_from'])) {
                $sql .= " AND sl.timestamp >= ?";
                $params[] = $filters['date_from'];
            }

            if (!empty($filters['date_to'])) {
                $sql .= " AND sl.timestamp <= ?";
                $params[] = $filters['date_to'];
            }

            $sql .= " ORDER BY sl.timestamp DESC LIMIT ? OFFSET ?";
            $params[] = $limit;
            $params[] = $offset;

            $stmt = self::$db->prepare($sql);
            $stmt->execute($params);

            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Security logger get logs error: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Log statistikalarini olish
     */
    public static function getStatistics($hours = 24) {
        try {
            $stmt = self::$db->prepare("
                SELECT 
                    action_type,
                    risk_level,
                    COUNT(*) as count,
                    COUNT(DISTINCT ip_address) as unique_ips,
                    COUNT(DISTINCT user_id) as unique_users
                FROM security_logs 
                WHERE timestamp > DATE_SUB(NOW(), INTERVAL ? HOUR)
                GROUP BY action_type, risk_level
                ORDER BY count DESC
            ");
            $stmt->execute([$hours]);

            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Security logger statistics error: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Shubhali IP manzillarni aniqlash
     */
    public static function getSuspiciousIPs($hours = 24, $minEvents = 10) {
        try {
            $stmt = self::$db->prepare("
                SELECT 
                    ip_address,
                    COUNT(*) as total_events,
                    SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_risk_events,
                    SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END) as medium_risk_events,
                    COUNT(DISTINCT action_type) as different_actions,
                    MIN(timestamp) as first_event,
                    MAX(timestamp) as last_event
                FROM security_logs 
                WHERE timestamp > DATE_SUB(NOW(), INTERVAL ? HOUR)
                GROUP BY ip_address
                HAVING total_events >= ?
                ORDER BY high_risk_events DESC, total_events DESC
            ");
            $stmt->execute([$hours, $minEvents]);

            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Security logger suspicious IPs error: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Foydalanuvchi faoliyati tarixini olish
     */
    public static function getUserActivity($userId, $limit = 50) {
        try {
            $stmt = self::$db->prepare("
                SELECT action_type, ip_address, risk_level, details, timestamp
                FROM security_logs 
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ");
            $stmt->execute([$userId, $limit]);

            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Security logger user activity error: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Eski loglarni tozalash
     */
    public static function cleanupOldLogs($days = 90) {
        try {
            $stmt = self::$db->prepare("
                DELETE FROM security_logs 
                WHERE timestamp < DATE_SUB(NOW(), INTERVAL ? DAY)
                AND risk_level != 'high'
            ");
            $stmt->execute([$days]);

            $deletedRows = $stmt->rowCount();

            // Fayl loglarini ham tozalash
            self::cleanupLogFiles($days);

            return $deletedRows;
        } catch (PDOException $e) {
            error_log("Security logger cleanup error: " . $e->getMessage());
            return 0;
        }
    }

    /**
     * Log fayllarini tozalash
     */
    private static function cleanupLogFiles($days) {
        $cutoffDate = strtotime("-{$days} days");
        $logDir = __DIR__ . '/../logs/';

        if (is_dir($logDir)) {
            $files = glob($logDir . '*.log');
            foreach ($files as $file) {
                if (filemtime($file) < $cutoffDate && basename($file) !== 'critical_security.log') {
                    // Arxivlash
                    $archiveFile = $file . '.' . date('Y-m-d', filemtime($file)) . '.archived';
                    rename($file, $archiveFile);
                    gzip($archiveFile);
                }
            }
        }
    }

    /**
     * Real-time monitoring uchun oxirgi hodisalarni olish
     */
    public static function getRecentEvents($minutes = 5, $riskLevels = ['medium', 'high']) {
        try {
            $placeholders = str_repeat('?,', count($riskLevels) - 1) . '?';
            $stmt = self::$db->prepare("
                SELECT sl.*, u.username
                FROM security_logs sl
                LEFT JOIN users u ON sl.user_id = u.id
                WHERE sl.timestamp > DATE_SUB(NOW(), INTERVAL ? MINUTE)
                AND sl.risk_level IN ({$placeholders})
                ORDER BY sl.timestamp DESC
            ");

            $params = array_merge([$minutes], $riskLevels);
            $stmt->execute($params);

            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Security logger recent events error: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Log export qilish (CSV format)
     */
    public static function exportLogs($filters = [], $format = 'csv') {
        $logs = self::getLogs(10000, 0, $filters); // Katta limit

        if ($format === 'csv') {
            $output = "Timestamp,Action Type,User,IP Address,Risk Level,Details\n";

            foreach ($logs as $log) {
                $output .= sprintf(
                    "%s,%s,%s,%s,%s,\"%s\"\n",
                    $log['timestamp'],
                    $log['action_type'],
                    $log['username'] ?: 'Guest',
                    $log['ip_address'],
                    $log['risk_level'],
                    str_replace('"', '""', $log['details'])
                );
            }

            return $output;
        }

        return $logs;
    }
}

// Avtomatik initializatsiya
SecurityLogger::init();
?>