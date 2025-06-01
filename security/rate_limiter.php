<?php
/**
 * Rate Limiter - So'rovlar cheklash tizimi
 * Web Security Project
 */

class RateLimiter {
    private $db;

    // Rate limiting sozlamalari
    private $limits = [
        'login' => ['max_attempts' => 5, 'window' => 900], // 5 urinish, 15 daqiqa
        'register' => ['max_attempts' => 3, 'window' => 3600], // 3 urinish, 1 soat
        'api' => ['max_attempts' => 100, 'window' => 3600], // 100 so'rov, 1 soat
        'password_reset' => ['max_attempts' => 3, 'window' => 3600], // 3 urinish, 1 soat
    ];

    public function __construct() {
        $this->db = getDB();
        $this->cleanupOldRecords();
    }

    /**
     * So'rov urinishini yozib olish
     */
    public function recordAttempt($ip, $actionType) {
        try {
            // Mavjud yozuvni tekshirish
            $stmt = $this->db->prepare("
                SELECT id, attempts, last_attempt 
                FROM rate_limits 
                WHERE ip_address = ? AND action_type = ? 
                AND last_attempt > DATE_SUB(NOW(), INTERVAL ? SECOND)
            ");
            $window = $this->limits[$actionType]['window'] ?? RATE_LIMIT_WINDOW;
            $stmt->execute([$ip, $actionType, $window]);
            $existing = $stmt->fetch();

            if ($existing) {
                // Mavjud yozuvni yangilash
                $newAttempts = $existing['attempts'] + 1;
                $maxAttempts = $this->limits[$actionType]['max_attempts'] ?? 10;

                $blockedUntil = null;
                if ($newAttempts >= $maxAttempts) {
                    $blockedUntil = date('Y-m-d H:i:s', time() + $window);
                }

                $stmt = $this->db->prepare("
                    UPDATE rate_limits 
                    SET attempts = ?, last_attempt = NOW(), blocked_until = ?
                    WHERE id = ?
                ");
                $stmt->execute([$newAttempts, $blockedUntil, $existing['id']]);
            } else {
                // Yangi yozuv yaratish
                $stmt = $this->db->prepare("
                    INSERT INTO rate_limits (ip_address, action_type, attempts, last_attempt) 
                    VALUES (?, ?, 1, NOW())
                ");
                $stmt->execute([$ip, $actionType]);
            }

            return true;
        } catch (PDOException $e) {
            error_log("Rate limiter record error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * IP manzil bloklanganmi tekshirish
     */
    public function isBlocked($ip, $actionType) {
        try {
            $stmt = $this->db->prepare("
                SELECT attempts, blocked_until 
                FROM rate_limits 
                WHERE ip_address = ? AND action_type = ?
                AND blocked_until > NOW()
            ");
            $stmt->execute([$ip, $actionType]);
            $result = $stmt->fetch();

            return $result !== false;
        } catch (PDOException $e) {
            error_log("Rate limiter check error: " . $e->getMessage());
            return false; // Xatolik bo'lsa, bloklamaymiz
        }
    }

    /**
     * Urinishlar sonini olish
     */
    public function getAttempts($ip, $actionType) {
        try {
            $stmt = $this->db->prepare("
                SELECT attempts 
                FROM rate_limits 
                WHERE ip_address = ? AND action_type = ?
                AND last_attempt > DATE_SUB(NOW(), INTERVAL ? SECOND)
            ");
            $window = $this->limits[$actionType]['window'] ?? RATE_LIMIT_WINDOW;
            $stmt->execute([$ip, $actionType, $window]);
            $result = $stmt->fetch();

            return $result ? (int)$result['attempts'] : 0;
        } catch (PDOException $e) {
            error_log("Rate limiter get attempts error: " . $e->getMessage());
            return 0;
        }
    }

    /**
     * Urinishlarni tozalash (muvaffaqiyatli amal bajarilganda)
     */
    public function clearAttempts($ip, $actionType) {
        try {
            $stmt = $this->db->prepare("
                DELETE FROM rate_limits 
                WHERE ip_address = ? AND action_type = ?
            ");
            $stmt->execute([$ip, $actionType]);
            return true;
        } catch (PDOException $e) {
            error_log("Rate limiter clear error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Bloklangan vaqtni olish
     */
    public function getBlockedUntil($ip, $actionType) {
        try {
            $stmt = $this->db->prepare("
                SELECT blocked_until 
                FROM rate_limits 
                WHERE ip_address = ? AND action_type = ?
                AND blocked_until > NOW()
            ");
            $stmt->execute([$ip, $actionType]);
            $result = $stmt->fetch();

            return $result ? $result['blocked_until'] : null;
        } catch (PDOException $e) {
            error_log("Rate limiter get blocked time error: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Qolgan vaqtni olish (soniyalarda)
     */
    public function getRemainingTime($ip, $actionType) {
        $blockedUntil = $this->getBlockedUntil($ip, $actionType);
        if (!$blockedUntil) {
            return 0;
        }

        $now = new DateTime();
        $blocked = new DateTime($blockedUntil);
        $diff = $blocked->getTimestamp() - $now->getTimestamp();

        return max(0, $diff);
    }

    /**
     * Rate limit ma'lumotlarini olish
     */
    public function getRateLimitInfo($ip, $actionType) {
        $maxAttempts = $this->limits[$actionType]['max_attempts'] ?? 10;
        $window = $this->limits[$actionType]['window'] ?? RATE_LIMIT_WINDOW;
        $currentAttempts = $this->getAttempts($ip, $actionType);
        $isBlocked = $this->isBlocked($ip, $actionType);
        $remainingTime = $this->getRemainingTime($ip, $actionType);

        return [
            'max_attempts' => $maxAttempts,
            'current_attempts' => $currentAttempts,
            'remaining_attempts' => max(0, $maxAttempts - $currentAttempts),
            'window_seconds' => $window,
            'is_blocked' => $isBlocked,
            'remaining_time' => $remainingTime,
            'can_attempt' => !$isBlocked && $currentAttempts < $maxAttempts
        ];
    }

    /**
     * Eski yozuvlarni tozalash
     */
    private function cleanupOldRecords() {
        try {
            // 24 soatdan eski yozuvlarni o'chirish
            $stmt = $this->db->prepare("
                DELETE FROM rate_limits 
                WHERE last_attempt < DATE_SUB(NOW(), INTERVAL 24 HOUR)
                AND (blocked_until IS NULL OR blocked_until < NOW())
            ");
            $stmt->execute();
        } catch (PDOException $e) {
            error_log("Rate limiter cleanup error: " . $e->getMessage());
        }
    }

    /**
     * Rate limit sozlamalarini yangilash
     */
    public function setLimit($actionType, $maxAttempts, $windowSeconds) {
        $this->limits[$actionType] = [
            'max_attempts' => $maxAttempts,
            'window' => $windowSeconds
        ];
    }

    /**
     * Barcha aktiv bloklarni ko'rish (admin uchun)
     */
    public function getActiveBlocks() {
        try {
            $stmt = $this->db->prepare("
                SELECT ip_address, action_type, attempts, blocked_until, last_attempt
                FROM rate_limits 
                WHERE blocked_until > NOW()
                ORDER BY blocked_until DESC
            ");
            $stmt->execute();
            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Rate limiter get blocks error: " . $e->getMessage());
            return [];
        }
    }

    /**
     * IP ni manual ravishda blokdan chiqarish (admin uchun)
     */
    public function unblockIP($ip, $actionType = null) {
        try {
            if ($actionType) {
                $stmt = $this->db->prepare("
                    UPDATE rate_limits 
                    SET blocked_until = NULL 
                    WHERE ip_address = ? AND action_type = ?
                ");
                $stmt->execute([$ip, $actionType]);
            } else {
                $stmt = $this->db->prepare("
                    UPDATE rate_limits 
                    SET blocked_until = NULL 
                    WHERE ip_address = ?
                ");
                $stmt->execute([$ip]);
            }
            return true;
        } catch (PDOException $e) {
            error_log("Rate limiter unblock error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Statistikalarni olish
     */
    public function getStatistics($hours = 24) {
        try {
            $stmt = $this->db->prepare("
                SELECT 
                    action_type,
                    COUNT(*) as total_attempts,
                    COUNT(DISTINCT ip_address) as unique_ips,
                    SUM(CASE WHEN blocked_until IS NOT NULL THEN 1 ELSE 0 END) as blocked_attempts
                FROM rate_limits 
                WHERE last_attempt > DATE_SUB(NOW(), INTERVAL ? HOUR)
                GROUP BY action_type
                ORDER BY total_attempts DESC
            ");
            $stmt->execute([$hours]);
            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Rate limiter statistics error: " . $e->getMessage());
            return [];
        }
    }
}