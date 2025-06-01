<?php
/**
 * Input Validator - Ma'lumotlarni tekshirish va tozalash
 * Web Security Project
 */

class InputValidator {

    // Xatoliklar ro'yxati
    private static $errors = array();

    // Validatsiya qoidalari
    private static $rules = array(
        'username' => array(
            'type' => 'string',
            'min_length' => 3,
            'max_length' => 20,
            'pattern' => '/^[a-zA-Z0-9_]+$/',
            'required' => true
        ),
        'email' => array(
            'type' => 'email',
            'max_length' => 100,
            'required' => true
        ),
        'password' => array(
            'type' => 'password',
            'min_length' => 6,
            'max_length' => 255,
            'required' => true
        ),
        'full_name' => array(
            'type' => 'string',
            'min_length' => 2,
            'max_length' => 100,
            'pattern' => '/^[a-zA-Z\s\'\-\.]+$/u',
            'required' => true
        ),
        'phone' => array(
            'type' => 'phone',
            'pattern' => '/^[\+]?[0-9\s\-\(\)]{7,15}$/',
            'required' => false
        ),
        'url' => array(
            'type' => 'url',
            'max_length' => 255,
            'required' => false
        ),
        'ip_address' => array(
            'type' => 'ip',
            'required' => false
        ),
        'date' => array(
            'type' => 'date',
            'required' => false
        ),
        'number' => array(
            'type' => 'numeric',
            'required' => false
        )
    );

    /**
     * Ma'lumotni tozalash (Sanitization)
     */
    public static function sanitize($input, $type = 'string') {
        if (is_array($input)) {
            return array_map(function($item) use ($type) {
                return self::sanitize($item, $type);
            }, $input);
        }

        // Asosiy tozalash
        $input = trim($input);

        switch ($type) {
            case 'string':
                // HTML teglarini olib tashlash
                $input = strip_tags($input);
                // Maxsus belgilarni kodlash
                $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
                break;

            case 'html':
                // Ruxsat etilgan HTML teglar (agar kerak bo'lsa)
                $allowedTags = '<p><br><strong><em><u><a><ul><ol><li>';
                $input = strip_tags($input, $allowedTags);
                break;

            case 'email':
                // Email tozalash
                $input = filter_var($input, FILTER_SANITIZE_EMAIL);
                $input = strtolower($input);
                break;

            case 'url':
                // URL tozalash
                $input = filter_var($input, FILTER_SANITIZE_URL);
                break;

            case 'numeric':
                // Faqat raqamlar
                $input = preg_replace('/[^0-9\.\-]/', '', $input);
                break;

            case 'alphanumeric':
                // Faqat harflar va raqamlar
                $input = preg_replace('/[^a-zA-Z0-9]/', '', $input);
                break;

            case 'username':
                // Username uchun maxsus tozalash
                $input = preg_replace('/[^a-zA-Z0-9_]/', '', $input);
                $input = strtolower($input);
                break;

            case 'phone':
                // Telefon raqami tozalash
                $input = preg_replace('/[^0-9\+\-\(\)\s]/', '', $input);
                break;

            case 'sql':
                // SQL injection himoyasi
                $input = str_replace(array("'", '"', '\\', '/', '*', '?', '<', '>', '|'), '', $input);
                break;

            case 'filename':
                // Fayl nomi tozalash
                $input = preg_replace('/[^a-zA-Z0-9\-_\.]/', '', $input);
                break;

            default:
                // Standart string tozalash
                $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
                break;
        }

        return $input;
    }

    /**
     * Ma'lumotni tekshirish (Validation)
     */
    public static function validate($input, $rules, $fieldName = 'field') {
        self::$errors = array();

        // Agar rules string bo'lsa, predefined rules dan olish
        if (is_string($rules)) {
            if (isset(self::$rules[$rules])) {
                $rules = self::$rules[$rules];
            } else {
                self::$errors[] = "Unknown validation rule: {$rules}";
                return false;
            }
        }

        // Required tekshirish
        if (isset($rules['required']) && $rules['required']) {
            if (empty($input) && $input !== '0') {
                self::$errors[] = "{$fieldName} majburiy maydon";
                return false;
            }
        }

        // Agar input bo'sh bo'lsa va required emas, validatsiyadan o'tish
        if (empty($input) && $input !== '0') {
            return true;
        }

        // Type-specific validation
        if (isset($rules['type'])) {
            switch ($rules['type']) {
                case 'email':
                    if (!filter_var($input, FILTER_VALIDATE_EMAIL)) {
                        self::$errors[] = "{$fieldName} noto'g'ri email format";
                        return false;
                    }
                    break;

                case 'url':
                    if (!filter_var($input, FILTER_VALIDATE_URL)) {
                        self::$errors[] = "{$fieldName} noto'g'ri URL format";
                        return false;
                    }
                    break;

                case 'ip':
                    if (!filter_var($input, FILTER_VALIDATE_IP)) {
                        self::$errors[] = "{$fieldName} noto'g'ri IP manzil";
                        return false;
                    }
                    break;

                case 'numeric':
                    if (!is_numeric($input)) {
                        self::$errors[] = "{$fieldName} raqam bo'lishi kerak";
                        return false;
                    }
                    break;

                case 'integer':
                    if (!filter_var($input, FILTER_VALIDATE_INT)) {
                        self::$errors[] = "{$fieldName} butun son bo'lishi kerak";
                        return false;
                    }
                    break;

                case 'date':
                    $date = DateTime::createFromFormat('Y-m-d', $input);
                    if (!$date || $date->format('Y-m-d') !== $input) {
                        self::$errors[] = "{$fieldName} noto'g'ri sana format (YYYY-MM-DD)";
                        return false;
                    }
                    break;

                case 'datetime':
                    $date = DateTime::createFromFormat('Y-m-d H:i:s', $input);
                    if (!$date || $date->format('Y-m-d H:i:s') !== $input) {
                        self::$errors[] = "{$fieldName} noto'g'ri sana-vaqt format";
                        return false;
                    }
                    break;

                case 'password':
                    if (!self::validatePassword($input)) {
                        self::$errors[] = "{$fieldName} kamida 8 ta belgi, katta va kichik harf, raqam bo'lishi kerak";
                        return false;
                    }
                    break;
            }
        }

        // Uzunlik tekshirish
        if (isset($rules['min_length'])) {
            if (strlen($input) < $rules['min_length']) {
                self::$errors[] = "{$fieldName} kamida {$rules['min_length']} ta belgidan iborat bo'lishi kerak";
                return false;
            }
        }

        if (isset($rules['max_length'])) {
            if (strlen($input) > $rules['max_length']) {
                self::$errors[] = "{$fieldName} {$rules['max_length']} ta belgidan oshmasligi kerak";
                return false;
            }
        }

        // Pattern tekshirish
        if (isset($rules['pattern'])) {
            if (!preg_match($rules['pattern'], $input)) {
                $message = isset($rules['pattern_message'])
                    ? $rules['pattern_message']
                    : "{$fieldName} noto'g'ri format";
                self::$errors[] = $message;
                return false;
            }
        }

        // Minimal va maksimal qiymat (raqamlar uchun)
        if (isset($rules['min']) && is_numeric($input)) {
            if ($input < $rules['min']) {
                self::$errors[] = "{$fieldName} {$rules['min']} dan kichik bo'lmasligi kerak";
                return false;
            }
        }

        if (isset($rules['max']) && is_numeric($input)) {
            if ($input > $rules['max']) {
                self::$errors[] = "{$fieldName} {$rules['max']} dan katta bo'lmasligi kerak";
                return false;
            }
        }

        // Ruxsat etilgan qiymatlar ro'yxati
        if (isset($rules['in'])) {
            if (!in_array($input, $rules['in'])) {
                self::$errors[] = "{$fieldName} ruxsat etilgan qiymatlardan biri bo'lishi kerak";
                return false;
            }
        }

        // Custom validator
        if (isset($rules['custom']) && is_callable($rules['custom'])) {
            $result = call_user_func($rules['custom'], $input);
            if ($result !== true) {
                self::$errors[] = is_string($result) ? $result : "{$fieldName} custom validation xatosi";
                return false;
            }
        }

        return true;
    }

    /**
     * Bir nechta maydonlarni tekshirish
     */
    public static function validateFields($data, $rulesArray) {
        $isValid = true;
        self::$errors = array();

        foreach ($rulesArray as $fieldName => $rules) {
            $value = isset($data[$fieldName]) ? $data[$fieldName] : '';

            if (!self::validate($value, $rules, $fieldName)) {
                $isValid = false;
            }
        }

        return $isValid;
    }

    /**
     * Parol kuchliligini tekshirish
     */
    public static function validatePassword($password) {
        // Kamida 8 ta belgi
        if (strlen($password) < 8) {
            return false;
        }

        // Katta harf
        if (!preg_match('/[A-Z]/', $password)) {
            return false;
        }

        // Kichik harf
        if (!preg_match('/[a-z]/', $password)) {
            return false;
        }

        // Raqam
        if (!preg_match('/[0-9]/', $password)) {
            return false;
        }

        // Maxsus belgi (ixtiyoriy)
        // if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        //     return false;
        // }

        return true;
    }

    /**
     * SQL Injection zaifliklarini tekshirish
     */
    public static function detectSQLInjection($input) {
        $suspiciousPatterns = array(
            '/(\bUNION\b.*\bSELECT\b)/i',
            '/(\bSELECT\b.*\bFROM\b)/i',
            '/(\bINSERT\b.*\bINTO\b)/i',
            '/(\bUPDATE\b.*\bSET\b)/i',
            '/(\bDELETE\b.*\bFROM\b)/i',
            '/(\bDROP\b.*\bTABLE\b)/i',
            '/(\'.*\bOR\b.*\')/i',
            '/(\".*\bOR\b.*\")/i',
            '/(\b1\s*=\s*1\b)/i',
            '/(\'\s*OR\s*\')/i',
            '/(--\s*)/i',
            '/(\/\*.*\*\/)/i'
        );

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }

        return false;
    }

    /**
     * XSS zaifliklarini tekshirish
     */
    public static function detectXSS($input) {
        $suspiciousPatterns = array(
            '/<script[^>]*>.*?<\/script>/is',
            '/<iframe[^>]*>.*?<\/iframe>/is',
            '/<object[^>]*>.*?<\/object>/is',
            '/<embed[^>]*>/i',
            '/<applet[^>]*>.*?<\/applet>/is',
            '/javascript:/i',
            '/vbscript:/i',
            '/onload\s*=/i',
            '/onclick\s*=/i',
            '/onerror\s*=/i',
            '/onmouseover\s*=/i',
            '/<img[^>]+src[^>]*>/i'
        );

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Fayl yuklash xavfsizligini tekshirish
     */
    public static function validateFileUpload($file, $allowedTypes = array(), $maxSize = 5242880) {
        self::$errors = array();

        // Fayl mavjudligini tekshirish
        if (!isset($file['tmp_name']) || empty($file['tmp_name'])) {
            self::$errors[] = "Fayl tanlanmagan";
            return false;
        }

        // Xatolik tekshirish
        if ($file['error'] !== UPLOAD_ERR_OK) {
            switch ($file['error']) {
                case UPLOAD_ERR_INI_SIZE:
                case UPLOAD_ERR_FORM_SIZE:
                    self::$errors[] = "Fayl juda katta";
                    break;
                case UPLOAD_ERR_PARTIAL:
                    self::$errors[] = "Fayl to'liq yuklanmadi";
                    break;
                case UPLOAD_ERR_NO_FILE:
                    self::$errors[] = "Fayl tanlanmagan";
                    break;
                default:
                    self::$errors[] = "Fayl yuklashda xatolik";
                    break;
            }
            return false;
        }

        // Fayl o'lchamini tekshirish
        if ($file['size'] > $maxSize) {
            self::$errors[] = "Fayl o'lchami " . round($maxSize / 1024 / 1024, 2) . "MB dan oshmasligi kerak";
            return false;
        }

        // Fayl turini tekshirish
        if (!empty($allowedTypes)) {
            $fileInfo = finfo_open(FILEINFO_MIME_TYPE);
            $mimeType = finfo_file($fileInfo, $file['tmp_name']);
            finfo_close($fileInfo);

            if (!in_array($mimeType, $allowedTypes)) {
                self::$errors[] = "Ruxsat etilmagan fayl turi";
                return false;
            }
        }

        // Fayl nomini tekshirish
        $fileName = $file['name'];
        if (!preg_match('/^[a-zA-Z0-9\-_\.]+$/', $fileName)) {
            self::$errors[] = "Fayl nomida ruxsat etilmagan belgilar";
            return false;
        }

        // Double extension tekshirish
        if (preg_match('/\.(php|phtml|php3|php4|php5|pl|py|jsp|asp|sh|cgi)$/i', $fileName)) {
            self::$errors[] = "Xavfli fayl kengaytmasi";
            return false;
        }

        return true;
    }

    /**
     * Xatoliklarni olish
     */
    public static function getErrors() {
        return self::$errors;
    }

    /**
     * Oxirgi xatolikni olish
     */
    public static function getLastError() {
        return empty(self::$errors) ? null : end(self::$errors);
    }

    /**
     * Xatoliklar mavjudligini tekshirish
     */
    public static function hasErrors() {
        return !empty(self::$errors);
    }

    /**
     * Xatoliklarni tozalash
     */
    public static function clearErrors() {
        self::$errors = array();
    }

    /**
     * Custom validation rule qo'shish
     */
    public static function addRule($name, $rule) {
        self::$rules[$name] = $rule;
    }

    /**
     * Validation rule olish
     */
    public static function getRule($name) {
        return isset(self::$rules[$name]) ? self::$rules[$name] : null;
    }

    /**
     * Barcha qoidalarni olish
     */
    public static function getAllRules() {
        return self::$rules;
    }

    /**
     * Form ma'lumotlarini to'liq tekshirish va tozalash
     */
    public static function processForm($data, $rules) {
        $processed = array();
        $isValid = true;
        self::$errors = array();

        foreach ($rules as $fieldName => $fieldRules) {
            $value = isset($data[$fieldName]) ? $data[$fieldName] : '';

            // Sanitize
            $sanitizeType = isset($fieldRules['sanitize']) ? $fieldRules['sanitize'] : 'string';
            $cleanValue = self::sanitize($value, $sanitizeType);

            // Validate
            if (!self::validate($cleanValue, $fieldRules, $fieldName)) {
                $isValid = false;
            }

            $processed[$fieldName] = $cleanValue;
        }

        return array(
            'isValid' => $isValid,
            'data' => $processed,
            'errors' => self::$errors
        );
    }
}

/**
 * Helper funksiyalar (global scope)
 */

// Qisqa sanitize funksiyasi
function sanitize($input, $type = 'string') {
    return InputValidator::sanitize($input, $type);
}

// Qisqa validate funksiyasi
function validate($input, $rules, $fieldName = 'field') {
    return InputValidator::validate($input, $rules, $fieldName);
}

// SQL injection tekshirish
function detectSQLInjection($input) {
    return InputValidator::detectSQLInjection($input);
}

// XSS tekshirish
function detectXSS($input) {
    return InputValidator::detectXSS($input);
}
?>