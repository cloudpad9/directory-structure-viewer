<?php
class Auth {
    private const USERS_FILE = __DIR__ . '/users.json';
    private const TOKENS_FILE = __DIR__ . '/auth_tokens.json';
    private const TOKEN_EXPIRY = 7 * 24 * 60 * 60; // 7 days
    private const MAX_LOGIN_ATTEMPTS = 5;
    private const LOCKOUT_TIME = 15 * 60; // 15 minutes

    // === USER MANAGEMENT ===

    public static function loadUsers(): array {
        if (!file_exists(self::USERS_FILE)) {
            // Create default admin user
            $defaultUsers = [
                'admin' => [
                    'password' => password_hash('admin123', PASSWORD_BCRYPT),
                    'created_at' => time()
                ]
            ];
            self::saveUsers($defaultUsers);
            return $defaultUsers;
        }

        $json = file_get_contents(self::USERS_FILE);
        return json_decode($json, true) ?: [];
    }

    private static function saveUsers(array $users): void {
        file_put_contents(
            self::USERS_FILE,
            json_encode($users, JSON_PRETTY_PRINT),
            LOCK_EX
        );
    }

    // === TOKEN MANAGEMENT ===

    private static function loadTokens(): array {
        if (!file_exists(self::TOKENS_FILE)) return [];
        $json = file_get_contents(self::TOKENS_FILE);
        return json_decode($json, true) ?: [];
    }

    private static function saveTokens(array $tokens): void {
        // Cleanup expired tokens
        $now = time();
        $tokens = array_filter($tokens, fn($t) => ($t['expires_at'] ?? 0) > $now);

        file_put_contents(
            self::TOKENS_FILE,
            json_encode($tokens, JSON_PRETTY_PRINT),
            LOCK_EX
        );
    }

    private static function generateToken(): string {
        return bin2hex(random_bytes(32));
    }

    // === RATE LIMITING ===

    private static function checkRateLimit(string $username): void {
        $tokens = self::loadTokens();
        $attempts = array_filter($tokens, function($t) use ($username) {
            return ($t['type'] ?? '') === 'login_attempt'
                && ($t['username'] ?? '') === $username
                && ($t['timestamp'] ?? 0) > (time() - self::LOCKOUT_TIME);
        });

        if (count($attempts) >= self::MAX_LOGIN_ATTEMPTS) {
            http_response_code(429);
            throw new RuntimeException('Too many login attempts. Please try again later.');
        }
    }

    private static function recordLoginAttempt(string $username, bool $success): void {
        $tokens = self::loadTokens();
        $tokens[] = [
            'type' => 'login_attempt',
            'username' => $username,
            'success' => $success,
            'timestamp' => time(),
            'expires_at' => time() + self::LOCKOUT_TIME
        ];
        self::saveTokens($tokens);
    }

    // === AUTHENTICATION ===

    public static function login(string $username, string $password): array {
        self::checkRateLimit($username);

        $users = self::loadUsers();

        if (!isset($users[$username])) {
            self::recordLoginAttempt($username, false);
            throw new RuntimeException('Invalid credentials');
        }

        if (!password_verify($password, $users[$username]['password'])) {
            self::recordLoginAttempt($username, false);
            throw new RuntimeException('Invalid credentials');
        }

        // Login successful
        self::recordLoginAttempt($username, true);

        $token = self::generateToken();
        $expiresAt = time() + self::TOKEN_EXPIRY;

        $tokens = self::loadTokens();
        $tokens[$token] = [
            'username' => $username,
            'created_at' => time(),
            'expires_at' => $expiresAt
        ];
        self::saveTokens($tokens);

        return [
            'token' => $token,
            'username' => $username,
            'expires_at' => $expiresAt
        ];
    }

    public static function authenticate(): array {
        $token = self::extractToken();

        if (!$token) {
            http_response_code(401);
            throw new RuntimeException('Authentication required');
        }

        $tokens = self::loadTokens();

        if (!isset($tokens[$token])) {
            http_response_code(401);
            throw new RuntimeException('Invalid token');
        }

        $tokenData = $tokens[$token];

        // Check expiry
        if (($tokenData['expires_at'] ?? 0) < time()) {
            unset($tokens[$token]);
            self::saveTokens($tokens);
            http_response_code(401);
            throw new RuntimeException('Token expired');
        }

        return $tokenData;
    }

    public static function logout(): void {
        $token = self::extractToken();
        if ($token) {
            $tokens = self::loadTokens();
            unset($tokens[$token]);
            self::saveTokens($tokens);
        }
    }

    private static function extractToken(): ?string {
        // Check Authorization header
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (preg_match('/Bearer\s+(.+)/', $authHeader, $matches)) {
            return $matches[1];
        }

        // Fallback to query param or POST data
        return $_REQUEST['token'] ?? null;
    }

    // === USER MANAGEMENT (for admin) ===

    public static function changePassword(string $username, string $oldPassword, string $newPassword): void {
        $users = self::loadUsers();

        if (!isset($users[$username])) {
            throw new RuntimeException('User not found');
        }

        if (!password_verify($oldPassword, $users[$username]['password'])) {
            throw new RuntimeException('Invalid current password');
        }

        $users[$username]['password'] = password_hash($newPassword, PASSWORD_BCRYPT);
        $users[$username]['updated_at'] = time();
        self::saveUsers($users);
    }
}

class Util {
    static function offsetToLineNumber($content, $offset) {
        return substr_count(substr(trim($content), 0, $offset), "\n") + 1;
    }

    static function removeRedundantBlankLines($content) {
        $lines = explode("\n", $content);

        $cleanedLines = [];
        $previousLineBlank = false;

        foreach ($lines as $line) {
            $isCurrentLineBlank = trim($line) === '';

            if (!($isCurrentLineBlank && $previousLineBlank)) {
                $cleanedLines[] = $line;
            }

            $previousLineBlank = $isCurrentLineBlank;
        }

        return implode("\n", $cleanedLines);
    }

    static function removeComments($content) {
        $pattern = array(
            '/\/\*[\s\S]*?\*\//',   // Xóa multi-line comments
            '/\/\/.*$/m',           // Xóa single-line comments
            '/^\s*#.*$/m'           // Xóa shell-style comments
        );

        return preg_replace($pattern, '', $content);
    }

    static function eol() { return PHP_EOL; }
}

class BlockHelper
{
    public static function getBlockInfosFromSignatures(string $content, array $signatures): array {
        // Sắp xếp signatures theo offset tăng dần
        usort($signatures, fn($a, $b) => $a[1] <=> $b[1]);

        $blockInfos = [];
        $offsets = array_column($signatures, 1);

        foreach ($signatures as $i => $signatureInfo) {
            $signature = $signatureInfo[0];
            $offset = $signatureInfo[1];
            $lineNumber = $signatureInfo[2];
            $type = $signatureInfo[3] ?? '';

            $blockContent = self::getBlockContent($content, $signature, $offset, $type);
            $endPos = $offset + strlen($blockContent);

            $parentOffsets = [];
            foreach ($offsets as $j => $existingOffset) {
                if ($j >= $i) break;
                if ($existingOffset < $offset && $blockInfos[$j]['endPos'] > $endPos) {
                    $parentOffsets[] = $existingOffset;
                    // Merge parent's parents
                    $parentOffsets = array_merge($parentOffsets, $blockInfos[$j]['parentOffsets']);
                }
            }

            $blockInfos[] = [
                'signature' => $signature,
                'offset' => $offset,
                'endPos' => $endPos,
                'lineNumber' => $lineNumber,
                'parentOffsets' => array_unique($parentOffsets)
            ];
        }

        return $blockInfos;
    }

    public static function getBlockContentsFromSignatures(string $content, array $signatures): array {
        $blocks = [];

        foreach ($signatures as $signature) {
            $offset = $signature[1];
            $type = $signature[3] ?? '';

            $blocks[$offset] = self::getBlockContent($content, $signature[0], $offset, $type);
        }

        return $blocks;
    }

    public static function getBlockContent(string $content, string $signature, int $offset, string $type): string
    {
        switch ($type) {
            case 'STYLE':
                return self::getBlockContent_Style($content, $signature, $offset);

            case 'APP_DIV':
                return self::getBlockContent_AppDiv($content, $signature, $offset);
        }

        return self::getBlockContent_Function($content, $signature, $offset);
    }

    public static function getBlockContent_Style(string $content, string $signature, int $startPos): string
    {
        $endTag = '</style>';
        $endPos = strpos($content, $endTag, $startPos);

        if ($endPos === false) {
            throw new RuntimeException("Closing style tag not found");
        }

        return substr($content, $startPos, $endPos + strlen($endTag) - $startPos);
    }

    public static function getBlockContent_Function(string $content, string $signature, int $startPos): string {
        $singleQuoteCount = 0;
        $doubleQuoteCount = 0;
        $braceCount = 0;
        $contentLength = strlen($content);

        for ($i = $startPos; $i < $contentLength; $i++) {
            $c = $content[$i];

            if ($c === '{') {
                if (!$singleQuoteCount && !$doubleQuoteCount) {
                    $braceCount++;
                }
            } elseif ($c === '}') {
                if (!$singleQuoteCount && !$doubleQuoteCount) {
                    $braceCount--;
                }
                if ($braceCount === 0) {
                    return substr($content, $startPos, $i - $startPos + 1);
                }
            } elseif ($c === "'") {
                if ($singleQuoteCount) {
                    $singleQuoteCount = 0;
                } else {
                    $singleQuoteCount = 1;
                }
            } elseif ($c === '"') {
                if ($doubleQuoteCount) {
                    $doubleQuoteCount = 0;
                } else {
                    $doubleQuoteCount = 1;
                }
            } elseif ($c === "\r" || $c === "\n") {
                // Nếu qua line mới thì reset lại việc đếm quote
                $doubleQuoteCount = 0;
                $singleQuoteCount = 0;
            }
        }

        throw new RuntimeException("Unmatched braces in function block, signature = $signature");
    }

    public static function getBlockContent_AppDiv(string $content, string $signature, int $startPos): string {
        $tagStack = [];
        $contentLength = strlen($content);

        for ($i = $startPos; $i < $contentLength; $i++) {
            if (substr($content, $i, 4) === '<div') {
                $tagStack[] = 'div';
                $i += 3; // Skip to end of '<div'
            } elseif (substr($content, $i, 6) === '</div>') {
                if (empty($tagStack)) {
                    throw new RuntimeException("Unmatched closing div tag, signature = $signature");
                }
                array_pop($tagStack);
                if (empty($tagStack)) {
                    return substr($content, $startPos, $i + 6 - $startPos);
                }
                $i += 5; // Skip to end of '</div>'
            }
        }

        throw new RuntimeException("Unclosed div tag, signature = $signature");
    }
}

class PhpHelper {
    static function getBlockSignatures($content) {
        preg_match_all('/\b(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+([a-zA-Z_]\w*)\s*\(/i', $content, $matches, PREG_OFFSET_CAPTURE);

        return array_map(function($match) use ($content) {
            return [$match[0], $match[1], Util::offsetToLineNumber($content, $match[1])];
        }, $matches[0]);
    }

    static function getBlockContents($content) {
        $signatures = self::getBlockSignatures($content);

        return BlockHelper::getBlockContentsFromSignatures($content, $signatures);
    }

    static function cleanupContent($content) {
        $content = self::removeEmptyBlocks($content);

        $content = self::removeUseStatements($content);

        $content = Util::removeComments($content);

        $content = Util::removeRedundantBlankLines($content);

        return $content;
    }

    static function removeEmptyBlocks($content) {
        $pattern = '/class\s+(\w+)\s*{[\s\n]*}/';

        return preg_replace($pattern, '', $content);
    }

    static function removeUseStatements($content) {
        $lines = explode("\n", $content);

        $cleanedLines = array_filter($lines, function($line) {
            return !preg_match('/^\s*use\s+/', trim($line));
        });

        return implode("\n", $cleanedLines);
    }
}

class JavascriptHelper {
    private const PATTERNS = [
        'CONST_ARROW' => '/\b(?:(const|let|var)\s+)([a-zA-Z_$][0-9a-zA-Z_$]*)\s*=\s*(?:async\s+)?(?:\(\s*.*?\s*\)\s*=>|([a-zA-Z_$][0-9a-zA-Z_$]*\s*=>))/',
        'FUNCTION' => '/\b(?:async\s+)?function\s+([a-zA-Z_$][0-9a-zA-Z_$]*)\s*\(/',
        'METHOD' => '/\b(?:async\s+)?([a-zA-Z_$][0-9a-zA-Z_$]*)\s*\(\s*\)\s*\{/',
        'STYLE' => '/<style[^>]*>/',
        'CONST_OBJECT' => '/\b(?:(const|let|var)\s+)([a-zA-Z_$][0-9a-zA-Z_$]*)\s*=\s*\{/',
        'APP_DIV' => '/<div\s+id="app"/'
    ];

    public static function getBlockSignatures(string $content): array {
        $blocks = [];

        foreach (self::PATTERNS as $type => $pattern) {
            preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE);
            $blocks = array_merge($blocks, self::processMatches($matches, $content, $type));
        }

        usort($blocks, function($a, $b) {
            return $a[2] <=> $b[2];
        });

        // IMPORTANT: Do 1 content block có thể khớp với nhiều pattern, nên nếu
        // có nhiều block có cùng lineNumber thì chúng ta chỉ giữ lại block
        // có offset nhỏ nhất
        return self::removeDuplicates($blocks);
    }

    private static function removeDuplicates(array $blocks): array {
        $uniqueBlocks = [];
        $lastLine = -1;
        $lastOffset = PHP_INT_MAX;

        foreach ($blocks as $block) {
            if ($block[2] !== $lastLine) {
                $uniqueBlocks[] = $block;
                $lastLine = $block[2];
                $lastOffset = $block[1];
            } elseif ($block[1] < $lastOffset) {
                array_pop($uniqueBlocks);
                $uniqueBlocks[] = $block;
                $lastOffset = $block[1];
            }
        }

        return $uniqueBlocks;
    }

    private static function processMatches(array $matches, string $content, string $type): array {
        if (empty($matches[0])) {
            return [];
        }

        return array_map(function($match) use ($content, $type, $matches) {
            $lineNumber = Util::offsetToLineNumber($content, $match[1]);
            return [$match[0], $match[1], $lineNumber, $type];
        }, $matches[0]);
    }

    static function getBlockContents($content) {
        $signatures = self:: getBlockSignatures($content);

        return BlockHelper::getBlockContentsFromSignatures($content, $signatures);
    }

    static function cleanupContent($content) {
        $content = self::removeEmptyBlocks($content);

        $content = self::removeSvgs($content);

        $content = self::removeBlankCodeLines($content);

        $content = Util::removeRedundantBlankLines($content);

        return $content;
    }

    static function removeEmptyBlocks($content) {
        $pattern = '/class\s+(\w+)\s*{[\s\n]*}/';

        return preg_replace($pattern, '', $content);
    }

    static function removeSvgs($content) {
        $pattern = '/<svg\b[^>]*>.*?<\/svg>/is';
        return preg_replace($pattern, '', $content);
    }

    static function removeBlankCodeLines($content) {
        $lines = explode("\n", $content);

        $cleanedLines = array_filter($lines, function($line) {
            return trim($line) !== ';';
        });

        return implode("\n", $cleanedLines);
    }
}

class MarkdownHelper {
    static function getBlockSignatures($content) {
        $pattern = '/^(#{2,3}\s.+)$/m';
        preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE);

        return array_map(function($match) use ($content) {
            return [trim($match[0]), $match[1], Util::offsetToLineNumber($content, $match[1])];
        }, $matches[0]);
    }

    static function getBlockContents($content) {
        $signatures = self::getBlockSignatures($content);

        return MarkdownBlockHelper::getBlockContentsFromSignatures($content, $signatures);
    }

    static function cleanupContent($content) {
        $content = Util::removeRedundantBlankLines($content);

        return $content;
    }
}

class MarkdownBlockHelper {
    static function getBlockContentsFromSignatures($content, $signatures) {
        $blocks = [];

        foreach ($signatures as $signature) {
            $offset = $signature[1];

            $blocks[$offset] = self::getBlockContentFromSignature($content, $signature[0], $offset);
        }

        return $blocks;
    }

    static function getBlockContentFromSignature($content, $signature, $startPos) {
        // Mỗi block bao gồm tất cả nội dung từ signature của nó đến signature tiếp theo có cùng cấp hoặc cấp cao hơn, hoặc đến hết nội dung nếu không có signature nào thỏa mãn điều kiện đó.
        // 1. Xác định vị trí bắt đầu của signature.
        // 2. Đếm số lượng dấu `#` trong signature để xác định cấp độ của heading.
        // 3. Sử dụng `preg_match_all` để tìm tất cả các heading lines sau signature.
        // 4. Loop qua các heading tìm được:
        //   - Nếu tìm thấy một heading có cấp độ bằng hoặc nhỏ hơn (tức là có số lượng `#` ít hơn hoặc bằng) signature, đó sẽ là điểm kết thúc của block.
        //   - Nếu không tìm thấy, block sẽ kết thúc ở cuối nội dung.
        // 5. Trích xuất nội dung block từ vị trí bắt đầu đến vị trí kết thúc.

        $signatureLevel = substr_count(trim($signature), '#');

        preg_match_all('/^(#{1,6})\s+(.+)$/m', $content, $matches, PREG_OFFSET_CAPTURE, $startPos + strlen($signature));

        $endPos = strlen($content);

        foreach ($matches[0] as $index => $match) {
            $currentLevel = strlen($matches[1][$index][0]);
            if ($currentLevel <= $signatureLevel) {
                $endPos = $match[1];
                break;
            }
        }

        return substr($content, $startPos, $endPos - $startPos);
    }
}

class FileProcessor {
    private const ENCRYPT_KEY = '5cfd4b523caaf3f434b7bebf0f8c8323';
    private const TOKEN_STORAGE_FILE = __DIR__ . '/tokens.json';
    private const TOKEN_LENGTH = 8;
    private const ENCRYPT_METHOD = 'AES-256-CBC';

    private const ACTION_LIST_FILES = 'list_files';
    private const ACTION_GET_FILE_CONTENT = 'get_file_content';
    private const ACTION_SAVE_FILE_CONTENT = 'save_file_content';
    private const ACTION_GET_FILE_CONTENTS = 'get_file_contents';
    private const ACTION_GET_FILE_CONTENTS_OUTLINE = 'get_file_contents_outline';
    private const ACTION_DOWNLOAD_FILES = 'download_files';
    private const ACTION_LIST_CONTENT_BLOCKS = 'list_content_blocks';
    private const ACTION_SEARCH_IN_FILES = 'search_in_files';
    private const ACTION_REPLACE_IN_FILES = 'replace_in_files';
    private const ACTION_RENAME_FILE = 'rename_file';
    private const ACTION_DELETE_FILE = 'delete_file';
    private const ACTION_GENERATE_PUBLIC_LINKS = 'generate_public_links';
    private const ACTION_LOGIN = 'login';
    private const ACTION_LOGOUT = 'logout';
    private const ACTION_CHANGE_PASSWORD = 'change_password';
    private const ACTION_GET_RAW_CONTENT = 'get_raw_content';

    public function main(): void {
        // Read POST body (JSON) if exists
        $raw = file_get_contents('php://input');
        $postData = json_decode($raw, true) ?: [];

        // Merge GET params with POST data (POST takes priority)
        $input = array_merge($_GET, $postData);

        $action = $input['action'] ?? '';

        try {
            // Public actions (no auth required)
            if ($action === self::ACTION_LOGIN) {
                header('Content-Type: application/json');
                $username = $input['username'] ?? '';
                $password = $input['password'] ?? '';
                $result = Auth::login($username, $password);
                echo json_encode(['success' => true, 'data' => $result]);
                return;
            }

            if ($action === self::ACTION_LOGOUT) {
                header('Content-Type: application/json');
                Auth::logout();
                echo json_encode(['success' => true]);
                return;
            }

            if ($action === self::ACTION_GET_RAW_CONTENT) {
                $token = $input['token'] ?? '';
                $this->downloadFile($token);
                return;
            }

            // All other actions require authentication
            $user = Auth::authenticate();

            switch ($input['action'] ?? '') {
                case self::ACTION_LIST_FILES:
                    header('Content-Type: application/json');
                    $path = $input['path'] ?? '';
                    echo json_encode(['files' => $this->getFiles($path)]);
                    break;
                case self::ACTION_GET_FILE_CONTENT:
                    header('Content-Type: application/json');
                    $path = $input['path'] ?? '';
                    echo json_encode(['content' => is_readable($path) ? file_get_contents($path) : '']);
                    break;
                case self::ACTION_SAVE_FILE_CONTENT:
                    header('Content-Type: application/json');
                    $path = $input['path'] ?? '';
                    $content = $input['content'] ?? '';
                    file_put_contents($path, $content);
                    echo json_encode(['success' => true]);
                    break;
                case self::ACTION_GET_FILE_CONTENTS:
                    header('Content-Type: application/json');
                    $paths = $input['paths'] ?? [];
                    $blocks = $input['blocks'] ?? [];
                    echo json_encode(['contents' => $this->getFileContentsWithSpecificBlocks($paths, $blocks)]);
                    break;
                case self::ACTION_GET_FILE_CONTENTS_OUTLINE:
                    header('Content-Type: application/json');
                    $paths = $input['paths'] ?? [];
                    echo json_encode(['contents' => $this->getFileContentsSimplified($paths)]);
                    break;
                case self::ACTION_DOWNLOAD_FILES:
                    $paths = $input['paths'] ?? [];
                    $this->downloadFiles($paths);
                    break;
                case self::ACTION_LIST_CONTENT_BLOCKS:
                    header('Content-Type: application/json');
                    $path = $input['path'] ?? '';
                    echo json_encode(['blocks' => $this->getBlockInfos($path)]);
                    break;
                case self::ACTION_SEARCH_IN_FILES:
                    header('Content-Type: application/json');
                    $paths = $input['paths'] ?? [];
                    $pattern = (string)($input['pattern'] ?? '');
                    $options = (array)($input['options'] ?? []);
                    echo json_encode($this->searchInFiles($paths, $pattern, $options));
                    break;
                case self::ACTION_REPLACE_IN_FILES:
                    header('Content-Type: application/json');
                    $paths = $input['paths'] ?? [];
                    $pattern = (string)($input['pattern'] ?? '');
                    $replacement = (string)($input['replacement'] ?? '');
                    $options = (array)($input['options'] ?? []);
                    echo json_encode($this->replaceInFiles($paths, $pattern, $replacement, $options));
                    break;
                case self::ACTION_RENAME_FILE:
                    header('Content-Type: application/json');
                    $path = $input['path'] ?? '';
                    $newName = $input['new_name'] ?? '';
                    echo json_encode($this->renameFile($path, $newName));
                    break;
                case self::ACTION_DELETE_FILE:
                    header('Content-Type: application/json');
                    $path = $input['path'] ?? '';
                    echo json_encode($this->deleteFile($path));
                    break;
                case self::ACTION_GENERATE_PUBLIC_LINKS:
                    header('Content-Type: application/json');
                    $paths = $input['paths'] ?? [];
                    echo json_encode(['links' => $this->generatePublicLinks($paths)]);
                    break;
                case self::ACTION_CHANGE_PASSWORD:
                    header('Content-Type: application/json');
                    Auth::changePassword(
                        $user['username'],
                        $input['old_password'] ?? '',
                        $input['new_password'] ?? ''
                    );
                default:
                    header('Content-Type: application/json');
                    echo json_encode(['error' => 'Invalid action']);
            }
        } catch (Exception $e) {
            header('Content-Type: application/json');
            echo json_encode(['error' => $e->getMessage()]);
        }
    }

private function encryptPath(string $path): string {
        $ivLength = openssl_cipher_iv_length(self::ENCRYPT_METHOD);
        $iv = openssl_random_pseudo_bytes($ivLength);

        $encrypted = openssl_encrypt($path, self::ENCRYPT_METHOD, self::ENCRYPT_KEY, 0, $iv);

        // Combine iv + encrypted, encode as base64url (safe for URL)
        $combined = base64_encode($iv . $encrypted);
        return strtr($combined, '+/', '-_');
    }

    private function decryptPath(string $token): string {
        $combined = base64_decode(strtr($token, '-_', '+/'));

        $ivLength = openssl_cipher_iv_length(self::ENCRYPT_METHOD);
        $iv = substr($combined, 0, $ivLength);
        $encrypted = substr($combined, $ivLength);

        $path = openssl_decrypt($encrypted, self::ENCRYPT_METHOD, self::ENCRYPT_KEY, 0, $iv);

        if ($path === false) {
            throw new RuntimeException('Invalid or expired token');
        }

        return $path;
    }

private function generateShortToken(string $path): string {
        // Generate random 8-char alphanumeric token
        $token = bin2hex(random_bytes(self::TOKEN_LENGTH / 2));

        // Load existing tokens
        $tokens = $this->loadTokens();

        // Store mapping
        $tokens[$token] = [
            'path' => $path,
            'created_at' => time()
        ];

        // Save back
        $this->saveTokens($tokens);

        return $token;
    }

    private function getPathFromToken(string $token): string {
        $tokens = $this->loadTokens();

        if (!isset($tokens[$token])) {
            throw new RuntimeException('Invalid or expired token');
        }

        return $tokens[$token]['path'];
    }

    private function loadTokens(): array {
        if (!file_exists(self::TOKEN_STORAGE_FILE)) {
            return [];
        }

        $json = file_get_contents(self::TOKEN_STORAGE_FILE);
        $tokens = json_decode($json, true);

        return is_array($tokens) ? $tokens : [];
    }

    private function saveTokens(array $tokens): void {
        // Optional: Cleanup old tokens (older than 30 days)
        $cutoff = time() - (30 * 24 * 60 * 60);
        $tokens = array_filter($tokens, function($data) use ($cutoff) {
            return ($data['created_at'] ?? 0) > $cutoff;
        });

        file_put_contents(
            self::TOKEN_STORAGE_FILE,
            json_encode($tokens, JSON_PRETTY_PRINT),
            LOCK_EX
        );
    }

    private function generatePublicLinks_v0(array $paths): array {
        $links = [];
        foreach ($paths as $path) {
            if (!is_file($path) || !is_readable($path)) {
                continue;
            }
            try {
                $token = $this->encryptPath($path);
                $links[] = ['path' => $path, 'token' => $token];
            } catch (Exception $e) {
                // Skip on error
            }
        }
        return $links;
    }

    private function generatePublicLinks(array $paths): array {
        $links = [];
        foreach ($paths as $path) {
            if (!is_file($path) || !is_readable($path)) {
                continue;
            }
            try {
                $token = $this->generateShortToken($path); // Changed
                $links[] = ['path' => $path, 'token' => $token];
            } catch (Exception $e) {
                // Skip on error
            }
        }
        return $links;
    }

    private function downloadFile(string $token): void {
        // $filePath = $this->decryptPath($token);
        $filePath = $this->getPathFromToken($token);

        if (!is_file($filePath) || !is_readable($filePath)) {
            http_response_code(404);
            exit('File not found or not readable');
        }

        $fileName = basename($filePath);

        // Detect MIME type
        $mime = 'application/octet-stream';
        if (function_exists('finfo_open')) {
            $f = finfo_open(FILEINFO_MIME_TYPE);
            if ($f) {
                $detected = finfo_file($f, $filePath);
                if ($detected) $mime = $detected;
                finfo_close($f);
            }
        } elseif (function_exists('mime_content_type')) {
            $detected = @mime_content_type($filePath);
            if ($detected) $mime = $detected;
        }

        header('Content-Type: ' . $mime);
        header('Content-Disposition: inline; filename="' . $fileName . '"');
        header('Content-Length: ' . filesize($filePath));
        header('Cache-Control: public, max-age=3600');
        header('Expires: ' . gmdate('D, d M Y H:i:s', time() + 3600) . ' GMT');

        readfile($filePath);
        exit;
    }

    private function renameFile(string $path, string $newName): array {
        if (!$path || !$newName) {
            throw new RuntimeException('Path and new name are required');
        }

        if (!file_exists($path)) {
            throw new RuntimeException('File not found');
        }

        if (!is_writable($path)) {
            throw new RuntimeException('File is not writable');
        }

        // Validate new name (no path separators)
        if (strpos($newName, '/') !== false || strpos($newName, '\\') !== false) {
            throw new RuntimeException('Invalid file name');
        }

        $dir = dirname($path);
        $newPath = $dir . DIRECTORY_SEPARATOR . $newName;

        if (file_exists($newPath)) {
            throw new RuntimeException('A file with that name already exists');
        }

        if (!rename($path, $newPath)) {
            throw new RuntimeException('Failed to rename file');
        }

        return ['success' => true, 'new_path' => $newPath];
    }

    private function deleteFile(string $path): array {
        if (!$path || !file_exists($path)) {
            throw new RuntimeException('File not found');
        }

        if (!unlink($path)) {
            throw new RuntimeException('Failed to delete file');
        }

        return ['success' => true];
    }

    private function searchInFiles(array $paths, string $pattern, array $options = []): array {
        $caseSensitive = $options['case_sensitive'] ?? true;
        $useRegex      = $options['regex'] ?? false;

        $matched = [];
        $scanned = 0; $matchedFiles = 0; $totalMatches = 0;

        foreach ($paths as $filePath) {
            if (!is_file($filePath) || !is_readable($filePath)) {
                continue;
            }
            $scanned++;

            $content = file_get_contents($filePath);
            $lines = preg_split("/\r\n|\n|\r/", $content);
            $fileTotal = 0; $lineHits = [];

            foreach ($lines as $i => $line) {
                [$occ, $indices] = $this->countOccurrencesAdv($line, $pattern, $caseSensitive, $useRegex);
                if ($occ > 0) {
                    $fileTotal += $occ;
                    $lineHits[] = [
                        'line' => $i + 1,
                        'occurrences' => $occ,
                        'indices' => $indices,
                        'preview' => $this->trimPreview($line), // giữ preview ngắn cho UI
                    ];
                }
            }

            if ($fileTotal > 0) {
                $matched[] = [
                    'path'  => $filePath,
                    'total' => $fileTotal,
                    'lines' => $lineHits
                ];
                $matchedFiles++;
                $totalMatches += $fileTotal;
            }
        }

        return [
            'summary' => [
                'scanned' => $scanned,
                'matched_files' => $matchedFiles,
                'total_matches' => $totalMatches
            ],
            'matches' => $matched
        ];
    }

    private function replaceInFiles(array $paths, string $pattern, string $replacement, array $options = []): array {
        $caseSensitive = $options['case_sensitive'] ?? true;
        $useRegex      = $options['regex'] ?? false;
        $dryRun        = $options['dry_run'] ?? false;

        $changed = [];
        $processed = 0; $totalReplaced = 0; $changedFiles = 0;

        foreach ($paths as $filePath) {
            if (!is_file($filePath) || !is_readable($filePath) || !is_writable($filePath)) {
                continue;
            }
            $processed++;

            $content = file_get_contents($filePath);
            [$updated, $replaced] = $this->replaceAllAdv($content, $pattern, $replacement, $caseSensitive, $useRegex);

            if ($replaced > 0) {
                if (!$dryRun) {
                    file_put_contents($filePath, $updated);
                }
                $changed[] = ['path' => $filePath, 'replaced' => $replaced];
                $changedFiles++;
                $totalReplaced += $replaced;
            }
        }

        return [
            'summary' => [
                'processed' => $processed,
                'changed_files' => $changedFiles,
                'total_replaced' => $totalReplaced,
                'dry_run' => $dryRun
            ],
            'changed' => $changed
        ];
    }

    private function countOccurrencesAdv(string $haystack, string $pattern, bool $caseSensitive, bool $useRegex): array {
        if ($pattern === '') {
            return [0, []];
        }

        $indices = [];
        if ($useRegex) {
            $flags = $caseSensitive ? '' : 'i';
            if (@preg_match_all('/' . $pattern . '/' . $flags, $haystack, $m, PREG_OFFSET_CAPTURE)) {
                foreach ($m[0] as $hit) {
                    $indices[] = $hit[1];
                }
            }
            return [count($indices), $indices];
        }

        // literal, UTF-8 safe
        $needle = $caseSensitive ? $pattern : mb_strtolower($pattern, 'UTF-8');
        $text   = $caseSensitive ? $haystack : mb_strtolower($haystack, 'UTF-8');

        $pos = 0; $nlen = mb_strlen($needle, 'UTF-8');
        if ($nlen === 0) {
            return [0, []];
        }

        while (($p = mb_strpos($text, $needle, $pos, 'UTF-8')) !== false) {
            $indices[] = $p;
            $pos = $p + $nlen;
        }
        return [count($indices), $indices];
    }

    private function replaceAllAdv(string $subject, string $pattern, string $replacement, bool $caseSensitive, bool $useRegex): array {
        if ($pattern === '') {
            return [$subject, 0];
        }

        if ($useRegex) {
            $flags = $caseSensitive ? '' : 'i';
            $count = 0;
            $result = @preg_replace('/' . $pattern . '/' . $flags, $replacement, $subject, -1, $count);
            if ($result === null) {
                // Regex invalid – giữ behavior rõ ràng
                throw new RuntimeException('Invalid regex pattern');
            }
            return [$result, $count];
        }

        // literal (multibyte-safe)
        $count = 0; $res = '';
        $text = $caseSensitive ? $subject : mb_strtolower($subject, 'UTF-8');
        $pat  = $caseSensitive ? $pattern : mb_strtolower($pattern, 'UTF-8');
        $pos = 0; $nlen = mb_strlen($pat, 'UTF-8');

        while (($p = mb_strpos($text, $pat, $pos, 'UTF-8')) !== false) {
            $res .= mb_substr($subject, $pos, $p - $pos, 'UTF-8') . $replacement;
            $pos = $p + $nlen; $count++;
        }
        $res .= mb_substr($subject, $pos, null, 'UTF-8');
        return [$res, $count];
    }

    private function trimPreview(string $line): string {
        $line = trim($line);
        // giới hạn preview cho gọn UI
        if (strlen($line) > 140) {
            return substr($line, 0, 140) . '…';
        }
        return $line;
    }

    private function getFiles(string $dir): array {
        $files = [];

        // Sử dụng Set (array flip) cho O(1) lookup thay vì O(n) với in_array
        $excludeDirs = array_flip([
            '.git',
            '.svn',
            'vendor',
            'node_modules',
            '.idea',
            '.vscode',
            'cache',
            'tmp',
            'temp',
            'logs',
            'dist',
            'build',
            'target'
        ]);

        if (!is_dir($dir)) {
            return $files;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                function ($file, $key, $iterator) use ($excludeDirs) {
                    // Chỉ filter directories, không cần check files
                    if (!$file->isDir()) {
                        return true;
                    }
                    $dirName = $file->getBasename();
                    // O(1) lookup thay vì O(n)
                    return !isset($excludeDirs[$dirName]);
                }
            ),
            RecursiveIteratorIterator::SELF_FIRST // Trả về cả directories và files
        );

        foreach ($iterator as $file) {
            $files[] = [
                'path' => $file->getPathname(),
                'type' => $file->isDir() ? 'directory' : 'file'
            ];
        }

        return $files;
    }

    private function downloadFiles(array $paths) {
        // Lọc bỏ các path không hợp lệ
        $paths = array_values(array_filter($paths, function ($p) {
            return is_string($p) && is_file($p) && is_readable($p);
        }));

        if (count($paths) === 0) {
            http_response_code(404);
            exit('No readable file to download');
        }

        // Trường hợp chỉ 1 file: trả thẳng với đúng MIME type
        if (count($paths) === 1) {
            $filePath = $paths[0];
            $fileName = basename($filePath);

            // Lấy mime type
            $mime = 'application/octet-stream';
            if (function_exists('finfo_open')) {
                $f = finfo_open(FILEINFO_MIME_TYPE);
                if ($f) {
                    $detected = finfo_file($f, $filePath);
                    if ($detected) $mime = $detected;
                    finfo_close($f);
                }
            } elseif (function_exists('mime_content_type')) {
                $detected = @mime_content_type($filePath);
                if ($detected) $mime = $detected;
            }

            // Header cho tải/preview đúng loại
            header('Content-Type: ' . $mime);
            // inline để browser preview (image/pdf/audio/video). Có thể đổi thành attachment nếu muốn luôn tải về.
            header('Content-Disposition: inline; filename="' . $fileName . '"');
            header('Content-Length: ' . filesize($filePath));
            header('Cache-Control: no-cache, must-revalidate');
            header('Expires: 0');

            readfile($filePath);
            exit;
        }

        // Nhiều file: tạo ZIP tạm
        $zipFile = tempnam(sys_get_temp_dir(), 'zip_');
        $zip = new ZipArchive();
        if ($zip->open($zipFile, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            throw new RuntimeException('Không thể tạo file ZIP');
        }

        // Tìm prefix thư mục chung để tạo đường dẫn tương đối đẹp trong ZIP
        $dirs = array_map('dirname', $paths);
        $baseDir = $dirs[0];
        foreach ($dirs as $dir) {
            $i = 0;
            $max = min(strlen($baseDir), strlen($dir));
            while ($i < $max && $baseDir[$i] === $dir[$i]) $i++;
            $baseDir = rtrim(substr($baseDir, 0, $i), DIRECTORY_SEPARATOR);
        }
        if ($baseDir === '') {
            $baseDir = dirname($paths[0]);
        }

        foreach ($paths as $filePath) {
            $relativePath = ltrim(str_replace($baseDir, '', $filePath), DIRECTORY_SEPARATOR);
            if ($relativePath === '' || $relativePath === basename($baseDir)) {
                $relativePath = basename($filePath);
            }
            $zip->addFile($filePath, $relativePath);
        }
        $zip->close();

        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="downloaded_files_' . date('Ymd_His') . '.zip"');
        header('Content-Length: ' . filesize($zipFile));
        header('Cache-Control: no-cache, must-revalidate');
        header('Expires: 0');

        readfile($zipFile);
        unlink($zipFile);
        exit;
    }

    private function getBlockInfos(string $path): array {
        if (!is_readable($path)) {
            return [];
        }

        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $content = file_get_contents($path);

        if ($extension === 'php') {
            $signatures = PhpHelper::getBlockSignatures($content);
        } else if ($extension === 'md') {
            $signatures = MarkdownHelper::getBlockSignatures($content);
        } else {
            $signatures = JavascriptHelper::getBlockSignatures($content);
        }

        $blockInfos = BlockHelper::getBlockInfosFromSignatures($content, $signatures);

        return $blockInfos;
    }

    private function getFileContentsWithSpecificBlocks(array $paths, array $blocks): array {
        $contents = [];

        foreach ($paths as $path) {
            if (is_readable($path) && is_file($path)) {
                $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                $content = file_get_contents($path);

                $selectedOffsets = $blocks[$path] ?? [];

                if (empty($selectedOffsets)) {
                    $contents[] = ['path' => $path, 'content' => trim($content)];

                    continue;
                }

                $blockInfos = $this->getBlockInfos($path);

                $selectedOffsets = $this->expandWithParentsOffsets($blockInfos, $selectedOffsets);

                if (!empty($selectedOffsets)) {
                    $deletedRanges = $this->getDeletedRanges($blockInfos, $selectedOffsets);

                    if (!empty($deletedRanges)) {
                        $content = $this->deleteContentRanges($content, $deletedRanges);
                        $content = $this->cleanupContent($extension, $content);
                    }
                }

                $contents[] = ['path' => $path, 'content' => trim($content)];
            }
        }

        return $contents;
    }

    private function getBlockContents(string $extension, string $content): array {
        if ($extension === 'php') {
            return PhpHelper::getBlockContents($content);
        } else if ($extension === 'md') {
            return MarkdownHelper::getBlockContents($content);
        }
        return JavascriptHelper::getBlockContents($content);
    }

    private function expandWithParentsOffsets(array $blockInfos, array $selectedOffsets): array {
        $map = array_column($blockInfos, null, 'offset');
        $results = array_flip($selectedOffsets);

        foreach ($selectedOffsets as $offset) {
            if (isset($map[$offset]['parentOffsets'])) {
                foreach ($map[$offset]['parentOffsets'] as $parentOffset) {
                    $results[$parentOffset] = true;
                }
            }
        }

        return array_keys($results);
    }

    private function getDeletedRanges(array $blockInfos, array $selectedOffsets): array {
        $deletedRanges = [];

        foreach ($blockInfos as $blockInfo) {
            $offset = $blockInfo['offset'];
            $endPos = $blockInfo['endPos'];

            if (!in_array($offset, $selectedOffsets)) {
                $deletedRanges[] = [$offset, $endPos];
            }
        }

        return $deletedRanges;
    }

    private function cleanupContent(string $extension, string $content): string {
        if ($extension === 'php') {
            return PhpHelper::cleanupContent($content);
        } else if ($extension === 'md') {
            return MarkdownHelper::cleanupContent($content);
        }
        return JavascriptHelper::cleanupContent($content);
    }

    private function deleteContentRanges(string $content, array $deletedRanges): string {
        if (empty($deletedRanges)) {
            return $content;
        }

        usort($deletedRanges, function($a, $b) {
            return $a[0] - $b[0];
        });

        $mergedRanges = $this->mergeRanges($deletedRanges);

        $result = '';
        $lastEnd = 0;

        foreach ($mergedRanges as $range) {
            $result .= substr($content, $lastEnd, $range[0] - $lastEnd);
            $lastEnd = $range[1];
        }

        $result .= substr($content, $lastEnd);

        return $result;
    }

    private function mergeRanges(array $ranges): array {
        $mergedRanges = [];
        $currentRange = $ranges[0];

        foreach ($ranges as $range) {
            if ($range[0] <= $currentRange[1]) {
                $currentRange[1] = max($currentRange[1], $range[1]);
            } else {
                $mergedRanges[] = $currentRange;
                $currentRange = $range;
            }
        }
        $mergedRanges[] = $currentRange;

        return $mergedRanges;
    }

    private function getFileContentsSimplified(array $paths): array {
        $contents = [];

        foreach ($paths as $path) {
            if (is_readable($path) && is_file($path)) {
                $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

                $content = file_get_contents($path);

                $content = (new SimplifiedContentHelper)->getSimplifiedContent($content, $extension);

                $contents[] = ['path' => $path, 'content' => trim($content)];
            }
        }

        return $contents;
    }
}

class SimplifiedContentHelper {
    /**
     * View outline cho file JS:
     * - Quét từ trái sang phải, tìm header kết thúc bằng "{", consume đến "}" khớp → thu về [signature => fullBody]
     * - Đệ quy vào body để lấy các chữ ký con
     * - Render outline: ngoài class/container thì function có con in "{ ... }" (không in implementation), nếu không có con in ";"
     *   - Arrow function KHÔNG có block body bị bỏ qua
     *   - `export default { ... }` được coi là container và hiển thị
     */
    public function getSimplifiedContent($content, $fileExtension = '')
    {
        $src = (string)$content;
        if ($src === '') return "// (empty)\n";

        // 1) Tạo bản mask để regex & đếm ngoặc ổn định
        $mask = $this->jsMask($src);

        // 2) Scan top-level → nodes (đã có children đệ quy)
        $nodes = $this->jsScanRange($src, $mask, 0, strlen($src), 'top');

        // 3) Render outline
        $out = $this->renderSimplifiedOutline($nodes);
        return trim($out) === '' ? "// (no declarations found)\n" : $out;
    }

    /* ============================================================
       ===============         SCANNER CORE         ===============
       ============================================================ */

    /**
     * Quét một khoảng [start, end) và trả về danh sách node có children (đệ quy).
     * $ctx: 'top' | 'class' | 'object' | 'block'
     */
    private function jsScanRange(string $src, string $mask, int $start, int $end, string $ctx): array
    {
        $nodes = [];
        $cursor = $start;

        while ($cursor < $end) {
            $match = $this->jsEarliestMatch($mask, $cursor, $ctx);
            if (!$match) break;

            $fullStart = $match['fullStart'];
            $openBrace = $match['openBrace'];
            $sigStart  = $match['sigStart'];
            $type      = $match['type'];

            // Loại control-flow cho function/method/assigned/... (không áp cho class/container)
            if ($type !== 'class' && $type !== 'container') {
                if ($this->jsIsControlFlowBefore($mask, $openBrace)) {
                    $cursor = $fullStart + 1;
                    continue;
                }
            }

            $closeBrace = $this->findMatchingBraceJs($src, $openBrace);
            if ($closeBrace < 0 || $closeBrace > $end) {
                $cursor = $fullStart + 1;
                continue;
            }

            // Signature nguyên văn từ src
            $sig = rtrim(substr($src, $sigStart, $openBrace - $sigStart));

            // Normalize cho các dạng gán/arrow/method field/property có block
            if ($type === 'assigned' || $type === 'classField' || $type === 'propAssigned') {
                $sig = $this->normalizeAssignedSignature($sig);
            }

            $full = substr($src, $sigStart, $closeBrace - $sigStart + 1);

            // Xác định context con
            $childCtx = 'block';
            if ($type === 'class')          $childCtx = 'class';
            elseif ($type === 'container')  $childCtx = 'object';

            $children = $this->jsScanRange($src, $mask, $openBrace + 1, $closeBrace, $childCtx);

            $nodes[] = [
                'kind'      => $type,                // 'class' | 'function' | 'method' | 'assigned' | 'classField' | 'propAssigned' | 'container'
                'signature' => $sig,
                'full'      => $full,                // để cần mapping [signature => body] ở cấp hiện tại
                'bodyStart' => $openBrace + 1,
                'bodyEnd'   => $closeBrace,
                'children'  => $children
            ];

            $cursor = $closeBrace + 1;
        }

        return $nodes;
    }

    /**
     * Tìm match gần nhất theo ngữ cảnh.
     * Trả về ['type','fullStart','openBrace','sigStart'] hoặc null.
     */
    private function jsEarliestMatch(string $mask, int $offset, string $ctx): ?array
    {
        $patterns = [];

        // Container export default { ... }
        $patterns['container'] =
            '/((?:export\s+default)\s*)\{/m';

        // Class (hỗ trợ extends/implements, generic)
        $patterns['class'] =
            '/(((?:export\s+(?:default\s+)?)?\s*class)\s+[A-Za-z_\$][A-Za-z0-9_\$]*' .
            '(?:\s*<[^{}>]*>)?' .
            '(?:\s+extends\s+[^{]+)?' .
            '(?:\s+implements\s+[^{]+)?' .
            ')\s*\{/m';

        // Function declaration (named) – hỗ trợ export/default/async/TS return type
        $patterns['function'] =
            '/(((?:export\s+(?:default\s+)?)?(?:async\s+)?function)\s+[A-Za-z_\$][A-Za-z0-9_\$]*' .
            '(?:\s*<[^{}>]*>)?\s*\([^)]*\)\s*(?:\:\s*[^;{]+)?)\s*\{/m';

        // Function anonymous (function (...) { ... }) – hỗ trợ export default
        $patterns['anon'] =
            '/(((?:export\s+(?:default\s+)?)?(?:async\s+)?function)\s*\([^)]*\)\s*(?:\:\s*[^;{]+)?)\s*\{/m';

        // Assigned / arrow có block body: const/let/var (có thể kèm export)
        $patterns['assigned'] =
            '/(((?:export\s+)?(?:const|let|var)\s+[A-Za-z_\$][A-Za-z0-9_\$]*\s*=\s*(?:async\s*)?' .
            '(?:function\s*\([^)]*\)|\([^)]*\)\s*=>|[A-Za-z_\$][A-Za-z0-9_\$]*\s*=>)\s*(?:\:\s*[^;{]+)?))\s*\{/m';

        // Class field có function/arrow (TS modifiers, #private)
        $patterns['classField'] =
            '/(?<!\S)' .
            '(' .
                '(?:(?:public|private|protected|readonly|override|abstract|static)\s+)*' .
                '#?[A-Za-z_\$][A-Za-z0-9_\$]*' .
                '(?:\s*:\s*[^=]+)?\s*=\s*(?:async\s*)?' .
                '(?:function\s*\([^)]*\)|\([^)]*\)\s*=>|[A-Za-z_\$][A-Za-z0-9_\$]*\s*=>)' .
                '(?:\s*:\s*[^;{]+)?' .
            ')\s*\{/m';

        // Object-literal property: foo: function(){}, foo: (...) => {}, v.v.
        $patterns['propAssigned'] =
            '/(?<!\S)' .
            '(' .
                '(?:#?[A-Za-z_\$][A-Za-z0-9_\$]*|\[\s*[^]]+\s*\])' .
                '\s*:\s*(?:async\s*)?(?:function\s*\([^)]*\)|\([^)]*\)\s*=>|[A-Za-z_\$][A-Za-z0-9_\$]*\s*=>)' .
                '(?:\s*:\s*[^;{]+)?' .
            ')\s*\{/m';

        // JS method trong class hoặc object-literal
        // - hỗ trợ modifiers TS, async, get/set, constructor, #private, computed key (ở mức cơ bản)
        $patterns['method'] =
            '/(?<!\S)' .
            '(' .
                '(?:(?:public|private|protected|readonly|override|abstract|static)\s+)*' .
                '(?:async\s+)?' .
                '(?:get|set)?\s*' .
                '(?:constructor|#?[A-Za-z_\$][A-Za-z0-9_\$]*|\[\s*[^]]+\s*\])' .
                '\s*\([^)]*\)\s*(?:\:\s*[^;{]+)?' .
            ')\s*\{/m';

        // Chọn theo context
        $use = [];
        if ($ctx === 'top') {
            // Ở top-level: cho phép container, class, function, assigned, anon
            $use = ['container','class','function','assigned','anon'];
        } elseif ($ctx === 'class' || $ctx === 'object') {
            // Trong class/object: ưu tiên method/field/prop, rồi function/assigned/anon, rồi class lồng
            $use = ['method','classField','propAssigned','function','assigned','anon','class'];
        } else { // 'block'
            // Trong block: function/assigned/anon + class (nested). Không có method rời.
            $use = ['function','assigned','anon','class'];
        }

        $best = null;
        foreach ($use as $type) {
            if (preg_match($patterns[$type], $mask, $m, PREG_OFFSET_CAPTURE, $offset)) {
                $sigStart  = $m[1][1];
                $fullText  = $m[0][0];
                $fullStart = $m[0][1];
                $openBrace = $fullStart + strlen($fullText) - 1; // '{' ở cuối match
                if ($best === null || $fullStart < $best['fullStart']) {
                    $best = compact('type','sigStart','fullStart','openBrace');
                }
            }
        }
        return $best;
    }

    /* ============================================================
       ===============        MASK & MATCHERS        ===============
       ============================================================ */

    /**
     * Mask JS: che chuỗi, comment, template literal (kèm ${}), và regex literal.
     * Giữ nguyên \n để offset và dòng không đổi.
     */
    private function jsMask(string $s): string
    {
        $len = strlen($s);
        $out = $s;

        $inLine=false; $inBlock=false; $inSQ=false; $inDQ=false; $inBT=false;
        $tplDepth=0;

        $inRegex=false; $inRegexClass=false; // /.../ và [...]
        for ($i = 0; $i < $len; $i++) {
            $c = $s[$i];
            $p = $i > 0 ? $s[$i-1] : '';
            $n = $i+1 < $len ? $s[$i+1] : '';

            // Regex literal
            if ($inRegex) {
                if ($inRegexClass) {
                    if ($p !== '\\' && $c === ']') $inRegexClass = false;
                    $out[$i] = ($c === "\n") ? "\n" : ' ';
                    continue;
                }
                if ($p !== '\\' && $c === '[') {
                    $inRegexClass = true;
                    $out[$i] = ' ';
                    continue;
                }
                if ($p !== '\\' && $c === '/') {
                    $inRegex = false;
                    $out[$i] = ' ';
                    // mask luôn các flag sau regex, ví dụ /a/i
                    $j = $i+1;
                    while ($j < $len && preg_match('/[a-z]/i', $s[$j])) {
                        $out[$j] = ' ';
                        $j++;
                    }
                    $i = $j-1;
                    continue;
                }
                $out[$i] = ($c === "\n") ? "\n" : ' ';
                continue;
            }

            // Comment line
            if ($inLine) {
                $out[$i] = ($c === "\n") ? "\n" : ' ';
                if ($c === "\n") $inLine = false;
                continue;
            }
            // Comment block
            if ($inBlock) {
                $out[$i] = ($c === "\n") ? "\n" : ' ';
                if ($p === '*' && $c === '/') $inBlock = false;
                continue;
            }
            // Template literal
            if ($inBT) {
                $out[$i] = ($c === "\n") ? "\n" : ' ';
                if ($p === '\\') continue;
                if ($c === '`' && $tplDepth === 0) { $inBT = false; continue; }
                if ($c === '{' && $i > 0 && $s[$i-1] === '$') { $tplDepth++; continue; }
                if ($c === '}' && $tplDepth > 0) { $tplDepth--; continue; }
                continue;
            }
            // Single / Double quotes
            if ($inSQ) {
                $out[$i] = ($c === "\n") ? "\n" : ' ';
                if ($p !== '\\' && $c === "'") $inSQ = false;
                continue;
            }
            if ($inDQ) {
                $out[$i] = ($c === "\n") ? "\n" : ' ';
                if ($p !== '\\' && $c === '"') $inDQ = false;
                continue;
            }

            // Mở comment
            if ($c === '/' && $n === '*') {
                $inBlock = true;
                $out[$i] = ' '; $out[$i+1] = ' '; $i++;
                continue;
            }
            if ($c === '/' && $n === '/') {
                $inLine = true;
                $out[$i] = ' '; $out[$i+1] = ' '; $i++;
                continue;
            }

            // Mở string / template
            if ($c === "'") { $inSQ = true; $out[$i] = ' '; continue; }
            if ($c === '"') { $inDQ = true; $out[$i] = ' '; continue; }
            if ($c === '`') { $inBT = true; $tplDepth = 0; $out[$i] = ' '; continue; }

            // Heuristic: mở regex literal khi gặp '/' ở "biểu thức context"
            if ($c === '/' && $n !== '/' && $n !== '*') {
                if ($this->looksLikeRegexStart($s, $i)) {
                    $inRegex = true;
                    $out[$i] = ' ';
                    continue;
                }
            }
        }
        return $out;
    }

    /**
     * Heuristic xác định '/' có phải mở regex literal không (dựa trên tiền cảnh).
     */
    private function looksLikeRegexStart(string $s, int $pos): bool
    {
        $k = $pos - 1;
        // Bỏ qua whitespace
        while ($k >= 0 && preg_match('/\s/', $s[$k])) $k--;
        if ($k < 0) return true; // đầu file

        // Ký tự trước thuộc nhóm "mở biểu thức" → khả năng cao là regex literal
        if (preg_match('/[=(:,\[\{;!?~+\-*\/%<>&|^]/', $s[$k])) return true;

        // Từ khóa
        $tail = substr($s, max(0, $k - 10), 11);
        if (preg_match('/\b(return|case|throw|yield)\s*$/', $tail)) return true;

        return false;
    }

    /**
     * true nếu ngay trước '{' là control-flow header (if/for/while/…)
     */
    private function jsIsControlFlowBefore(string $mask, int $bracePos): bool
    {
        $look = 260;
        $from = max(0, $bracePos - $look);
        $snip = substr($mask, $from, $bracePos - $from);
        return (bool)preg_match('/\b(if|for|while|switch|catch|with|do|try|else|finally)\s*(\([^)]*\))?\s*$/', $snip);
    }

    /**
     * Tìm '}' khớp cho '{' tại $openPos (bỏ qua chuỗi/comment/template/regex).
     */
    private function findMatchingBraceJs(string $s, int $openPos): int
    {
        $len = strlen($s);
        $depth = 0;

        $inLine=false; $inBlock=false; $inSQ=false; $inDQ=false; $inBT=false; $tplDepth=0;
        $inRegex=false; $inRegexClass=false;

        for ($i = $openPos; $i < $len; $i++) {
            $c = $s[$i];
            $p = $i > 0 ? $s[$i-1] : '';
            $n = $i+1 < $len ? $s[$i+1] : '';

            if ($inRegex) {
                if ($inRegexClass) {
                    if ($p !== '\\' && $c === ']') $inRegexClass = false;
                    continue;
                }
                if ($p !== '\\' && $c === '[') { $inRegexClass = true; continue; }
                if ($p !== '\\' && $c === '/') { $inRegex = false;
                    // skip flags
                    $j = $i+1; while ($j < $len && preg_match('/[a-z]/i', $s[$j])) $j++; $i = $j-1; continue; }
                continue;
            }

            if ($inLine) { if ($c === "\n") $inLine = false; continue; }
            if ($inBlock){ if ($p === '*' && $c === '/') $inBlock = false; continue; }
            if ($inBT)   {
                if ($p === '\\') continue;
                if ($c === '`' && $tplDepth === 0) { $inBT = false; continue; }
                if ($c === '{' && $i > 0 && $s[$i-1] === '$') { $tplDepth++; continue; }
                if ($c === '}' && $tplDepth > 0) { $tplDepth--; continue; }
                continue;
            }
            if ($inSQ)   { if ($p !== '\\' && $c === "'") $inSQ = false; continue; }
            if ($inDQ)   { if ($p !== '\\' && $c === '"') $inDQ = false; continue; }

            // mở/đóng comment
            if ($c === '/' && $n === '*') { $inBlock = true; $i++; continue; }
            if ($c === '/' && $n === '/') { $inLine  = true; $i++; continue; }

            // mở chuỗi / template
            if ($c === "'") { $inSQ = true; continue; }
            if ($c === '"') { $inDQ = true; continue; }
            if ($c === '`') { $inBT = true; $tplDepth = 0; continue; }

            // regex literal
            if ($c === '/' && $n !== '/' && $n !== '*') {
                if ($this->looksLikeRegexStart($s, $i)) { $inRegex = true; continue; }
            }

            if ($c === '{') { $depth++; continue; }
            if ($c === '}') {
                $depth--;
                if ($depth === 0) return $i;
                continue;
            }
        }
        return -1;
    }

    /**
     * Chuẩn hoá các dạng gán/arrow/field/property có block → "function name(params)"
     */
    private function normalizeAssignedSignature(string $sig): string
    {
        $t = trim($sig);

        // (export )?const name = async function (a,b)
        if (preg_match('/^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_\$][A-Za-z0-9_\$]*)\s*=\s*(?:async\s*)?function\s*\(([^)]*)\)$/', $t, $m)) {
            return "function {$m[1]}({$m[2]})";
        }
        // (export )?const name = (a,b) =>
        if (preg_match('/^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_\$][A-Za-z0-9_\$]*)\s*=\s*\(([^)]*)\)\s*=>$/', $t, $m)) {
            return "function {$m[1]}({$m[2]})";
        }
        // (export )?const name = a =>
        if (preg_match('/^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_\$][A-Za-z0-9_\$]*)\s*=\s*([A-Za-z_\$][A-Za-z0-9_\$]*)\s*=>$/', $t, $m)) {
            return "function {$m[1]}({$m[2]})";
        }
        // class field: (modifiers )?#?name = async function(a,b)
        if (preg_match('/^(?:(?:public|private|protected|readonly|override|abstract|static)\s+)*#?([A-Za-z_\$][A-Za-z0-9_\$]*)\s*(?:\:\s*[^=]+)?\s*=\s*(?:async\s*)?function\s*\(([^)]*)\)$/', $t, $m)) {
            return "function {$m[1]}({$m[2]})";
        }
        // class field: name = (a,b) =>
        if (preg_match('/^(?:(?:public|private|protected|readonly|override|abstract|static)\s+)*#?([A-Za-z_\$][A-Za-z0-9_\$]*)\s*(?:\:\s*[^=]+)?\s*=\s*\(([^)]*)\)\s*=>$/', $t, $m)) {
            return "function {$m[1]}({$m[2]})";
        }
        // class field: name = x =>
        if (preg_match('/^(?:(?:public|private|protected|readonly|override|abstract|static)\s+)*#?([A-Za-z_\$][A-Za-z0-9_\$]*)\s*(?:\:\s*[^=]+)?\s*=\s*([A-Za-z_\$][A-Za-z0-9_\$]*)\s*=>$/', $t, $m)) {
            return "function {$m[1]}({$m[2]})";
        }
        // object prop: key: function(a,b)
        if (preg_match('/^(#?[A-Za-z_\$][A-Za-z0-9_\$]*|\[\s*[^]]+\s*\])\s*:\s*(?:async\s*)?function\s*\(([^)]*)\)$/', $t, $m)) {
            $name = $m[1];
            return "function {$name}({$m[2]})";
        }
        // object prop: key: (a,b) =>
        if (preg_match('/^(#?[A-Za-z_\$][A-Za-z0-9_\$]*|\[\s*[^]]+\s*\])\s*:\s*\(([^)]*)\)\s*=>$/', $t, $m)) {
            $name = $m[1];
            return "function {$name}({$m[2]})";
        }
        return $t;
    }

    /* ============================================================
       ===============           RENDER            ===============
       ============================================================ */

    private function renderSimplifiedOutline(array $nodes, int $depth = 0, string $parentCtx = 'top'): string
    {
        $pad = str_repeat(' ', 4 * $depth);
        $out = '';

        foreach ($nodes as $n) {
            $sig  = rtrim($n['signature']);
            $kind = $n['kind'];
            $hasChildren = !empty($n['children']);

            if ($kind === 'class') {
                $out .= $pad . $sig . " {\n";
                $out .= $this->renderSimplifiedOutline($n['children'], $depth + 1, 'class');
                $out .= $pad . "}\n";
            } elseif ($kind === 'container') {
                // export default { ... } – coi là container
                $out .= $pad . $sig . " {\n";
                $out .= $this->renderSimplifiedOutline($n['children'], $depth + 1, 'object');
                $out .= $pad . "}\n";
            } else {
                // function/method/assigned/...
                $isInClassOrObject = ($parentCtx === 'class' || $parentCtx === 'object');
                if ($isInClassOrObject) {
                    // Trong class/container: in kiểu declaration ;
                    $out .= $pad . $sig . ";\n";
                } else {
                    if ($hasChildren) {
                        $out .= $pad . $sig . " {\n";
                        $out .= $this->renderSimplifiedOutline($n['children'], $depth + 1, 'block');
                        $out .= $pad . "}\n";
                    } else {
                        $out .= $pad . $sig . ";\n";
                    }
                }
            }
        }
        return $out;
    }
}

$processor = new FileProcessor();
$processor->main();
