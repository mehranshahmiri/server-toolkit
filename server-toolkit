<?php
/**
 * SERVER TOOLKIT ULTIMATE
 * The All-In-One Single-File System Administration Suite
 *
 * @author  Mehran Shahmiri <www.mehranshahmiri.com>
 * @version 4.0.0 (Ultimate)
 * @license MIT
 *
 * [!] SECURITY INSTRUCTIONS:
 * 1. Change the $CONFIG['AUTH_HASH'] immediately.
 * 2. Rename this file to a random string (e.g., admin_x92z.php).
 * 3. Delete this file via the "Self Destruct" button when finished.
 */

// ==============================================================================
// 1. CONFIGURATION
// ==============================================================================

// Default Password: "password"
// Generate new hash using the tool inside or password_hash('pass', PASSWORD_BCRYPT)
$CONFIG = [
    'AUTH_HASH'       => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
    'ALLOWED_IPS'     => [], // Example: ['123.45.67.89']
    'SESSION_NAME'    => 'ST_ULTIMATE_SESS',
    'MAX_LOGIN_ATTEMPTS' => 5,
    'LOCKOUT_TIME'    => 900,
    
    // Root path for File Manager (Default: Directory of this script)
    // Change to $_SERVER['DOCUMENT_ROOT'] to manage the whole site.
    'ROOT_PATH'       => __DIR__, 

    // Feature Flags
    'ENABLE_FILE_WRITE' => true,   // Edit, Delete, Upload, Chmod, Zip
    'ENABLE_DB_WRITE'   => true,   // Execute non-SELECT queries
    'ENABLE_NET_TOOLS'  => true,   // Port scan, SMTP test
];

// ==============================================================================
// 2. CORE SYSTEM
// ==============================================================================

session_name($CONFIG['SESSION_NAME']);
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Security Headers
header("X-Frame-Options: SAMEORIGIN");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");

// IP Guard
if (!empty($CONFIG['ALLOWED_IPS']) && !in_array($_SERVER['REMOTE_ADDR'], $CONFIG['ALLOWED_IPS'])) {
    http_response_code(403); die("⛔ Access Denied");
}

// Rate Limiting
if (!isset($_SESSION['attempts'])) $_SESSION['attempts'] = 0;
if ($_SESSION['attempts'] >= $CONFIG['MAX_LOGIN_ATTEMPTS']) {
    if (time() - $_SESSION['last_attempt'] < $CONFIG['LOCKOUT_TIME']) die("⛔ Too many failed attempts. Try again in 15 minutes.");
    else $_SESSION['attempts'] = 0;
}

// CSRF
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));

// Helper Functions
function json_resp($data, $code = 200) {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

function verify_csrf() {
    $h = getallheaders();
    $t = $_POST['csrf'] ?? $h['X-CSRF-Token'] ?? '';
    if (!hash_equals($_SESSION['csrf'], $t)) json_resp(['error' => 'CSRF Validation Failed'], 403);
}

function safe_path($path) {
    global $CONFIG;
    // Normalize slashes
    $path = str_replace('\\', '/', $path);
    // Resolve base path
    $base = realpath($CONFIG['ROOT_PATH']);
    if (!$base) $base = $CONFIG['ROOT_PATH']; // Fallback if file doesn't exist yet
    
    // Construct target path
    // If path is absolute and starts with base, use it. Otherwise append to base.
    if (strpos($path, $base) === 0) {
        $target = $path;
    } else {
        $target = $base . '/' . $path;
    }

    // Clean up .. 
    $realTarget = realpath($target);
    
    // If file exists, check strict containment
    if ($realTarget) {
        if (strpos($realTarget, $base) === 0) return $realTarget;
        return false;
    }

    // If file doesn't exist (creating new), check directory containment
    $dir = dirname($target);
    $realDir = realpath($dir);
    if ($realDir && strpos($realDir, $base) === 0) return $target;
    
    return false;
}

function fmt_size($bytes) {
    if ($bytes == 0) return '0 B';
    $u = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = floor(log($bytes, 1024));
    return round($bytes / pow(1024, $i), 2) . ' ' . $u[$i];
}

// ==============================================================================
// 3. AUTHENTICATION
// ==============================================================================

if (isset($_GET['logout'])) { session_destroy(); header("Location: " . $_SERVER['PHP_SELF']); exit; }

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    if (password_verify($_POST['password'], $CONFIG['AUTH_HASH'])) {
        $_SESSION['user'] = true; $_SESSION['attempts'] = 0;
        header("Location: " . $_SERVER['PHP_SELF']); exit;
    }
    $_SESSION['attempts']++; $_SESSION['last_attempt'] = time();
    $login_err = "Invalid credentials";
}

if (empty($_SESSION['user'])) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Server Toolkit Ultimate</title>
        <style>
            :root { --bg: #0f172a; --panel: #1e293b; --accent: #3b82f6; --text: #f8fafc; --border: #334155; }
            body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; height: 100vh; display: grid; place-items: center; margin: 0; }
            .login { background: var(--panel); padding: 2.5rem; border-radius: 1rem; width: 100%; max-width: 400px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); border: 1px solid var(--border); }
            h1 { font-size: 1.5rem; margin: 0 0 1.5rem; text-align: center; color: var(--accent); }
            input { width: 100%; padding: 0.75rem; background: #0f172a; border: 1px solid var(--border); color: white; border-radius: 0.5rem; margin-bottom: 1rem; box-sizing: border-box; }
            button { width: 100%; padding: 0.75rem; background: var(--accent); color: white; border: none; border-radius: 0.5rem; font-weight: bold; cursor: pointer; transition: .2s; }
            button:hover { filter: brightness(110%); }
            .err { color: #ef4444; font-size: 0.9rem; text-align: center; margin-bottom: 1rem; background: rgba(239, 68, 68, 0.1); padding: 10px; border-radius: 6px; }
            .credit { text-align: center; margin-top: 1.5rem; font-size: 0.8rem; color: #64748b; }
            .credit a { color: #64748b; text-decoration: none; border-bottom: 1px dotted #64748b; }
        </style>
    </head>
    <body>
        <div class="login">
            <h1>System Access</h1>
            <?php if(isset($login_err)) echo "<div class='err'>$login_err</div>"; ?>
            <form method="post">
                <input type="password" name="password" placeholder="Enter Password" required autofocus>
                <button type="submit" name="login">Initialize Session</button>
            </form>
            <div class="credit">Made with &hearts; by <a href="https://www.mehranshahmiri.com" target="_blank">Mehran Shahmiri</a></div>
        </div>
    </body>
    </html>
    <?php exit;
}

// ==============================================================================
// 4. API ROUTER
// ==============================================================================

if (isset($_GET['api'])) {
    verify_csrf();
    $req = $_GET['api'];
    
    try {
        switch ($req) {
            // --- DASHBOARD ---
            case 'stats':
                // Try reading /proc/meminfo for Linux
                $memTotal = $memFree = 0;
                if (@is_readable('/proc/meminfo')) {
                    $m = file_get_contents('/proc/meminfo');
                    if (preg_match('/MemTotal:\s+(\d+)/', $m, $mt)) $memTotal = $mt[1] * 1024;
                    if (preg_match('/MemAvailable:\s+(\d+)/', $m, $mf)) $memFree = $mf[1] * 1024;
                }
                // Fallback for non-Linux or restricted
                if ($memTotal == 0) { 
                    $memTotal = 1; $memFree = 1; // Prevent div by zero
                    $mem_txt = "N/A";
                } else {
                    $mem_txt = fmt_size($memTotal);
                }
                
                $load = function_exists('sys_getloadavg') ? sys_getloadavg() : [0,0,0];
                $diskTotal = disk_total_space($CONFIG['ROOT_PATH']);
                $diskFree = disk_free_space($CONFIG['ROOT_PATH']);
                
                json_resp([
                    'cpu_load' => $load,
                    'mem_total' => $mem_txt,
                    'mem_used_pct' => $memTotal > 1 ? round((($memTotal-$memFree)/$memTotal)*100) : 0,
                    'disk_total' => fmt_size($diskTotal),
                    'disk_used_pct' => round((($diskTotal-$diskFree)/$diskTotal)*100),
                    'os' => php_uname('s') . ' ' . php_uname('r'),
                    'php' => PHP_VERSION,
                    'server' => $_SERVER['SERVER_SOFTWARE'],
                    'server_ip' => $_SERVER['SERVER_ADDR'] ?? 'Unknown',
                    'client_ip' => $_SERVER['REMOTE_ADDR']
                ]);
                break;

            // --- FILE MANAGER ---
            case 'list':
                $p = safe_path($_POST['path'] ?? '');
                if (!$p || !is_dir($p)) json_resp(['error' => 'Invalid Directory'], 400);
                $scan = scandir($p);
                $files = [];
                foreach ($scan as $f) {
                    if ($f === '.' || $f === '..') continue;
                    $full = $p . '/' . $f;
                    $isDir = is_dir($full);
                    $files[] = [
                        'name' => $f,
                        'type' => $isDir ? 'dir' : 'file',
                        'size' => $isDir ? '-' : fmt_size(filesize($full)),
                        'perm' => substr(sprintf('%o', fileperms($full)), -4),
                        'mod'  => date("M j H:i", filemtime($full))
                    ];
                }
                // Return path relative to display
                $displayPath = $p;
                json_resp(['files' => $files, 'path' => $displayPath, 'sep'=>DIRECTORY_SEPARATOR]);
                break;
            
            case 'file_read':
                $p = safe_path($_POST['path']);
                if (!$p || !is_file($p)) json_resp(['error' => 'File not found'], 404);
                if (filesize($p) > 2000000) json_resp(['error' => 'File too large (>2MB) to edit inline'], 400);
                json_resp(['content' => file_get_contents($p)]);
                break;

            case 'file_save':
                if (!$CONFIG['ENABLE_FILE_WRITE']) json_resp(['error' => 'Write Disabled'], 403);
                $p = safe_path($_POST['path']);
                if (!$p) json_resp(['error' => 'Invalid path'], 400);
                if (file_put_contents($p, $_POST['content']) === false) json_resp(['error' => 'Write failed'], 500);
                json_resp(['status' => 'ok']);
                break;

            case 'delete':
                if (!$CONFIG['ENABLE_FILE_WRITE']) json_resp(['error' => 'Write Disabled'], 403);
                $p = safe_path($_POST['path']);
                if (!$p) json_resp(['error' => 'Invalid path'], 400);
                if (is_dir($p)) { @rmdir($p) ? json_resp(['status'=>'ok']) : json_resp(['error'=>'Dir not empty'], 400); }
                else { @unlink($p); json_resp(['status'=>'ok']); }
                break;

            case 'upload':
                if (!$CONFIG['ENABLE_FILE_WRITE']) json_resp(['error' => 'Write Disabled'], 403);
                $destDir = safe_path($_POST['path']);
                if (!$destDir || !is_dir($destDir)) json_resp(['error' => 'Invalid directory'], 400);
                if (isset($_FILES['file'])) {
                    $target = $destDir . '/' . basename($_FILES['file']['name']);
                    if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) json_resp(['status' => 'ok']);
                    else json_resp(['error' => 'Move failed'], 500);
                }
                break;

            case 'chmod':
                if (!$CONFIG['ENABLE_FILE_WRITE']) json_resp(['error' => 'Write Disabled'], 403);
                $p = safe_path($_POST['path']);
                $m = octdec($_POST['mode']);
                if (@chmod($p, $m)) json_resp(['status' => 'ok']);
                else json_resp(['error' => 'Chmod failed'], 500);
                break;

            case 'zip':
                if (!class_exists('ZipArchive')) json_resp(['error' => 'Zip ext missing'], 500);
                $p = safe_path($_POST['path']);
                $name = basename($p) . '_' . date('YmdHi') . '.zip';
                $target = dirname($p) . '/' . $name;
                $zip = new ZipArchive();
                if ($zip->open($target, ZipArchive::CREATE) === TRUE) {
                    if (is_dir($p)) {
                        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p), RecursiveIteratorIterator::LEAVES_ONLY);
                        foreach ($files as $file) {
                            if (!$file->isDir()) {
                                $fp = $file->getRealPath();
                                $zip->addFile($fp, substr($fp, strlen($p) + 1));
                            }
                        }
                    } else $zip->addFile($p, basename($p));
                    $zip->close();
                    json_resp(['status' => 'ok', 'file' => $name]);
                }
                json_resp(['error' => 'Zip failed'], 500);
                break;
            
            case 'unzip':
                if (!$CONFIG['ENABLE_FILE_WRITE']) json_resp(['error' => 'Write Disabled'], 403);
                $p = safe_path($_POST['path']);
                $dest = dirname($p);
                $zip = new ZipArchive();
                if ($zip->open($p) === TRUE) {
                    $zip->extractTo($dest);
                    $zip->close();
                    json_resp(['status' => 'ok']);
                }
                json_resp(['error' => 'Unzip failed'], 500);
                break;
            
            case 'mk_item':
                if (!$CONFIG['ENABLE_FILE_WRITE']) json_resp(['error' => 'Write Disabled'], 403);
                $base = safe_path($_POST['path']);
                $name = $_POST['name'];
                $type = $_POST['type'];
                $target = $base . '/' . $name;
                if(file_exists($target)) json_resp(['error' => 'Exists'], 400);
                if($type === 'dir') mkdir($target); else touch($target);
                json_resp(['status' => 'ok']);
                break;

            // --- DATABASE ---
            case 'db_query':
                try {
                    $pdo = new PDO($_POST['dsn'], $_POST['user'], $_POST['pass']);
                    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    $q = $_POST['query'];
                    // Basic safeguard
                    if (!$CONFIG['ENABLE_DB_WRITE'] && preg_match('/^(INSERT|UPDATE|DELETE|DROP|ALTER)/i', $q)) {
                        json_resp(['error' => 'Safe Mode: Read-only'], 403);
                    }
                    $stmt = $pdo->query($q);
                    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    json_resp(['rows' => $rows, 'count' => count($rows)]);
                } catch (Exception $e) { json_resp(['error' => $e->getMessage()], 500); }
                break;
            
            case 'db_dump':
                try {
                    $pdo = new PDO($_POST['dsn'], $_POST['user'], $_POST['pass']);
                    $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
                    $sql = "-- Server Toolkit Dump " . date('Y-m-d H:i') . "\n\n";
                    foreach ($tables as $t) {
                        $sql .= "DROP TABLE IF EXISTS `$t`;\n";
                        $row = $pdo->query("SHOW CREATE TABLE `$t`")->fetch(PDO::FETCH_NUM);
                        $sql .= $row[1] . ";\n\n";
                        $rows = $pdo->query("SELECT * FROM `$t` LIMIT 2000"); // Limit for safety
                        while($r = $rows->fetch(PDO::FETCH_ASSOC)) {
                            $sql .= "INSERT INTO `$t` VALUES (";
                            $vals = array_map(function($v) use ($pdo) { return $pdo->quote($v); }, array_values($r));
                            $sql .= implode(",", $vals) . ");\n";
                        }
                        $sql .= "\n";
                    }
                    json_resp(['sql' => $sql]);
                } catch (Exception $e) { json_resp(['error' => $e->getMessage()], 500); }
                break;

            // --- TOOLS ---
            case 'port_scan':
                $h = $_POST['host']; $p = $_POST['port'];
                $c = @fsockopen($h, $p, $en, $es, 2);
                json_resp(['open' => (bool)$c, 'err' => $es]);
                if($c) fclose($c);
                break;
            
            case 'smtp_test':
                $to = $_POST['to'];
                $s = mail($to, "Test from Server Toolkit", "It works!", "From: admin@" . $_SERVER['SERVER_NAME']);
                json_resp(['sent' => $s]);
                break;

            case 'dns_lookup':
                $ip = gethostbyname($_POST['host']);
                json_resp(['ip' => $ip]);
                break;

            case 'http_test':
                $url = $_POST['url'];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                curl_setopt($ch, CURLOPT_NOBODY, true);
                $res = curl_exec($ch);
                $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
                json_resp(['code' => $code]);
                break;
            
            case 'malware_scan':
                $p = $CONFIG['ROOT_PATH'];
                $sigs = ['base64_decode', 'eval(', 'shell_exec', 'passthru', 'system(', 'proc_open', 'GLOBALS'];
                $hits = [];
                $iter = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p));
                foreach ($iter as $f) {
                    if ($f->isFile() && $f->getExtension() === 'php') {
                        $c = file_get_contents($f);
                        foreach ($sigs as $sig) {
                            if (strpos($c, $sig) !== false) {
                                $hits[] = ['file' => substr($f->getPathname(), strlen($p)), 'sig' => $sig];
                                if (count($hits) > 50) break 2;
                            }
                        }
                    }
                }
                json_resp(['hits' => $hits]);
                break;
            
            case 'hash_gen':
                json_resp(['hash' => password_hash($_POST['pass'], PASSWORD_BCRYPT)]);
                break;

            case 'opcache_reset':
                if (function_exists('opcache_reset')) { opcache_reset(); json_resp(['status' => 'ok']); }
                else json_resp(['error' => 'OPCache not available'], 400);
                break;
            
            case 'self_destruct':
                if ($_POST['confirm'] === 'yes') {
                    unlink(__FILE__);
                    json_resp(['status' => 'bye']);
                }
                break;

            default: json_resp(['error' => 'Unknown Action'], 400);
        }
    } catch (Exception $e) { json_resp(['error' => $e->getMessage()], 500); }
}

// ==============================================================================
// 5. FRONTEND (SPA)
// ==============================================================================
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Server Toolkit Ultimate</title>
<style>
/* --- THEME & RESET --- */
:root {
    --bg-dark: #0f172a; --bg-panel: #1e293b; --bg-hover: #334155;
    --border: #334155; --text-main: #f8fafc; --text-muted: #94a3b8;
    --accent: #3b82f6; --accent-hover: #2563eb;
    --success: #10b981; --danger: #ef4444; --warning: #f59e0b;
    --shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06);
}
* { box-sizing: border-box; outline: none; }
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg-dark); color: var(--text-main); display: flex; height: 100vh; overflow: hidden; font-size: 14px; }
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg-dark); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

/* --- LAYOUT --- */
aside { width: 260px; background: var(--bg-panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; z-index: 20; flex-shrink: 0; }
.brand { padding: 1.5rem; font-size: 1.25rem; font-weight: 800; color: var(--text-main); border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; }
.brand span { color: var(--accent); }
.menu { flex: 1; overflow-y: auto; padding: 1rem 0; }
.menu-cat { padding: 0.75rem 1.5rem 0.25rem; font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.05em; }
.menu-btn { width: 100%; text-align: left; padding: 0.75rem 1.5rem; background: transparent; border: none; color: var(--text-muted); cursor: pointer; transition: 0.2s; display: flex; align-items: center; gap: 12px; font-weight: 500; font-size: 0.9rem; }
.menu-btn:hover { background: var(--bg-hover); color: var(--text-main); }
.menu-btn.active { background: rgba(59,130,246,0.1); color: var(--accent); border-right: 3px solid var(--accent); }
.menu-btn svg { width: 18px; height: 18px; opacity: 0.8; }
.aside-foot { padding: 1rem; border-top: 1px solid var(--border); text-align: center; font-size: 0.8rem; color: var(--text-muted); }
.aside-foot a { color: var(--text-muted); text-decoration: none; }
.aside-foot a:hover { color: var(--accent); }

main { flex: 1; overflow-y: auto; padding: 2rem; position: relative; }
.view { display: none; max-width: 1400px; margin: 0 auto; animation: fadein 0.3s ease; }
.view.active { display: block; }
@keyframes fadein { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }

/* --- COMPONENTS --- */
.card { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: var(--shadow); position: relative; }
.card h3 { margin: 0 0 1rem; font-size: 1.1rem; font-weight: 600; display: flex; justify-content: space-between; align-items: center; color: var(--text-main); }

.grid { display: grid; gap: 1.5rem; }
.grid-2 { grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); }
.grid-4 { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }

.stat-card { background: var(--bg-dark); border: 1px solid var(--border); padding: 1.25rem; border-radius: 0.5rem; text-align: center; }
.stat-val { font-size: 1.75rem; font-weight: 700; color: var(--accent); display: block; margin: 0.5rem 0; }
.stat-lbl { color: var(--text-muted); font-size: 0.85rem; font-weight: 500; }
.progress { height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; margin-top: 10px; }
.bar { height: 100%; background: var(--accent); transition: width 0.5s ease; }

.btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; background: var(--accent); color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 500; cursor: pointer; transition: 0.2s; font-size: 0.9rem; line-height: 1; }
.btn:hover { background: var(--accent-hover); }
.btn-sm { padding: 4px 10px; font-size: 0.8rem; }
.btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--text-muted); }
.btn-ghost:hover { border-color: var(--text-muted); color: var(--text-main); background: var(--bg-hover); }
.btn-danger { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
.btn-danger:hover { background: var(--danger); color: white; }

input, select, textarea { width: 100%; background: var(--bg-dark); border: 1px solid var(--border); color: var(--text-main); padding: 10px; border-radius: 6px; font-family: monospace; font-size: 0.9rem; transition: 0.2s; }
input:focus, select:focus, textarea:focus { border-color: var(--accent); }
::placeholder { color: var(--text-muted); opacity: 0.5; }

table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th { text-align: left; padding: 12px; color: var(--text-muted); border-bottom: 1px solid var(--border); font-weight: 600; background: rgba(0,0,0,0.1); }
td { padding: 12px; border-bottom: 1px solid var(--border); color: var(--text-main); vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--bg-hover); }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code { background: rgba(0,0,0,0.3); padding: 2px 5px; border-radius: 3px; color: #e2e8f0; font-family: monospace; font-size: 0.85em; }

/* --- MODALS & TOAST --- */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 50; display: none; align-items: center; justify-content: center; backdrop-filter: blur(2px); }
.modal { background: var(--bg-panel); width: 90%; max-width: 600px; max-height: 90vh; border-radius: 12px; border: 1px solid var(--border); display: flex; flex-direction: column; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
.modal-head { padding: 1.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; font-weight: bold; font-size: 1.1rem; color: var(--text-main); }
.modal-body { padding: 1.5rem; overflow-y: auto; flex: 1; }
.modal-foot { padding: 1rem 1.5rem; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 10px; background: var(--bg-dark); border-radius: 0 0 12px 12px; }

.toast { position: fixed; bottom: 20px; right: 20px; background: var(--bg-panel); color: var(--text-main); padding: 1rem 1.5rem; border-radius: 8px; border-left: 4px solid var(--accent); box-shadow: 0 10px 15px -3px rgba(0,0,0,0.5); transform: translateX(150%); transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1); z-index: 100; display: flex; align-items: center; gap: 10px; }
.toast.show { transform: translateX(0); }

/* --- RESPONSIVE --- */
@media (max-width: 768px) {
    body { flex-direction: column; }
    aside { width: 100%; flex: none; height: auto; border-right: none; border-bottom: 1px solid var(--border); }
    .menu { display: none; }
    .aside-foot { display: none; }
    .brand { justify-content: space-between; }
    .brand::after { content: 'Menu ☰'; font-size: 0.9rem; font-weight: normal; color: var(--text-muted); cursor: pointer; border: 1px solid var(--border); padding: 5px 10px; border-radius: 4px; }
    .brand:active + .menu { display: block; }
    main { padding: 1rem; }
    .grid-4 { grid-template-columns: 1fr 1fr; }
}
</style>
<script>
    // --- GLOBAL STATE ---
    const CSRF = "<?php echo $_SESSION['csrf']; ?>";
    let curPath = "";
    let curEditorPath = "";

    // --- ICONS ---
    const icons = {
        home: '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline>',
        folder: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>',
        db: '<ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>',
        terminal: '<polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line>',
        shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>',
        wifi: '<path d="M5 12.55a11 11 0 0 1 14.08 0"></path><path d="M1.42 9a16 16 0 0 1 21.16 0"></path><path d="M8.53 16.11a6 6 0 0 1 6.95 0"></path><line x1="12" y1="20" x2="12.01" y2="20"></line>',
        file: '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline>',
        tool: '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"></path>'
    };
    const icon = (n) => `<svg viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">${icons[n]}</svg>`;

    // --- API & UTIL ---
    async function post(act, data = {}) {
        const fd = new FormData();
        fd.append('csrf', CSRF);
        for (let k in data) fd.append(k, data[k]);
        try {
            const r = await fetch(`?api=${act}`, { method: 'POST', body: fd });
            const j = await r.json();
            if (r.status !== 200) throw new Error(j.error || 'Server Error');
            return j;
        } catch (e) {
            toast(e.message, 'err');
            return null;
        }
    }

    function toast(msg, type = 'info') {
        const t = document.getElementById('toast');
        t.innerHTML = `<span>${type==='err'?'⚠️':'✅'}</span> ${msg}`;
        t.style.borderLeftColor = type === 'err' ? 'var(--danger)' : 'var(--success)';
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 3000);
    }

    function switchView(id) {
        document.querySelectorAll('.view').forEach(el => el.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        document.querySelectorAll('.menu-btn').forEach(el => el.classList.remove('active'));
        if(event && event.currentTarget) event.currentTarget.classList.add('active');
        
        if (id === 'dash') loadStats();
        if (id === 'files') loadFiles('');
    }

    // --- MODULES ---
    
    // Dashboard
    async function loadStats() {
        const d = await post('stats');
        if (!d) return;
        
        const setBar = (id, val, txt) => {
            document.getElementById(id+'-val').innerText = txt;
            document.getElementById(id+'-bar').style.width = val + '%';
            document.getElementById(id+'-bar').style.backgroundColor = val > 80 ? 'var(--danger)' : 'var(--accent)';
        };

        setBar('cpu', d.cpu_load[0] * 10, d.cpu_load[0]); // Approx scale
        setBar('mem', d.mem_used_pct, d.mem_total);
        setBar('disk', d.disk_used_pct, d.disk_total);
        
        document.getElementById('sys-info').innerHTML = `
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                <div>OS: <code>${d.os}</code></div>
                <div>PHP: <code>${d.php}</code></div>
                <div>Software: <code>${d.server}</code></div>
                <div>Server IP: <code>${d.server_ip}</code></div>
            </div>
        `;
    }

    // File Manager
    async function loadFiles(path) {
        const d = await post('list', { path });
        if (!d) return;
        curPath = d.path;
        document.getElementById('cur-path').innerText = d.path || '/';
        
        const tbody = document.getElementById('file-list');
        tbody.innerHTML = '';
        
        // Up Dir
        if (d.path && d.path !== '.' && d.path !== '/') {
            const parent = d.path.includes(d.sep) ? d.path.substring(0, d.path.lastIndexOf(d.sep)) : '';
            tbody.innerHTML += `<tr onclick="loadFiles('${parent}')" style="cursor:pointer; background:rgba(255,255,255,0.05)"><td colspan="5">⤴ Up Level</td></tr>`;
        }

        d.files.forEach(f => {
            const fp = d.path ? d.path + d.sep + f.name : f.name;
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${f.type === 'dir' ? '📁' : '📄'} <a href="#" onclick="${f.type === 'dir' ? `loadFiles('${fp}')` : `editFile('${fp}')`}; return false;">${f.name}</a></td>
                <td>${f.size}</td>
                <td><a href="#" onclick="promptChmod('${fp}', '${f.perm}')">${f.perm}</a></td>
                <td>${f.mod}</td>
                <td>
                    <div style="display:flex; gap:5px;">
                        <button class="btn-ghost btn-sm" onclick="delItem('${fp}')">&times;</button>
                        ${f.type === 'dir' ? `<button class="btn-ghost btn-sm" onclick="zipItem('${fp}')">Zip</button>` : ''}
                        ${f.name.endsWith('.zip') ? `<button class="btn-ghost btn-sm" onclick="unzipItem('${fp}')">Unzip</button>` : ''}
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async function editFile(p) {
        const d = await post('file_read', { path: p });
        if (!d) return;
        curEditorPath = p;
        document.getElementById('editor-content').value = d.content;
        document.getElementById('editor-title').innerText = p;
        document.getElementById('editor-modal').style.display = 'flex';
    }

    async function saveFile() {
        const content = document.getElementById('editor-content').value;
        const res = await post('file_save', { path: curEditorPath, content });
        if (res) { toast('File Saved'); document.getElementById('editor-modal').style.display = 'none'; }
    }
    
    async function mkItem(type) {
        const name = prompt(`Enter Name for new ${type}:`);
        if(name) await post('mk_item', {path: curPath, name, type}) && loadFiles(curPath);
    }

    async function delItem(p) { if(confirm('Delete '+p+'?')) await post('delete', {path:p}) && loadFiles(curPath); }
    async function zipItem(p) { await post('zip', {path:p}) && loadFiles(curPath); }
    async function unzipItem(p) { await post('unzip', {path:p}) && loadFiles(curPath); }
    
    async function promptChmod(p, old) {
        const m = prompt('Enter new permissions (e.g. 0755):', '0'+old);
        if(m) await post('chmod', {path:p, mode:m}) && loadFiles(curPath);
    }
    
    async function uploadFile() {
        const f = document.getElementById('up-input').files[0];
        if(!f) return;
        const fd = new FormData();
        fd.append('csrf', CSRF);
        fd.append('path', curPath);
        fd.append('file', f);
        try {
            await fetch('?api=upload', {method:'POST', body:fd});
            toast('Uploaded'); loadFiles(curPath);
        } catch(e) { toast('Error', 'err'); }
    }

    // Database
    async function dbQuery() {
        const res = await post('db_query', {
            dsn: document.getElementById('db-dsn').value,
            user: document.getElementById('db-user').value,
            pass: document.getElementById('db-pass').value,
            query: document.getElementById('db-sql').value
        });
        const out = document.getElementById('db-out');
        out.innerHTML = '';
        if (res && res.rows) {
            if (res.rows.length === 0) { out.innerHTML = '<i>No rows returned.</i>'; return; }
            let h = '<table style="font-size:0.8rem"><thead><tr>';
            Object.keys(res.rows[0]).forEach(k => h += `<th>${k}</th>`);
            h += '</tr></thead><tbody>';
            res.rows.forEach(r => {
                h += '<tr>';
                Object.values(r).forEach(v => h += `<td>${v}</td>`);
                h += '</tr>';
            });
            out.innerHTML = h + '</tbody></table>';
        }
    }
    
    async function dbDump() {
        const res = await post('db_dump', {
            dsn: document.getElementById('db-dsn').value,
            user: document.getElementById('db-user').value,
            pass: document.getElementById('db-pass').value
        });
        if(res && res.sql) {
            const blob = new Blob([res.sql], {type:'text/plain'});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'dump.sql';
            a.click();
        }
    }

    // Security & Net
    async function scanMalware() {
        document.getElementById('scan-res').innerHTML = 'Scanning... (This may take a moment)';
        const d = await post('malware_scan');
        if(d && d.hits) {
            if(d.hits.length === 0) document.getElementById('scan-res').innerHTML = '<span style="color:var(--success)">No threats found.</span>';
            else {
                let h = '<ul style="color:var(--danger)">';
                d.hits.forEach(x => h += `<li><b>${x.file}</b> found <code>${x.sig}</code></li>`);
                document.getElementById('scan-res').innerHTML = h + '</ul>';
            }
        }
    }

    async function selfDestruct() {
        if(prompt('Type "DELETE" to confirm immediate removal of this tool.') === 'DELETE') {
            await post('self_destruct', {confirm:'yes'});
            alert('System destroyed. Bye.');
            window.location.reload();
        }
    }
    
    async function checkPort() {
        const r = await post('port_scan', {host: document.getElementById('port-host').value, port: document.getElementById('port-num').value});
        toast(r.open ? 'Port Open' : 'Port Closed/Filtered', r.open?'info':'err');
    }
    
    async function checkDNS() {
        const r = await post('dns_lookup', {host: document.getElementById('dns-host').value});
        if(r) alert("IP: " + r.ip);
    }
    
    async function checkHTTP() {
        const r = await post('http_test', {url: document.getElementById('http-url').value});
        if(r) alert("Status Code: " + r.code);
    }
    
    async function resetOP() {
        const r = await post('opcache_reset');
        if(r) toast('OPCache Reset');
    }

    // Init
    window.onload = () => loadStats();

</script>
</head>
<body>

<aside>
    <div class="brand">
        <script>document.write(icon('terminal'))</script> Server<span>Toolkit</span>
    </div>
    <div class="menu">
        <div class="menu-cat">System</div>
        <button class="menu-btn active" onclick="switchView('dash')"><script>document.write(icon('home'))</script> Dashboard</button>
        <button class="menu-btn" onclick="switchView('files')"><script>document.write(icon('folder'))</script> File Manager</button>
        <button class="menu-btn" onclick="switchView('db')"><script>document.write(icon('db'))</script> Database</button>
        
        <div class="menu-cat">Security & Net</div>
        <button class="menu-btn" onclick="switchView('sec')"><script>document.write(icon('shield'))</script> Security</button>
        <button class="menu-btn" onclick="switchView('net')"><script>document.write(icon('wifi'))</script> Network</button>
        <button class="menu-btn" onclick="switchView('utils')"><script>document.write(icon('tool'))</script> Utilities</button>
        
        <div class="menu-cat">Meta</div>
        <button class="menu-btn" onclick="selfDestruct()" style="color:var(--danger)"><script>document.write(icon('shield'))</script> Self Destruct</button>
        <a href="?logout" class="menu-btn"><script>document.write(icon('home'))</script> Logout</a>
    </div>
    <div class="aside-foot">
        Made with &hearts; by<br><a href="https://www.mehranshahmiri.com" target="_blank">Mehran Shahmiri</a>
    </div>
</aside>

<main>
    <!-- DASHBOARD -->
    <div id="dash" class="view active">
        <div class="grid grid-4">
            <div class="stat-card">
                <span class="stat-lbl">CPU Load</span>
                <span class="stat-val" id="cpu-val">-</span>
                <div class="progress"><div class="bar" id="cpu-bar" style="width:0%"></div></div>
            </div>
            <div class="stat-card">
                <span class="stat-lbl">Memory</span>
                <span class="stat-val" id="mem-val">-</span>
                <div class="progress"><div class="bar" id="mem-bar" style="width:0%"></div></div>
            </div>
            <div class="stat-card">
                <span class="stat-lbl">Disk</span>
                <span class="stat-val" id="disk-val">-</span>
                <div class="progress"><div class="bar" id="disk-bar" style="width:0%"></div></div>
            </div>
        </div>
        <br>
        <div class="card">
            <h3>Server Information</h3>
            <div id="sys-info" style="line-height:1.8">Loading...</div>
        </div>
        <div class="card">
            <h3>PHP Configuration Advisor</h3>
            <table>
                <tr><th>Setting</th><th>Value</th><th>Recommendation</th></tr>
                <tr><td>display_errors</td><td><?php echo ini_get('display_errors'); ?></td><td>Should be 0/Off</td></tr>
                <tr><td>max_execution_time</td><td><?php echo ini_get('max_execution_time'); ?></td><td>> 30s recommended</td></tr>
                <tr><td>upload_max_filesize</td><td><?php echo ini_get('upload_max_filesize'); ?></td><td>Depends on needs</td></tr>
                <tr><td>memory_limit</td><td><?php echo ini_get('memory_limit'); ?></td><td>>= 128M</td></tr>
                <tr><td>post_max_size</td><td><?php echo ini_get('post_max_size'); ?></td><td>> upload_max_filesize</td></tr>
            </table>
        </div>
    </div>

    <!-- FILES -->
    <div id="files" class="view">
        <div class="card">
            <h3>File Explorer <span style="font-weight:400; color:var(--text-muted); font-size:0.9rem" id="cur-path">/</span></h3>
            <div style="display:flex; gap:10px; margin-bottom:15px; flex-wrap:wrap;">
                <button class="btn btn-sm" onclick="mkItem('file')">New File</button>
                <button class="btn btn-sm" onclick="mkItem('dir')">New Folder</button>
                <div style="flex:1"></div>
                <input type="file" id="up-input" style="width:auto; padding:5px;">
                <button class="btn btn-sm" onclick="uploadFile()">Upload</button>
                <button class="btn btn-sm btn-ghost" onclick="loadFiles(curPath)">Refresh</button>
            </div>
            <div style="overflow-x:auto">
                <table id="file-table">
                    <thead><tr><th>Name</th><th>Size</th><th>Perms</th><th>Modified</th><th>Actions</th></tr></thead>
                    <tbody id="file-list"></tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- DATABASE -->
    <div id="db" class="view">
        <div class="card">
            <h3>SQL Commander</h3>
            <div class="grid grid-2">
                <input id="db-dsn" placeholder="mysql:host=127.0.0.1;dbname=test">
                <input id="db-user" placeholder="Username">
                <input id="db-pass" type="password" placeholder="Password">
            </div>
            <textarea id="db-sql" rows="5" placeholder="SELECT * FROM users LIMIT 10" style="margin-top:15px"></textarea>
            <div style="margin-top:10px; display:flex; gap:10px">
                <button class="btn" onclick="dbQuery()">Execute Query</button>
                <button class="btn btn-ghost" onclick="dbDump()">Download SQL Dump</button>
            </div>
        </div>
        <div class="card">
            <h3>Results</h3>
            <div id="db-out" style="overflow-x:auto; max-height:500px"></div>
        </div>
    </div>

    <!-- SECURITY -->
    <div id="sec" class="view">
        <div class="card">
            <h3>Malware Scanner</h3>
            <p style="color:var(--text-muted)">Scans for suspicious PHP functions (eval, base64_decode, shell_exec) recursively.</p>
            <button class="btn btn-danger" onclick="scanMalware()">Start Deep Scan</button>
            <div id="scan-res" style="margin-top:15px; background:var(--bg-dark); padding:10px; border-radius:6px; max-height:300px; overflow:auto"></div>
        </div>
        <div class="card">
            <h3>Password Hash Generator</h3>
            <div style="display:flex; gap:10px">
                <input id="hash-in" placeholder="String to hash">
                <button class="btn" onclick="post('hash_gen', {pass: document.getElementById('hash-in').value}).then(r => alert(r.hash))">Generate</button>
            </div>
        </div>
    </div>

    <!-- NETWORK -->
    <div id="net" class="view">
        <div class="card">
            <h3>Port Scanner</h3>
            <div style="display:flex; gap:10px">
                <input id="port-host" placeholder="Host (e.g. google.com)">
                <input id="port-num" placeholder="Port (e.g. 80)" style="width:100px">
                <button class="btn" onclick="checkPort()">Scan</button>
            </div>
        </div>
        <div class="card">
            <h3>DNS Lookup</h3>
            <div style="display:flex; gap:10px">
                <input id="dns-host" placeholder="Domain name">
                <button class="btn btn-ghost" onclick="checkDNS()">Lookup</button>
            </div>
        </div>
        <div class="card">
            <h3>HTTP Status Check</h3>
            <div style="display:flex; gap:10px">
                <input id="http-url" placeholder="https://example.com">
                <button class="btn btn-ghost" onclick="checkHTTP()">Ping</button>
            </div>
        </div>
        <div class="card">
            <h3>SMTP Tester</h3>
            <div style="display:flex; gap:10px">
                <input id="smtp-to" placeholder="Email Address">
                <button class="btn" onclick="post('smtp_test', {to:document.getElementById('smtp-to').value}).then(r => toast(r.sent?'Sent':'Failed', r.sent?'info':'err'))">Send Test</button>
            </div>
        </div>
    </div>

    <!-- UTILITIES -->
    <div id="utils" class="view">
        <div class="card">
            <h3>OPCache Management</h3>
            <p style="color:var(--text-muted)">Clear the PHP OpCache to force scripts to reload.</p>
            <button class="btn" onclick="resetOP()">Reset OPCache</button>
        </div>
    </div>

    <!-- MODALS -->
    <div id="editor-modal" class="modal-overlay">
        <div class="modal" style="height:80vh; width:80vw; max-width:900px;">
            <div class="modal-head">Editing: <span id="editor-title" style="font-weight:400; font-size:0.9rem; margin-left:10px; color:var(--accent);"></span></div>
            <div class="modal-body" style="padding:0">
                <textarea id="editor-content" style="width:100%; height:100%; border:none; resize:none; background:#0f172a; color:#f8fafc; padding:20px; font-family:monospace; line-height:1.5; font-size:14px;"></textarea>
            </div>
            <div class="modal-foot">
                <button class="btn btn-ghost" onclick="document.getElementById('editor-modal').style.display='none'">Cancel</button>
                <button class="btn" onclick="saveFile()">Save Changes</button>
            </div>
        </div>
    </div>

    <div id="toast" class="toast"></div>

</main>
</body>
</html>
