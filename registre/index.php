<?php
define('API_BASE',    'URL API');
define('TIMEOUT',     20);
define('HMAC_SECRET', 'HMAC SECRET');
define('NONCE_TTL',   120);
define('AES_MASTER',  'AES CODE');
define('CF_SECRET',   'CF Cloudflare');
define('TOKEN_TTL',   1200);

session_start();
if (!isset($_SESSION['used_nonces'])) $_SESSION['used_nonces'] = [];

if (!isset($_SESSION['aes_key'])) {
    $_SESSION['aes_key'] = random_bytes(32);
}

$verified   = $_SESSION['cf_verified']   ?? false;
$verifiedAt = $_SESSION['cf_verified_at'] ?? 0;

if (!$verified || (time() - $verifiedAt) > TOKEN_TTL) {
    session_write_close();
    header('Location: verify.php');
    exit;
}

function sec_reject($msg = 'Request validation failed.') {
    http_response_code(403);
    echo json_encode(['error' => $msg]);
    exit;
}

function derive_session_key(): string {
    return hash_hkdf('sha256', $_SESSION['aes_key'], 32, 'payload-enc-v1', AES_MASTER);
}

function aes_decrypt(string $b64): string|false {
    $raw = base64_decode($b64, true);
    if ($raw === false || strlen($raw) < 28) return false;
    $iv         = substr($raw, 0, 12);
    $tag        = substr($raw, 12, 16);
    $ciphertext = substr($raw, 28);
    $key        = derive_session_key();
    $plain      = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return $plain;
}

function decrypt_field(string $name): string {
    $val = $_POST[$name] ?? '';
    if ($val === '') return '';
    $dec = aes_decrypt($val);
    return ($dec === false) ? '' : $dec;
}

function verify_request() {
    $ts    = $_POST['_ga']  ?? '';
    $nonce = $_POST['_bd']  ?? '';
    $sig   = $_POST['_gl']  ?? '';
    $fp    = $_POST['_utm'] ?? '';
    $hp    = $_POST['_ref'] ?? '';

    if ($hp !== '') sec_reject();
    if (!$ts || !$nonce || !$sig || !$fp) sec_reject();

    $now = time();
    if (abs($now - (int)$ts) > NONCE_TTL) sec_reject('Request expired. Please try again.');

    if (in_array($nonce, $_SESSION['used_nonces'], true)) sec_reject();

    $ua_raw    = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $ua_hash   = substr(hash('sha256', $ua_raw), 0, 16);
    $fp_prefix = substr($fp, 0, 16);
    if (!hash_equals($ua_hash, $fp_prefix)) sec_reject();

    $origin = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? '';
    $host   = $_SERVER['HTTP_HOST'] ?? '';
    if ($origin !== '' && $host !== '' && strpos($origin, $host) === false) sec_reject();

    $skip = ['_ga','_bd','_gl','_utm','_ref'];
    $payload_keys = array_values(array_filter(array_keys($_POST), fn($k) => !in_array($k, $skip)));
    sort($payload_keys);
    $payload_str = implode('|', array_map(fn($k) => $k . '=' . $_POST[$k], $payload_keys));
    $expected    = hash_hmac('sha256', $ts . '.' . $nonce . '.' . $payload_str, HMAC_SECRET);
    if (!hash_equals($expected, $sig)) sec_reject();

    $_SESSION['used_nonces'][] = $nonce;
    if (count($_SESSION['used_nonces']) > 200)
        $_SESSION['used_nonces'] = array_slice($_SESSION['used_nonces'], -100);
}

$action = $_GET['action'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'GET' && $action === 'enc-token') {
    header('Content-Type: application/json; charset=utf-8');
    $key     = derive_session_key();
    $token   = hash_hmac('sha256', session_id() . '|enc-token', $key);
    echo json_encode(['t' => $token, 'k' => bin2hex($key)]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action !== '') {
    header('Content-Type: application/json; charset=utf-8');
    verify_request();

    switch ($action) {
        case 'send-otp':
            $url    = API_BASE . '/register/send-otp';
            $fields = [
                'author'    => decrypt_field('_f1'),
                'matricule' => decrypt_field('_f2'),
                'email'     => decrypt_field('_f3'),
                'phone'     => decrypt_field('_f4'),
                'coauthors' => decrypt_field('_f5'),
                'title'     => decrypt_field('_f6'),
            ];

            if (isset($_FILES['_fd']) && $_FILES['_fd']['error'] === UPLOAD_ERR_OK) {
                $fields['poster'] = new CURLFile(
                    $_FILES['_fd']['tmp_name'],
                    $_FILES['_fd']['type'] ?: 'application/pdf',
                    basename($_FILES['_fd']['name'])
                );
            }

            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $fields,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => TIMEOUT,
            ]);
            break;

        case 'verify-otp':
            $email = decrypt_field('_f3');
            $otp   = decrypt_field('_f8');
            $body  = json_encode(['email' => $email, 'otp' => $otp]);
            $url   = API_BASE . '/register/verify-otp';

            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $body,
                CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => TIMEOUT,
            ]);
            break;

        default:
            http_response_code(400);
            echo json_encode(['error' => 'Bad request']);
            exit;
    }

    $response  = curl_exec($ch);
    $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($curlError) {
        http_response_code(502);
        echo json_encode(['error' => 'Gateway error']);
        exit;
    }

    http_response_code($httpCode);
    echo $response;
    exit;
}

$deadline = mktime(23, 59, 59, 4, 13, 2026);
$now_gmt1 = time() + 3600;
$event_ended = $now_gmt1 > $deadline;
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Science Day 2026 — Project Submission</title>

  <style>
:root {
  --bg:           #0e1117;
  --surface:      #161b27;
  --surface-2:    #1d2535;
  --border:       rgba(99,130,167,0.18);
  --border-hover: rgba(99,130,167,0.4);
  --accent:       #5b8dee;
  --accent-dim:   rgba(91,141,238,0.12);
  --accent-glow:  rgba(91,141,238,0.25);
  --gold:         #c9a84c;
  --gold-dim:     rgba(201,168,76,0.12);
  --text-1:       #e8edf5;
  --text-2:       #8fa3be;
  --text-3:       #546882;
  --success:      #3ecf8e;
  --success-dim:  rgba(62,207,142,0.12);
  --error:        #f16b6b;
  --error-dim:    rgba(241,107,107,0.12);
  --radius-sm:    6px;
  --radius:       10px;
  --radius-lg:    16px;
  --radius-xl:    22px;
  --shadow-card:  0 0 0 1px var(--border), 0 24px 60px rgba(0,0,0,0.45);
  --shadow-input: 0 0 0 3px var(--accent-glow);
  --transition:   180ms cubic-bezier(0.4,0,0.2,1);
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 16px; scroll-behavior: smooth; }
body {
  font-family: system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text-1);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
  min-height: 100vh;
}
.bg-grid {
  position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background-image:
    linear-gradient(rgba(91,141,238,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(91,141,238,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
}
.bg-glow {
  position: fixed; top: -200px; left: 50%; transform: translateX(-50%);
  width: 900px; height: 600px; border-radius: 50%;
  background: radial-gradient(ellipse, rgba(91,141,238,0.06) 0%, transparent 70%);
  z-index: 0; pointer-events: none;
}
.page-wrapper {
  position: relative; z-index: 1;
  min-height: 100vh;
  display: flex; flex-direction: column;
}
.site-header {
  padding: 28px 24px 24px;
  border-bottom: 1px solid var(--border);
  background: rgba(22,27,39,0.8);
  backdrop-filter: blur(12px);
}
.header-inner {
  max-width: 760px; margin: 0 auto;
  display: flex; align-items: center; justify-content: space-between;
  gap: 16px; flex-wrap: wrap;
}
.header-logo { display: flex; align-items: center; gap: 14px; }
.logo-mark {
  width: 44px; height: 44px;
  border: 1px solid var(--border-hover);
  border-radius: 12px;
  display: flex; align-items: center; justify-content: center;
  overflow: hidden;
  background: var(--accent-dim);
  flex-shrink: 0;
}
.logo-mark img { width: 44px; height: 44px; object-fit: cover; border-radius: 12px; }
.logo-text { display: flex; flex-direction: column; }
.logo-uni {
  font-size: 0.75rem; font-weight: 500; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--text-2);
}
.logo-event {
  font-size: 1.2rem; font-weight: 700;
  color: var(--text-1); line-height: 1.2;
}
.header-badge {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: 0.7rem; font-weight: 600; letter-spacing: 0.1em;
  text-transform: uppercase; color: var(--success);
  background: var(--success-dim);
  border: 1px solid rgba(62,207,142,0.25);
  border-radius: 100px; padding: 5px 14px;
}
.header-tagline {
  max-width: 760px; margin: 10px auto 0;
  font-size: 0.78rem; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--text-3); text-align: center;
}
.main-content { flex: 1; padding: 40px 20px; }
.form-container {
  max-width: 680px; margin: 0 auto;
  background: var(--surface);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-card);
  overflow: hidden;
}
.form-header {
  display: flex; align-items: center; gap: 18px;
  padding: 28px 36px;
  background: linear-gradient(135deg, var(--surface-2) 0%, rgba(29,37,53,0.6) 100%);
  border-bottom: 1px solid var(--border);
}
.form-header-icon {
  width: 48px; height: 48px; flex-shrink: 0;
  border-radius: var(--radius);
  background: var(--accent-dim);
  border: 1px solid rgba(91,141,238,0.25);
  display: flex; align-items: center; justify-content: center;
  color: var(--accent);
}
.form-header-icon svg { width: 24px; height: 24px; }
.form-header h1 { font-size: 1.45rem; font-weight: 700; color: var(--text-1); line-height: 1.2; }
.form-description { font-size: 0.825rem; color: var(--text-2); margin-top: 3px; }
.req-star { color: var(--error); font-weight: 700; margin-left: 1px; }
.step-indicator {
  display: flex; align-items: center; justify-content: center;
  padding: 22px 36px;
  border-bottom: 1px solid var(--border);
  gap: 0;
}
.step { display: flex; flex-direction: column; align-items: center; gap: 6px; position: relative; }
.step-dot {
  width: 38px; height: 38px; border-radius: 50%;
  border: 2px solid var(--border-hover);
  background: var(--surface-2);
  display: flex; align-items: center; justify-content: center;
  color: var(--text-3);
  transition: var(--transition);
}
.step-dot svg { width: 16px; height: 16px; }
.step span {
  font-size: 0.68rem; font-weight: 600; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--text-3);
  transition: color var(--transition);
}
.step.active .step-dot { border-color: var(--accent); background: var(--accent-dim); color: var(--accent); box-shadow: 0 0 0 4px var(--accent-glow); }
.step.active span  { color: var(--accent); }
.step.done .step-dot { border-color: var(--success); background: var(--success-dim); color: var(--success); }
.step.done span { color: var(--success); }
.step-line {
  flex: 1; height: 1px; min-width: 36px; max-width: 80px;
  background: var(--border); margin: 0 4px; margin-bottom: 22px;
  transition: background var(--transition);
}
.form-step { display: none; padding: 32px 36px; animation: stepIn 0.28s ease both; }
.form-step.active { display: block; }
@keyframes stepIn { from { opacity: 0; transform: translateX(18px); } to { opacity: 1; transform: translateX(0); } }
.section-header {
  display: flex; align-items: center; gap: 12px;
  margin-bottom: 28px; padding-bottom: 16px;
  border-bottom: 1px solid var(--border);
}
.section-icon {
  width: 36px; height: 36px; flex-shrink: 0;
  border-radius: var(--radius-sm);
  background: var(--accent-dim);
  border: 1px solid rgba(91,141,238,0.2);
  display: flex; align-items: center; justify-content: center;
  color: var(--accent);
}
.section-icon svg { width: 18px; height: 18px; }
.section-header h2 { font-size: 1.1rem; font-weight: 600; color: var(--text-1); }
.fields-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.form-group { display: flex; flex-direction: column; gap: 7px; }
.form-group.full-width { grid-column: 1 / -1; }
.form-group label {
  display: flex; align-items: center; gap: 7px;
  font-size: 0.825rem; font-weight: 500; color: var(--text-2); letter-spacing: 0.01em;
}
.form-group label svg { width: 14px; height: 14px; color: var(--text-3); flex-shrink: 0; }
.optional-tag {
  margin-left: auto;
  font-size: 0.68rem; font-weight: 500; letter-spacing: 0.06em;
  text-transform: uppercase; color: var(--text-3);
  background: rgba(99,130,167,0.08);
  border-radius: 100px; padding: 2px 8px;
}
.input-wrap { position: relative; }
.input-wrap input,
.input-wrap textarea,
.input-wrap select {
  width: 100%; padding: 11px 14px;
  font-family: system-ui, -apple-system, sans-serif;
  font-size: 0.9rem; color: var(--text-1);
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  transition: border-color var(--transition), box-shadow var(--transition);
  outline: none; appearance: none;
}
.input-wrap input::placeholder,
.input-wrap textarea::placeholder { color: var(--text-3); }
.input-wrap input:focus,
.input-wrap textarea:focus,
.input-wrap select:focus { border-color: var(--accent); box-shadow: var(--shadow-input); }
.input-wrap input.err,
.input-wrap textarea.err,
.input-wrap select.err { border-color: var(--error); box-shadow: 0 0 0 3px rgba(241,107,107,0.18); }
.input-wrap textarea { resize: vertical; min-height: 90px; }
.field-error { font-size: 0.775rem; color: var(--error); display: none; align-items: center; gap: 5px; }
.field-error.show { display: flex; }
.step-nav {
  display: flex; justify-content: space-between; align-items: center;
  margin-top: 32px; padding-top: 24px;
  border-top: 1px solid var(--border);
}
.btn-next, .btn-submit {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 11px 24px;
  font-family: system-ui, -apple-system, sans-serif;
  font-size: 0.875rem; font-weight: 600; color: #fff;
  background: linear-gradient(135deg, #3a6fdb 0%, var(--accent) 100%);
  border: none; border-radius: var(--radius); cursor: pointer;
  transition: opacity var(--transition), transform var(--transition), box-shadow var(--transition);
  box-shadow: 0 4px 18px rgba(91,141,238,0.35);
}
.btn-next svg, .btn-submit svg { width: 16px; height: 16px; }
.btn-next:hover, .btn-submit:hover { opacity: 0.92; transform: translateY(-1px); box-shadow: 0 8px 28px rgba(91,141,238,0.45); }
.btn-next:active, .btn-submit:active { transform: translateY(0); }
.btn-submit:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
.btn-back {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 11px 18px;
  font-family: system-ui, -apple-system, sans-serif;
  font-size: 0.875rem; font-weight: 500; color: var(--text-2);
  background: transparent;
  border: 1px solid var(--border);
  border-radius: var(--radius); cursor: pointer;
  transition: border-color var(--transition), color var(--transition);
}
.btn-back svg { width: 16px; height: 16px; }
.btn-back:hover { border-color: var(--border-hover); color: var(--text-1); }
.btn-label, .btn-loader { display: inline-flex; align-items: center; gap: 8px; }
.spinner {
  width: 15px; height: 15px;
  border: 2px solid rgba(255,255,255,0.3);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.75s linear infinite;
  flex-shrink: 0;
}
@keyframes spin { to { transform: rotate(360deg); } }
.dropzone {
  position: relative;
  border: 1.5px dashed var(--border-hover);
  border-radius: var(--radius-lg);
  background: var(--surface-2);
  transition: border-color var(--transition), background var(--transition);
  overflow: hidden; cursor: pointer;
}
.dropzone.hover, .dropzone:hover { border-color: var(--accent); background: var(--accent-dim); }
.file-hidden { position: absolute; inset: 0; opacity: 0; cursor: pointer; z-index: 2; }
.dz-idle { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px 24px; text-align: center; }
.dz-icon { margin-bottom: 16px; color: var(--text-3); }
.dz-icon svg { width: 64px; height: 64px; }
.dz-text { font-size: 0.95rem; font-weight: 500; color: var(--text-1); margin-bottom: 4px; }
.dz-sub  { font-size: 0.8rem; color: var(--text-3); margin-bottom: 14px; }
.dz-hint { font-size: 0.75rem; color: var(--text-3); margin-top: 12px; }
.btn-browse {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 9px 20px; position: relative; z-index: 3;
  font-family: system-ui, -apple-system, sans-serif;
  font-size: 0.825rem; font-weight: 600; color: var(--accent);
  background: var(--accent-dim);
  border: 1px solid rgba(91,141,238,0.3);
  border-radius: var(--radius); cursor: pointer;
  transition: background var(--transition), box-shadow var(--transition);
}
.btn-browse svg { width: 15px; height: 15px; }
.btn-browse:hover { background: rgba(91,141,238,0.2); box-shadow: 0 0 0 3px var(--accent-glow); }
.dz-preview { padding: 16px 20px; }
.file-card {
  display: flex; align-items: center; gap: 14px;
  padding: 14px 16px;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); position: relative; z-index: 3;
}
.file-card-icon { flex-shrink: 0; }
.file-card-icon svg { width: 40px; height: 40px; }
.file-card-info { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.file-card-name { font-size: 0.875rem; font-weight: 500; color: var(--text-1); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.file-card-size { font-size: 0.75rem; color: var(--text-3); }
.file-card-remove {
  flex-shrink: 0; width: 30px; height: 30px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 50%; border: 1px solid var(--border);
  background: transparent; color: var(--text-2); cursor: pointer;
  transition: background var(--transition), color var(--transition);
}
.file-card-remove svg { width: 14px; height: 14px; }
.file-card-remove:hover { background: var(--error-dim); color: var(--error); border-color: var(--error); }
.otp-info {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 14px 18px; margin-bottom: 28px;
  background: var(--gold-dim);
  border: 1px solid rgba(201,168,76,0.25);
  border-radius: var(--radius);
  font-size: 0.85rem; color: var(--text-2); line-height: 1.55;
}
.otp-info svg { width: 18px; height: 18px; color: var(--gold); flex-shrink: 0; margin-top: 1px; }
.otp-info strong { color: var(--text-1); }
.otp-inputs { display: flex; gap: 10px; flex-wrap: wrap; }
.otp-digit {
  width: 52px; height: 60px;
  font-family: system-ui, -apple-system, sans-serif;
  font-size: 1.6rem; font-weight: 700; text-align: center;
  color: var(--accent);
  background: var(--surface-2);
  border: 1.5px solid var(--border);
  border-radius: var(--radius);
  outline: none;
  transition: border-color var(--transition), box-shadow var(--transition);
  caret-color: var(--accent);
}
.otp-digit:focus { border-color: var(--accent); box-shadow: var(--shadow-input); }
.otp-digit.filled { border-color: rgba(91,141,238,0.5); }
.captcha-wrap {
  display: flex; justify-content: flex-start;
  margin-top: 20px;
}
.result-panel { padding: 56px 36px; text-align: center; animation: stepIn 0.35s ease both; }
.result-icon { margin-bottom: 24px; }
.result-icon svg { width: 72px; height: 72px; }
.success-icon svg { color: var(--success); }
.error-icon   svg { color: var(--error); }
.result-panel h2 { font-size: 1.6rem; font-weight: 700; color: var(--text-1); margin-bottom: 12px; }
.result-panel p  { font-size: 0.9rem; color: var(--text-2); max-width: 420px; margin: 0 auto; }
.sub-id-badge {
  display: inline-flex; align-items: center; gap: 8px;
  margin-top: 24px; padding: 10px 20px;
  background: var(--surface-2); border: 1px solid var(--border);
  border-radius: var(--radius); font-size: 0.82rem; color: var(--text-2);
}
.sub-id-badge svg { width: 15px; height: 15px; color: var(--text-3); }
.sub-id-badge span { font-weight: 700; color: var(--accent); font-family: ui-monospace, monospace; letter-spacing: 0.04em; }
.btn-retry {
  display: inline-flex; align-items: center; gap: 8px;
  margin-top: 24px; padding: 11px 24px;
  font-family: system-ui, -apple-system, sans-serif;
  font-size: 0.875rem; font-weight: 600; color: var(--text-1);
  background: var(--surface-2); border: 1px solid var(--border);
  border-radius: var(--radius); cursor: pointer;
  transition: border-color var(--transition), transform var(--transition);
}
.btn-retry svg { width: 16px; height: 16px; }
.btn-retry:hover { border-color: var(--border-hover); transform: translateY(-1px); }
.site-footer { border-top: 1px solid var(--border); padding: 20px 24px; background: rgba(22,27,39,0.6); }
.footer-inner {
  max-width: 760px; margin: 0 auto;
  display: flex; align-items: center; justify-content: space-between;
  flex-wrap: wrap; gap: 8px;
}
.footer-brand, .footer-contact { display: inline-flex; align-items: center; gap: 7px; font-size: 0.78rem; color: var(--text-3); }
.footer-contact { color: var(--text-2); }
.footer-contact a { color: inherit; text-decoration: none; }
.footer-contact a:hover { color: var(--text-1); }
@media (max-width: 640px) {
  .form-header { padding: 22px 20px; flex-direction: column; align-items: flex-start; gap: 14px; }
  .form-step   { padding: 24px 20px; }
  .step-indicator { padding: 18px 20px; gap: 0; }
  .step-line   { min-width: 20px; }
  .step span   { font-size: 0.6rem; }
  .fields-grid { grid-template-columns: 1fr; }
  .otp-inputs  { justify-content: center; }
  .otp-digit   { width: 44px; height: 54px; font-size: 1.35rem; }
  .footer-inner { flex-direction: column; text-align: center; }
}
@media (max-width: 400px) {
  .otp-digit { width: 38px; height: 48px; font-size: 1.2rem; }
  .step-dot  { width: 30px; height: 30px; }
  .step-dot svg { width: 12px; height: 12px; }
}
.btn-add-member {
  display: inline-flex; align-items: center; gap: 6px;
  margin-top: 10px; padding: 8px 16px;
  font-family: system-ui, -apple-system, sans-serif;
  font-size: 0.825rem; font-weight: 600; color: var(--accent);
  background: var(--accent-dim);
  border: 1px solid rgba(91,141,238,0.3);
  border-radius: var(--radius); cursor: pointer;
  transition: background var(--transition);
}
.btn-add-member svg { width: 14px; height: 14px; }
.btn-add-member:hover { background: rgba(91,141,238,0.2); }
.coauthor-row {
  display: flex; align-items: center; gap: 8px; margin-bottom: 8px;
}
.coauthor-row input {
  flex: 1; padding: 9px 12px;
  font-family: system-ui, -apple-system, sans-serif;
  font-size: 0.875rem; color: var(--text-1);
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius); outline: none;
  transition: border-color var(--transition), box-shadow var(--transition);
}
.coauthor-row input:focus { border-color: var(--accent); box-shadow: var(--shadow-input); }
.coauthor-remove {
  flex-shrink: 0; width: 30px; height: 30px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 50%; border: 1px solid var(--border);
  background: transparent; color: var(--text-2); cursor: pointer;
  transition: background var(--transition), color var(--transition);
}
.coauthor-remove svg { width: 13px; height: 13px; }
.coauthor-remove:hover { background: var(--error-dim); color: var(--error); border-color: var(--error); }
  </style>
</head>
<body>

<div class="bg-grid" aria-hidden="true"></div>
<div class="bg-glow" aria-hidden="true"></div>

<?php if ($event_ended): ?>
<div class="page-wrapper" style="display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:40px 20px;">
  <div style="max-width:520px;width:100%;">
    <div style="width:80px;height:80px;border-radius:50%;background:rgba(201,168,76,0.12);border:1.5px solid rgba(201,168,76,0.35);display:flex;align-items:center;justify-content:center;margin:0 auto 28px;">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="#c9a84c" stroke-width="1.8"/><path d="M12 6v6l4 2" stroke="#c9a84c" stroke-width="2" stroke-linecap="round"/></svg>
    </div>
    <h1 style="font-size:2rem;font-weight:800;color:#e8edf5;margin-bottom:14px;line-height:1.2;">Event Ended</h1>
    <p style="font-size:1rem;color:#8fa3be;line-height:1.7;margin-bottom:28px;">The submission period for <strong style="color:#e8edf5;">Science Day 2026</strong> has closed on <strong style="color:#e8edf5;">April 13, 2026 at 23:59</strong>.<br>Thank you for your interest.</p>
    <div style="display:inline-flex;align-items:center;gap:7px;padding:8px 18px;background:rgba(99,130,167,0.08);border:1px solid rgba(99,130,167,0.18);border-radius:100px;font-size:0.78rem;color:#546882;">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" stroke="currentColor" stroke-width="1.8"/><path d="M22 6l-10 7L2 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
      <a href="mailto:infobrains.uhbc@gmail.com" style="color:inherit;text-decoration:none;">infobrains.uhbc@gmail.com</a>
    </div>
  </div>
  <footer style="position:fixed;bottom:0;left:0;right:0;border-top:1px solid rgba(99,130,167,0.18);padding:16px 24px;background:rgba(22,27,39,0.6);display:flex;align-items:center;justify-content:center;">
    <span style="font-size:0.78rem;color:#546882;">&copy; 2026 Infobrains. All rights reserved.</span>
  </footer>
</div>
<?php else: ?>

<div class="page-wrapper">

  <header class="site-header">
    <div class="header-inner">
      <div class="header-logo">
        <div class="logo-mark">
          <img src="https://i.imgur.com/IWsBAHM.png" alt="InfoBrains Logo"/>
        </div>
        <div class="logo-text">
          <span class="logo-uni">Chlef University</span>
          <span class="logo-event">Science Day 2026</span>
        </div>
      </div>
      <div class="header-badge">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.8"/><path d="M12 6v6l4 2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
        Submissions Open
      </div>
    </div>
    <p class="header-tagline">University Innovation &amp; Research Forum</p>
  </header>

  <main class="main-content">
    <div class="form-container">

      <div class="form-header">
        <div class="form-header-icon">
          <svg viewBox="0 0 24 24" fill="none"><path d="M9 3H5a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2V9l-6-6z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 3v6h6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M8 13h8M8 17h5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        </div>
        <div>
          <h1>Project Submission</h1>
          <p class="form-description">All fields marked <span class="req-star">*</span> are required.</p>
        </div>
      </div>

      <div class="step-indicator" id="stepIndicator">
        <div class="step active" data-step="1">
          <div class="step-dot">
            <svg viewBox="0 0 24 24" fill="none"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="7" r="4" stroke="currentColor" stroke-width="1.8"/></svg>
          </div>
          <span>Author</span>
        </div>
        <div class="step-line"></div>
        <div class="step" data-step="2">
          <div class="step-dot">
            <svg viewBox="0 0 24 24" fill="none"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </div>
          <span>Project</span>
        </div>
        <div class="step-line"></div>
        <div class="step" data-step="3">
          <div class="step-dot">
            <svg viewBox="0 0 24 24" fill="none"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </div>
          <span>Upload</span>
        </div>
        <div class="step-line"></div>
        <div class="step" data-step="4">
          <div class="step-dot">
            <svg viewBox="0 0 24 24" fill="none"><path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.07 9.81a19.79 19.79 0 01-3.07-8.67A2 2 0 012 1h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L6.91 8.91a16 16 0 006.18 6.18l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </div>
          <span>Verify</span>
        </div>
      </div>

      <form id="scienceForm" novalidate>

        <div class="form-step active" id="step1">
          <div class="section-header">
            <div class="section-icon">
              <svg viewBox="0 0 24 24" fill="none"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="7" r="4" stroke="currentColor" stroke-width="1.8"/></svg>
            </div>
            <h2>Author Information</h2>
          </div>
          <div class="fields-grid">
            <div class="form-group">
              <label for="author">
                <svg viewBox="0 0 24 24" fill="none"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="7" r="4" stroke="currentColor" stroke-width="1.8"/></svg>
                Full Name<span class="req-star">*</span>
              </label>
              <div class="input-wrap">
                <input type="text" id="author" name="author" placeholder="e.g. Yacine Boudiaf" autocomplete="name"/>
              </div>
              <span class="field-error" id="authorError">
                <svg viewBox="0 0 24 24" fill="none" width="13" height="13"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.8"/><path d="M12 8v4M12 16h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
                Please enter the author's full name.
              </span>
            </div>
            <div class="form-group">
              <label for="matricule">
                <svg viewBox="0 0 24 24" fill="none"><rect x="3" y="4" width="18" height="18" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M16 2v4M8 2v4M3 10h18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
                Matricule<span class="req-star">*</span>
              </label>
              <div class="input-wrap">
                <input type="text" id="matricule" name="matricule" placeholder="e.g. 221234567890"/>
              </div>
              <span class="field-error" id="matriculeError">
                <svg viewBox="0 0 24 24" fill="none" width="13" height="13"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.8"/><path d="M12 8v4M12 16h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
                Please enter a valid matricule.
              </span>
            </div>
            <div class="form-group">
              <label for="email">
                <svg viewBox="0 0 24 24" fill="none"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" stroke="currentColor" stroke-width="1.8"/><path d="M22 6l-10 7L2 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
                Email<span class="req-star">*</span>
              </label>
              <div class="input-wrap">
                <input type="email" id="email" name="email" placeholder="you@univ-chlef.dz" autocomplete="email"/>
              </div>
              <span class="field-error" id="emailError">
                <svg viewBox="0 0 24 24" fill="none" width="13" height="13"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.8"/><path d="M12 8v4M12 16h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
                Please enter a valid email address.
              </span>
            </div>
            <div class="form-group">
              <label for="phone">
                <svg viewBox="0 0 24 24" fill="none"><path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.07 9.81a19.79 19.79 0 01-3.07-8.67A2 2 0 012 1h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L6.91 8.91a16 16 0 006.18 6.18l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
                Phone<span class="req-star">*</span>
              </label>
              <div class="input-wrap">
                <input type="tel" id="phone" name="phone" placeholder="e.g. 0550123456" autocomplete="tel"/>
              </div>
              <span class="field-error" id="phoneError">
                <svg viewBox="0 0 24 24" fill="none" width="13" height="13"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.8"/><path d="M12 8v4M12 16h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
                Please enter a valid phone number.
              </span>
            </div>
          </div>
          <div class="step-nav">
            <span></span>
            <button type="button" class="btn-next" id="next1">
              Next
              <svg viewBox="0 0 24 24" fill="none"><path d="M5 12h14M13 6l6 6-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </button>
          </div>
        </div>

        <div class="form-step" id="step2">
          <div class="section-header">
            <div class="section-icon">
              <svg viewBox="0 0 24 24" fill="none"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </div>
            <h2>Project Details</h2>
          </div>
          <div class="fields-grid">
            <div class="form-group full-width">
              <label for="title">
                <svg viewBox="0 0 24 24" fill="none"><path d="M4 6h16M4 12h16M4 18h7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
                Project Title<span class="req-star">*</span>
              </label>
              <div class="input-wrap">
                <input type="text" id="title" name="title" placeholder="Enter your project title"/>
              </div>
              <span class="field-error" id="titleError">
                <svg viewBox="0 0 24 24" fill="none" width="13" height="13"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.8"/><path d="M12 8v4M12 16h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
                Please enter the project title.
              </span>
            </div>
            <div class="form-group full-width">
              <label>
                <svg viewBox="0 0 24 24" fill="none"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="9" cy="7" r="4" stroke="currentColor" stroke-width="1.8"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
                Co-Authors
                <span class="optional-tag">Optional</span>
              </label>
              <div id="coauthorsList"></div>
              <button type="button" class="btn-add-member" id="addCoauthor">
                <svg viewBox="0 0 24 24" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
                Add Member
              </button>
              <input type="hidden" id="coauthors" name="coauthors"/>
            </div>
          </div>
          <div class="step-nav">
            <button type="button" class="btn-back" id="back2">
              <svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5M11 6l-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
              Back
            </button>
            <button type="button" class="btn-next" id="next2">
              Next
              <svg viewBox="0 0 24 24" fill="none"><path d="M5 12h14M13 6l6 6-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </button>
          </div>
        </div>

        <div class="form-step" id="step3">
          <div class="section-header">
            <div class="section-icon">
              <svg viewBox="0 0 24 24" fill="none"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </div>
            <h2>Poster Upload</h2>
          </div>
          <div class="form-group full-width">
            <label>
              <svg viewBox="0 0 24 24" fill="none"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M14 2v6h6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
              Poster PDF<span class="req-star">*</span>
            </label>
            <div class="dropzone" id="dropzone">
              <input type="file" class="file-hidden" id="posterInput" accept=".pdf"/>
              <div class="dz-idle" id="dzIdle">
                <div class="dz-icon">
                  <svg viewBox="0 0 24 24" fill="none"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="M14 2v6h6" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 18v-6M9 15l3-3 3 3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </div>
                <p class="dz-text">Drop your PDF here</p>
                <p class="dz-sub">or browse from your device</p>
                <button type="button" class="btn-browse" id="browseBtn">
                  <svg viewBox="0 0 24 24" fill="none"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
                  Choose File
                </button>
                <p class="dz-hint">PDF only &bull; Maximum 10 MB</p>
              </div>
              <div class="dz-preview" id="dzPreview" style="display:none">
                <div class="file-card">
                  <div class="file-card-icon">
                    <svg viewBox="0 0 40 40" fill="none"><rect width="40" height="40" rx="8" fill="rgba(241,107,107,0.12)"/><path d="M12 8h11l7 7v17a2 2 0 01-2 2H12a2 2 0 01-2-2V10a2 2 0 012-2z" stroke="#f16b6b" stroke-width="1.5" stroke-linejoin="round"/><path d="M23 8v7h7" stroke="#f16b6b" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><text x="14" y="30" font-size="7" font-weight="700" fill="#f16b6b" font-family="system-ui">PDF</text></svg>
                  </div>
                  <div class="file-card-info">
                    <div class="file-card-name" id="fileName"></div>
                    <div class="file-card-size" id="fileSize"></div>
                  </div>
                  <button type="button" class="file-card-remove" id="removeFile" aria-label="Remove file">
                    <svg viewBox="0 0 24 24" fill="none"><path d="M18 6L6 18M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
                  </button>
                </div>
              </div>
            </div>
            <span class="field-error" id="posterError">
              <svg viewBox="0 0 24 24" fill="none" width="13" height="13"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.8"/><path d="M12 8v4M12 16h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
              Please upload a PDF file (max 10 MB).
            </span>
          </div>
          <div class="step-nav">
            <button type="button" class="btn-back" id="back3">
              <svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5M11 6l-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
              Back
            </button>
            <button type="button" class="btn-next" id="next3">
              Send OTP &amp; Verify
              <svg viewBox="0 0 24 24" fill="none"><path d="M5 12h14M13 6l6 6-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </button>
          </div>
        </div>

        <div class="form-step" id="step4">
          <div class="section-header">
            <div class="section-icon">
              <svg viewBox="0 0 24 24" fill="none"><path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.07 9.81a19.79 19.79 0 01-3.07-8.67A2 2 0 012 1h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L6.91 8.91a16 16 0 006.18 6.18l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </div>
            <h2>Email Verification</h2>
          </div>
          <div class="otp-info">
            <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.8"/><path d="M12 8v4M12 16h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
            <span>A 6-digit code was sent to <strong id="otpEmailDisplay"></strong>. Enter it below to complete your submission.</span>
          </div>
          <div class="otp-inputs">
            <input class="otp-digit" type="text" inputmode="numeric" maxlength="1" autocomplete="one-time-code"/>
            <input class="otp-digit" type="text" inputmode="numeric" maxlength="1"/>
            <input class="otp-digit" type="text" inputmode="numeric" maxlength="1"/>
            <input class="otp-digit" type="text" inputmode="numeric" maxlength="1"/>
            <input class="otp-digit" type="text" inputmode="numeric" maxlength="1"/>
            <input class="otp-digit" type="text" inputmode="numeric" maxlength="1"/>
          </div>
          <span class="field-error" id="otpError" style="margin-top:10px">
            <svg viewBox="0 0 24 24" fill="none" width="13" height="13"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.8"/><path d="M12 8v4M12 16h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
          </span>
          <div class="step-nav">
            <button type="button" class="btn-back" id="back4">
              <svg viewBox="0 0 24 24" fill="none"><path d="M19 12H5M11 6l-6 6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
              Back
            </button>
            <button type="submit" class="btn-submit" id="submitBtn">
              <span class="btn-label">
                Submit
                <svg viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17l-5-5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
              </span>
              <span class="btn-loader" style="display:none">
                <span class="spinner"></span>
                Submitting…
              </span>
            </button>
          </div>
        </div>

      </form>

      <div class="result-panel" id="successPanel" style="display:none">
        <div class="result-icon success-icon">
          <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.6"/><path d="M7.5 12l3 3 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </div>
        <h2>Submission Received!</h2>
        <p>Your project has been submitted successfully. You will receive a confirmation email shortly.</p>
        <div class="sub-id-badge">
          <svg viewBox="0 0 24 24" fill="none"><path d="M9 3H5a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2V9l-6-6z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 3v6h6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
          Submission ID: <span id="submissionIdDisplay"></span>
        </div>
      </div>

      <div class="result-panel" id="errorPanel" style="display:none">
        <div class="result-icon error-icon">
          <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.6"/><path d="M15 9l-6 6M9 9l6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
        </div>
        <h2>Submission Failed</h2>
        <p id="errorText">An unexpected error occurred. Please try again.</p>
        <button type="button" class="btn-retry" id="retryBtn">
          <svg viewBox="0 0 24 24" fill="none"><path d="M23 4v6h-6M1 20v-6h6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
          Try Again
        </button>
      </div>

    </div>
  </main>

  <footer class="site-footer">
    <div class="footer-inner">
      <span class="footer-brand">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
        &copy; 2026 Infobrains. All rights reserved.
      </span>
      <span class="footer-contact">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" stroke="currentColor" stroke-width="1.8"/><path d="M22 6l-10 7L2 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
        <a href="mailto:infobrains.uhbc@gmail.com">infobrains.uhbc@gmail.com</a>
      </span>
    </div>
  </footer>

</div>

<?php endif; ?>

<?php if (!$event_ended): ?>
<script>
let vmF=typeof globalThis!=='undefined'?globalThis:typeof window!=='undefined'?window:global,vmM=Object['defineProperty'],vmO=Object['create'],vmo=Object['getOwnPropertyDescriptor'],vmN=Object['getOwnPropertyNames'],vmL=Object['getOwnPropertySymbols'],vmS=Object['setPrototypeOf'],vmB=Object['getPrototypeOf'],vmK=Function['prototype']['call'],vmE=Function['prototype']['apply'],vmp=Reflect['apply'],vmP_46887=vmF['vmP_46887']||(vmF['vmP_46887']={});const vmw_b1d5e3=(function(){let q=['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','AQqYAQAAEI4BkAEICm5leHQzCBJfMHgyMTQ5NjQEAQMIEGRpc2FibGVkCBRTZW5kaW5n4oCmCBZ0ZXh0Q29udGVudAgYXzB4OGE4ZGMyJCQxCBhfMHg3NjFiMWQkJDEIGF8weDIxNzdkMiQkMQgYXzB4MmIxNzZiJCQxCBhfMHgyNTg0ZTUkJDEIGF8weDE4NGQyOSQkMQgMYXV0aG9yCAp2YWx1ZQgIdHJpbQQACAZfZjEIEm1hdHJpY3VsZQgGX2YyCAplbWFpbAgGX2YzCApwaG9uZQgGX2Y0CBJjb2F1dGhvcnMIBl9mNQgKdGl0bGUIBl9mNggSXzB4MmIzMjg5CBJfMHgyYWRkYTEIEEZvcm1EYXRhCAxPYmplY3QIDmVudHJpZXMIDmZvckVhY2gEFwgSXzB4NTY3ZTY1CApzbGljZQgIc2l6ZQgIdHlwZQgeYXBwbGljYXRpb24vcGRmBAMIGF8weDQxOWJmYyQkMggMYXBwZW5kCAZfZmQICG5hbWUIEl8weGY4NzVmZQgIUE9TVAgMbWV0aG9kCAhib2R5CApmZXRjaAQCCAhqc29uCA5zdWNjZXNzCB5vdHBFbWFpbERpc3BsYXkEBAgSXzB4MjM3NmM1CBJfMHgyZjQ0MWYICmZvY3VzCBJlcnJvclRleHQICmVycm9yCAx2YWx1ZXMIDGVycm9ycwgIam9pbggCIAgmRmFpbGVkIHRvIHNlbmQgT1RQLggSXzB4NWIzNTYxCBhfMHgxZjg4MzIkJDEIZk5ldHdvcmsgZXJyb3IuIENoZWNrIHlvdXIgY29ubmVjdGlvbiBhbmQgdHJ5IGFnYWluLgIIrgNTZW5kIE9UUCAmYW1wOyBWZXJpZnkgPHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIGZpbGw9Im5vbmUiIHN0eWxlPSJ3aWR0aDoxNnB4O2hlaWdodDoxNnB4Ij48cGF0aCBkPSJNNSAxMmgxNE0xMyA2bDYgNi02IDYiIHN0cm9rZT0iY3VycmVudENvbG9yIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPjwvc3ZnPggSaW5uZXJIVE1MCBJfMHgzNzNkOGHEBKoDpAMApgMAbA4MAI4BBgwAjgEGdKoD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','AQGICQACAAQUCAx0YXJnZXQIDmNsb3Nlc3QIFiNyZW1vdmVGaWxlBAEIFCNicm93c2VCdG4IEl8weDU2N2U2NQgWcG9zdGVySW5wdXQIEl8weDIxNDk2NAgKY2xpY2sEAEwEAAQABAAEAAAEAQQCAAAEAwQBAAAABAAEAAAEAQQEAAAEAwQBAAAABAUAAAQGBAcEAwQBAAQIBAkEAACqA6QDEIwBCIwBADY2AG4IZgYQjAEIjAEANjYAbmgCcKYDQGgApgMAbAiMAQBuBgYYLi40OEw=','AQGACQACAAQMCB5zdG9wUHJvcGFnYXRpb24EAAgWcG9zdGVySW5wdXQIEl8weDIxNDk2NAQBCApjbGljayKqAwQApAMEABAEAAgAjAEEAAAEAW4EAAYAAAQCpgMEAwAEBGwEAQgAjAEEBQAEAW4EAAYA','AQGACQACAAQGCB5zdG9wUHJvcGFnYXRpb24EAAgSXzB4MzkxNjExGKoDpAMQCIwBAG4GpgMAbAYEAAQABAAABAAEAQQAAAQCBAEEAAA=','AQGACQACAAQQCBxwcmV2ZW50RGVmYXVsdAQACBBkcm9wem9uZQgSXzB4MjE0OTY0BAEIEmNsYXNzTGlzdAgGYWRkCApob3ZlciqqA6QDEAiMAQBuBgCmAwBsjAEIjAEANjYAbgYEAAQABAAABAAEAQQAAAQCBAMEBAQBBAUABAYEBwAABAQEAQA=','AQGACQACAAQQCBxwcmV2ZW50RGVmYXVsdAQACBBkcm9wem9uZQgSXzB4MjE0OTY0BAEIEmNsYXNzTGlzdAgMcmVtb3ZlCApob3ZlciqqA6QDEAiMAQBuBgCmAwBsjAEIjAEANjYAbgYEAAQABAAABAAEAQQAAAQCBAMEBAQBBAUABAYEBwAABAQEAQA=','AQGICQACBAQiCBxwcmV2ZW50RGVmYXVsdAQACBBkcm9wem9uZQgSXzB4MjE0OTY0BAEIEmNsYXNzTGlzdAgMcmVtb3ZlCApob3ZlcggYZGF0YVRyYW5zZmVyCApmaWxlcwgYRGF0YVRyYW5zZmVyCAppdGVtcwgGYWRkCBZwb3N0ZXJJbnB1dAgaZGlzcGF0Y2hFdmVudAgKRXZlbnQIDGNoYW5nZYoBBAAEAAQAAAQABAEEAAAEAgQDBAQEAQQFAAQGBAcAAAQEBAEABAAECAQJBAEABAEEAQAAAAAECgQBBAAEAgQCBAsABAwEAQAABAQEAQAEDQQDBAQEAQQCBAkECQAEDQQDBAQEAQAEDgQPBBAEBAQBAAAEBAQBAKoDpAMQCIwBAG4GAKYDAGyMAQiMAQA2NgBuBhCMAYwBAJABDgxAaAJwlgEA0AEODIwBCIwBDDY2AG4GAKYDAGwMjAGOAQYApgMAbAiMAZYBAADQATY2AG4GAjpA','AQGICQAAAAQgCA5fMHhmNjgwCAp2YWx1ZQgOcmVwbGFjZQgEXEQIAmcIAAQCCApzbGljZQQABAEIEmNsYXNzTGlzdAgMdG9nZ2xlCAxmaWxsZWQIEl8weDJmNDQxZggSXzB4MTM1NTRmCApmb2N1c4ABqgMEAKQDBACmAwQApgMEAIwBBAEIAIwBBALEAgYDAAQANgA2AAAEBTYANgAABAZuBAIIAIwBBAcABAg2ADYAAAQJNgA2AAAEBm4EAo4BBAEGAKYDBACMAQQKCACMAQQLAAQMNgA2AKYDBACMAQQBAAQFVgA2ADYAAAQGbgQCBgCmAwQAjAEEAQgAaAAGAKYDBA2mAwQOAAQJFACQAQBoAKYDBA2mAwQOAAQJFACQAQAIAIwBBA8ABAhuBAAGAARcamqAAQ==','AQGICQACAAQSCAZrZXkIEkJhY2tzcGFjZQgOXzB4ZjY4MAgKdmFsdWUIEl8weDJmNDQxZggSXzB4MTM1NTRmBAEICmZvY3VzBAA+BAAEAAQABAAEAQAAAAAEAgQDAAAAAAQEBAUEBgAAAAQEBAUEBgAAAAQHBAgEAACqA6QDEIwBAFQIaAamA4wBQAhoBqYDpgMAFpABaKYDpgMAFpABCIwBAG4GBg4YGigoPg==','AQGICQAEAAQOCBJfMHgyZjQ0MWYIEl8weDEzNTU0ZggKdmFsdWUIEmNsYXNzTGlzdAgGYWRkCAxmaWxsZWQEATwEAKoDBACkAwQApgMEAaYDBAEQABQAkAEAaAQApgMEAaYDBAEQABQAkAEEABAEAo4BAAYEAKYDBAGmAwQBEAAUAJABBAOMAQAIBASMAQQFAAA2ADYEBgAEAW4ABgIOPA==','AQGIAQACBCwIHHByZXZlbnREZWZhdWx0BAAIGmNsaXBib2FyZERhdGEIDmdldERhdGEICHRleHQEAQgACA5yZXBsYWNlCARcRAgCZwQCCApzbGljZQQGCApzcGxpdAgOZm9yRWFjaAQoCBJfMHgyZjQ0MWYICE1hdGgIBm1pbggSXzB4MTM1NTRmCAxsZW5ndGgICmZvY3VzrgGqAwQApAMEABAEAAgAjAEEAAAEAW4EAAYAEAQAjAEEAggAjAEEAwAEBDYANgAABAVuBAEIAGYABgAABAYIAIwBBAfEAgYIAAkANgA2AAAEBjYANgAABApuBAIIAIwBBAsABAE2ADYAAAQMNgA2AAAECm4EAg4EAQwEAQgAjAEEDQAEBjYANgAABAVuBAEIAIwBBA4ABA/IAQA2ADYAAAQFbgQBBgCmAwQQlgEEEQgAjAEEEqYDBBMMBAGMAQQUFAA2ADYApgMEEIwBBBQABAUWADYANgAABApuBAKQAQAOBAIMBAJoAAwEAggAjAEEFQAEAW4EAAYABCQqoAGuAQ==','AQGAAQAEABQIDl8weGY2ODAIEl8weDEzNTU0ZgggYWRkRXZlbnRMaXN0ZW5lcggKaW5wdXQEJgQCCA5rZXlkb3duBCcICnBhc3RlBCleBAAEAAQABAAABAEEAQAEAAAEAgQDAAAEBAAAAAQFBAIABAAABAIEBgAABAcAAAAEBQQCAAQAAAQCBAgAAAQJAAAABAUEAgCqA6QDEK4DBhCuAwamAwiMAQA2NgDIATY2AG4GpgMIjAEANjYAyAE2NgBuBqYDCIwBADY2AMgBNjYAbgY=','AQEICAACCDoOAggIZG9uZQMICnZhbHVlCBhfMHg1YWM2YjMkJDEIDGFwcGVuZAQCUgQABAAEAAAEAAQABAEEAAAABAEABAIEAQQDBAIEAAAABAEABAIEAQQDBAMEAQAEAAAEBAAEBQQCAAAEAwAABAYEAgCqA6QDEP4BDgAODPYBCIwBaAAOjAEODPYBCIwBaAAOjAEODGYM+AGmAwiMAQw2Ngw2NgBucAYWHCguNDo=','AQGACQACAAQMCAAICnZhbHVlCBJjbGFzc0xpc3QIDHJlbW92ZQgMZmlsbGVkBAEgBACqAwQApAMEABAEAAAEAY4BAAYEABAEAowBAAgEA4wBBAQAADYANgQFAAQBbgAG','AQOYAQACEpABCBxwcmV2ZW50RGVmYXVsdAQACBJfMHgyMmZlOGQIDGxlbmd0aAQGCBJfMHgyZjQ0MWYIEG90cEVycm9yCBJfMHgyMTQ5NjQEAQhOUGxlYXNlIGVudGVyIHRoZSBjb21wbGV0ZSA2LWRpZ2l0IGNvZGUuCBJfMHgzZjFjYzEEAwgSY2xhc3NMaXN0CAxyZW1vdmUICHNob3cIEnN1Ym1pdEJ0bgMIEGRpc2FibGVkCBpxdWVyeVNlbGVjdG9yCBQuYnRuLWxhYmVsCApzdHlsZQgIbm9uZQgOZGlzcGxheQgWLmJ0bi1sb2FkZXIIFmlubGluZS1mbGV4CBhfMHgyNWYyYmMkJDEIGF8weDI4NzFmOCQkMQgYXzB4NDg1YmU2JCQxCBhfMHg1YWM2YjMkJDEIGF8weDExOTNlMyQkMQgYXzB4MTkwOWM1JCQxCAplbWFpbAgKdmFsdWUICHRyaW0IBl9mMwgGX2Y4CBJfMHgyYjMyODkIEl8weDJhZGRhMQgQRm9ybURhdGEIDE9iamVjdAgOZW50cmllcwgOZm9yRWFjaAQrCBJfMHgxY2E3NmMICFBPU1QIDG1ldGhvZAgIYm9keQgKZmV0Y2gEAggIanNvbggMc3RhdHVzBa0BCBJlcnJvclRleHQICmVycm9yCEZUb28gbWFueSByZXF1ZXN0cyBmcm9tIHRoaXMgZGV2aWNlLggWdGV4dENvbnRlbnQIEl8weDViMzU2MQgOc3VjY2Vzcwgac3VibWlzc2lvbl9pZAgACApzbGljZQQICBZ0b1VwcGVyQ2FzZQgYXzB4M2Y5YmYxJCQyCCZzdWJtaXNzaW9uSWREaXNwbGF5CBhJbnZhbGlkIE9UUC4IVEludmFsaWQgb3IgZXhwaXJlZCBjb2RlLiBQbGVhc2UgdHJ5IGFnYWluLgIELAgKZm9jdXMIJEFuIGVycm9yIG9jY3VycmVkLghmTmV0d29yayBlcnJvci4gQ2hlY2sgeW91ciBjb25uZWN0aW9uIGFuZCB0cnkgYWdhaW4u+gQEAAQABAAABAAEAQQAAAQCBAEEAAQBBAEEAwQEAAAEBQQBAAQGBAcECAQBBAkECgQLBAMAAAAEBgQHBAgEAQQMAAQNBA4AAAQIBAEABA8EBwQIBAEEAgQCBBAEEQAEAgAEEgQTAAAECAQB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','AQCAAQAAOMABBAAEAQgSXzB4M2EzMmQ0BAIIEl8weDU0YTczYwQDCBJfMHgyYjMyODkEBggSXzB4MjM3NmM1BAcIEl8weDNmMWNjMQQICBJfMHgzZDc5ZGIECQgSXzB4NGY4YmExBAoIEl8weDQ4NGVlYwQLCBJfMHgxMzlkOTAEDAgSXzB4NDBiNjdmBA0IEl8weDM5MTYxMQQPCBJfMHgyMmZlOGQEEQgSXzB4MTcyOGQwBBMIEl8weDJmNTIyOQQWCBJfMHgyYWRkYTEEGAgSXzB4MzczZDhhBBkIEl8weDViMzU2MQQbCBJfMHgxZDEwODcEHQgSXzB4MjAxNDMwCBJfMHg0MTkzNmQIEl8weGY4NzVmZQgSXzB4MWNhNzZjCBJfMHg0MjNkNDUIEl8weDU2N2U2NQgSXzB4ZTUyNmFkCBJfMHgyMTQ5NjQIEl8weDJmNDQxZggUdXNlIHN0cmljdAhQU2MhM25jM0RAeTIwMjYjQ2hsM2YkSzN5XlYzcnkkM2NyM3QmTDBuZwgyaW5kZXgucGhwP2FjdGlvbj1zZW5kLW90cAg2aW5kZXgucGhwP2FjdGlvbj12ZXJpZnktb3RwBAEEHggWcG9zdGVySW5wdXQIIGFkZEV2ZW50TGlzdGVuZXIIDGNoYW5nZQQfBAIIEGRyb3B6b25lCApjbGljawQgCBJicm93c2VCdG4EIQgUcmVtb3ZlRmlsZQQiCBBkcmFnb3ZlcgQjCBJkcmFnbGVhdmUEJAgIZHJvcAQlCBBkb2N1bWVudAggcXVlcnlTZWxlY3RvckFsbAgULm90cC1kaWdpdAgOZm9yRWFjaAQqCBZzY2llbmNlRm9ybQgMc3VibWl0BC0ICm5leHQxBC4ICmJhY2syBC8ICm5leHQyBDAICmJhY2szBDEICm5leHQzBDIICmJhY2s0BDMIEHJldHJ5QnRuBDQIFmFkZENvYXV0aG9yBDUEAKwGpAMAyAEOAMgBCA6uAwDIAQgOrgMAyAEIDq4DAMgBCA6uAwDIAQgOrgMAyAEIDq4DAMgBCA6uAwDIAQgOrgMAyAEIDq4DAMgBCA6uAwDIAQgOrgMAyAEIDq4DAMgBCA6uAwDIAQgOrgMAyAEIDq4DAMgBCA6uAwDIAQgOrgMAyAEIDq4DAMgBCA6uA7QDtAO0A7QDtAO0A7QDtAMABgCyAwCyAwCyAwSuAwSuAwCuAwDIAbIDAKYDAGwIjAEANjYAyAE2NgBuBgCmAwBsCIwBADY2AMgBNjYAbgYApgMAbAiMAQA2NgDIATY2AG4GAKYDAGwIjAEANjYAyAE2NgBuBgCmAwBsCIwBADY2AMgBNjYAbgYApgMAbAiMAQA2NgDIATY2AG4GAKYDAGwIjAEANjYAyAE2NgBuBpYBCIwBADY2AG6yA6YDCIwBAMgBNjYAbgYApgMAbAiMAQA2NgDIATY2AG4GAKYDAGwIjAEANjYAyAE2NgBuBgCmAwBsCIwBADY2AMgBNjYAbgYApgMAbAiMAQA2NgDIATY2AG4GAKYDAGwIjAEANjYAyAE2NgBuBgCmAwBsCIwBADY2AMgBNjYAbgYApgMAbAiMAQA2NgDIATY2AG4GAKYDAGwIjAEANjYAyAE2NgBuBgCmAwBsCIwBADY2AMgBNjYAbgYMAGwGrAMCcAQABAAABAAEAQAABAEEAgQDAAAEAgQEBAUAAAQDBAYEBwAABAQECAQJAAAEBQQKBAsAAAQGBAwEDQAABAcEDgQPAAAECAQQBBEAAAQJBBIEEwAABAoEFAQVAAAECwQWBBcAAAQMBBgEGQAABA0EGgQbAAAEDgQcBB0AAAQPBB4EHwAABBAEIAQhAAAEEQQiBCMAAAQSBCQEJQAABBMEJgQnBCgEKQQqBCsELAQtBC4ELwAEMAQnBDEEKAQyBCkABCoABCsEMwQsBDQABC0ENQQtBDMEAQAENgQ3AAAEOAAAAAQ5BAIABDoELQQzBAEABDYEOwAABDwAAAAEOQQCAAQ9BC0EMwQBAAQ2BDsAAAQ+AAAABDkEAgAEPwQtBDMEAQAENgQ7AAAEQAAAAAQ5BAIABDoELQQzBAEABDYEQQAABEIAAAAEOQQCAAQ6BC0EMwQBAAQ2BEMAAAREAAAABDkEAgAEOgQtBDMEAQAENgRFAAAERgAAAAQ5BAIABEcABEgESQAABDMEAQQuBC4ABEoESwAAAAQzBAEABEwELQQzBAEABDYETQAABE4AAAAEOQQCAARPBC0EMwQBAAQ2BDsAAARQAAAABDkEAgAEUQQtBDMEAQAENgQ7AAAEUgAAAAQ5BAIABFMELQQzBAEABDYEOwAABFQAAAAEOQQCAARVBC0EMwQBAAQ2BDsAAARWAAAABDkEAgAEVwQtBDMEAQAENgQ7AAAEWAAAAAQ5BAIABFkELQQzBAEABDYEOwAABFoAAAAEOQQCAARbBC0EMwQBAAQ2BDsAAARcAAAABDkEAgAEXQQtBDMEAQAENgQ7AAAEXgAAAAQ5BAIABAAEXwQAAAQAAAA='],g={'0':0x6a,'1':0x16b,'2':0xa3,'3':0x1c0,'4':0x4b,'5':0x14e,'6':0x8d,'7':0xdc,'8':0x19d,'9':0x1c3,'10':0x7,'11':0x5c,'12':0xb1,'13':0x1a2,'14':0x18e,'15':0x9b,'16':0x85,'17':0x1f4,'18':0x2a,'19':0x82,'20':0xa2,'21':0x50,'22':0x7c,'23':0xe1,'24':0x16,'25':0xdf,'26':0x13,'27':0x1f6,'28':0x147,'29':0x1eb,'32':0xa,'40':0x1a7,'41':0x8a,'42':0xe7,'43':0xc4,'44':0xcf,'45':0x88,'46':0x17f,'47':0x13e,'50':0x8f,'51':0x1ee,'52':0x1c,'53':0xe2,'54':0x3a,'55':0xfb,'56':0x39,'57':0xf,'58':0x105,'59':0x16d,'60':0x97,'61':0x190,'62':0xb,'63':0xd4,'64':0x125,'65':0x161,'70':0x13d,'71':0x1ac,'72':0xa1,'73':0x1b,'74':0xec,'75':0xf2,'76':0x6b,'77':0x18a,'78':0x122,'79':0x87,'80':0xe0,'81':0x11,'82':0x1fd,'83':0x12b,'84':0x10c,'90':0x6f,'91':0x72,'92':0x14d,'93':0x59,'94':0x4e,'95':0x166,'100':0x10e,'101':0x96,'102':0xd9,'103':0x11e,'104':0x1b1,'105':0x15e,'106':0x163,'107':0x4f,'110':0x8c,'111':0x1e1,'112':0x12,'120':0xaf,'121':0x66,'122':0x10d,'123':0x19a,'124':0xb2,'125':0x138,'126':0x1ff,'127':0x81,'128':0x198,'129':0x18,'130':0x1db,'131':0x192,'132':0x1f3,'140':0x64,'141':0x35,'142':0x92,'143':0xf8,'144':0x23,'145':0x83,'146':0x1d1,'147':0x141,'148':0xa5,'149':0x142,'150':0x99,'151':0x15f,'152':0x8b,'153':0x1ab,'154':0x76,'155':0x14c,'156':0xde,'157':0xf7,'158':0x5,'160':0x133,'161':0x18b,'162':0x1e5,'163':0x63,'164':0x19b,'165':0x140,'166':0x11b,'167':0x21,'168':0x30,'169':0x7d,'180':0x13a,'181':0xfd,'182':0x1fa,'183':0x1df,'184':0x171,'185':0x67,'200':0x4a,'201':0x1cb,'202':0x1cc,'210':0x145,'211':0x1de,'212':0x19c,'213':0x1be,'214':0x47,'215':0xbe,'216':0x95,'217':0xc6,'218':0xa4,'219':0x42,'220':0x70,'221':0x187,'250':0x194,'251':0x16f,'252':0x176,'253':0x1d3,'254':0x17e,'255':0xf6,'256':0x1cf,'257':0x169,'258':0x4c,'259':0x182,'260':0x48,'261':0x1e3,'270':0xad,'271':0x156};const m=0x1,j=0x2,w=0x3,D=0x4,I=0x78,i=0x79,P=0x7a,b=typeof 0x0n,Z=[],F=function(){throw new TypeError('\x27caller\x27,\x20\x27callee\x27,\x20and\x20\x27arguments\x27\x20properties\x20may\x20not\x20be\x20accessed\x20on\x20strict\x20mode\x20functions\x20or\x20the\x20arguments\x20objects\x20for\x20calls\x20to\x20them');};Object['preventExtensions'](F);let v=new WeakSet(),u=new WeakSet(),M=new WeakMap();function O(qB,qK,qE){try{vmM(qB,qK,qE);}catch(qp){}}function o(qB,qK){let qE=new Array(qK),qp=![];for(let qC=qK-0x1;qC>=0x0;qC--){let qR=qB();qR&&typeof qR==='object'&&v['has'](qR)?(qp=!![],qE[qC]=qR):qE[qC]=qR;}if(!qp)return qE;let qY=[];for(let qf=0x0;qf<qK;qf++){let qG=qE[qf];if(qG&&typeof qG==='object'&&v['has'](qG)){let qd=qG['value'];if(Array['isArray'](qd)){for(let qx=0x0;qx<qd['length'];qx++)qY['push'](qd[qx]);}}else qY['push'](qG);}return qY;}function N(qB){let qK=[];for(let qE in qB){qK['push'](qE);}return qK;}function L(qB){return Array['prototype']['slice']['call'](qB);}function S(qB){return typeof qB==='function'&&qB['prototype']?qB['prototype']:qB;}function B(qB){if(typeof qB==='function')return vmB(qB);let qK=vmB(qB),qE=qK&&vmo(qK,'constructor'),qp=qE&&qE['value'],qY=qp&&typeof qp==='function'&&(qp['prototype']===qK||vmB(qp['prototype'])===vmB(qK));if(qY)return vmB(qK);return qK;}function K(qB,qK){let qE=qB;while(qE!==null){let qp=vmo(qE,qK);if(qp)return{'desc':qp,'proto':qE};qE=vmB(qE);}return{'desc':null,'proto':qB};}function E(qB,qK){if(!qB['_$O1cfgJ'])return;qK in qB['_$O1cfgJ']&&delete qB['_$O1cfgJ'][qK];let qE=qK['indexOf']('$$');if(qE!==-0x1){let qp=qK['substring'](0x0,qE);qp in qB['_$O1cfgJ']&&delete qB['_$O1cfgJ'][qp];}}function p(qB,qK){let qE=qB;while(qE){E(qE,qK),qE=qE['_$skyF7O'];}}function Y(qB,qK,qE,qp){if(qp){let qY=Reflect['set'](qB,qK,qE);if(!qY)throw new TypeError('Cannot\x20assign\x20to\x20read\x20only\x20property\x20\x27'+String(qK)+'\x27\x20of\x20object');}else Reflect['set'](qB,qK,qE);}function C(){return!vmP_46887['_$TvPKXo']&&(vmP_46887['_$TvPKXo']=new Map()),vmP_46887['_$TvPKXo'];}function R(){return vmP_46887['_$TvPKXo']||null;}function f(qB,qK,qE){if(qB[0x0]===undefined||!qE)return;let qp=qB[0x10][qB[0x0]];!qK['_$V9UZjo']&&(qK['_$V9UZjo']=vmO(null)),qK['_$V9UZjo'][qp]=qE,qB[0xc]&&(!qK['_$5EcxPs']&&(qK['_$5EcxPs']=vmO(null)),qK['_$5EcxPs'][qp]=!![]),O(qE,'name',{'value':qp,'writable':![],'enumerable':![],'configurable':!![]});}function G(qB){return'_$dWNdBc'+qB['substring'](0x1)+'_$R1azX0';}function d(qB){return'_$Zg7WnI'+qB['substring'](0x1)+'_$TzWqcg';}function x(qB,qK,qE,qp,qY){let qC;return qp?qC=function qR(){let qf=new.target!==undefined?new.target:vmP_46887['_$9tjGj8'];return qB(qK,arguments,qE,qC,qf,this===qY?undefined:this);}:qC=function qf(){let qG=new.target!==undefined?new.target:vmP_46887['_$9tjGj8'];return qB(qK,arguments,qE,qC,qG,this);},M['set'](qC,{'b':qK,'e':qE}),qC;}function t(qB,qK,qE,qp,qY){let qC;return qp?qC=async function qR(){let qf=new.target!==undefined?new.target:vmP_46887['_$9tjGj8'];return await qB(qK,arguments,qE,qC,qf,undefined,this===qY?undefined:this);}:qC=async function qf(){let qG=new.target!==undefined?new.target:vmP_46887['_$9tjGj8'];return await qB(qK,arguments,qE,qC,qG,undefined,this);},qC;}function l(qB,qK,qE,qp,qY,qC){let qR;return qY?qR=function qf(){return qB(qK,arguments,qE,qR,undefined,this===qC?undefined:this);}:qR=function qG(){return qB(qK,arguments,qE,qR,undefined,this);},qp['add'](qR),qR;}function U(qB,qK,qE,qp){let qY;return qY={'CcbByy':(...qC)=>{return qB(qK,qC,qE,qY,undefined,qp);}}['CcbByy'],qY;}function Q(qB,qK,qE,qp){let qY;return qY={'CcbByy':async(...qC)=>{return await qB(qK,qC,qE,qY,undefined,undefined,qp);}}['CcbByy'],qY;}function A(qB,qK,qE,qp,qY){let qC;return qp?qC={'CcbByy'(){let qR=new.target!==undefined?new.target:vmP_46887['_$9tjGj8'];return qB(qK,arguments,qE,qC,qR,this===qY?undefined:this);}}['CcbByy']:qC={'CcbByy'(){let qR=new.target!==undefined?new.target:vmP_46887['_$9tjGj8'];return qB(qK,arguments,qE,qC,qR,this);}}['CcbByy'],M['set'](qC,{'b':qK,'e':qE}),qC;}function X(qB,qK,qE,qp,qY){let qC;return qp?qC={async 'CcbByy'(){let qR=new.target!==undefined?new.target:vmP_46887['_$9tjGj8'];return await qB(qK,arguments,qE,qC,qR,undefined,this===qY?undefined:this);}}['CcbByy']:qC={async 'CcbByy'(){let qR=new.target!==undefined?new.target:vmP_46887['_$9tjGj8'];return await qB(qK,arguments,qE,qC,qR,undefined,this);}}['CcbByy'],qC;}function c(qB,qK,qE,qp,qY,qC){let qR=new Array(0x8),qf=0x0,qG=new Array((qB[0x1]||0x0)+(qB[0x2]||0x0)),qd=0x0,qx=qB[0x10],qt=qB[0xb],ql=qB[0x15]||Z,qU=qB[0xd]||Z,qQ=qt['length']>>0x1,qA=(qB[0x1]*0x1f^qB[0x2]*0x11^qQ*0xd^qx['length']*0x7)>>>0x0&0x3,qX,qc,qe;switch(qA){case 0x1:qX=0x1,qc=0x0,qe=0x1;break;case 0x2:qX=0x0,qc=qQ,qe=0x0;break;case 0x3:qX=qQ,qc=0x0,qe=0x0;break;default:qX=0x0,qc=0x1,qe=0x1;break;}let qk=null,qr=null,qs=![],qy=undefined,qW=![],qV=0x0,qT=![],qz=0x0,qn=!!qB[0xa],qa=!!qB[0x4],qh=!!qB[0x6],qJ=!!qB[0x16],qH=qC,g0=!!qB[0x5];!qn&&!g0&&(qC===undefined||qC===null)&&(qC=vmF);let g1=gP=>{qR[qf++]=gP;},g2=()=>qR[--qf],g3=gP=>gP,g4={['_$V9UZjo']:null,['_$igrgfe']:null,['_$O1cfgJ']:null,['_$skyF7O']:qE};if(qK){let gP=qB[0x1]||0x0;for(let gb=0x0,gZ=qK['length']<gP?qK['length']:gP;gb<gZ;gb++){qG[gb]=qK[gb];}}let g5=(qn||!qa)&&qK?L(qK):null,g6=null,g7=![],g8=qG['length'],g9=null,gq=0x0;qJ&&(g4['_$O1cfgJ']=vmO(null),g4['_$O1cfgJ']['__this__']=!![]);f(qB,g4,qp);let gg={['_$91g7PJ']:qn,['_$jJm7Vy']:qa,['_$kU7fVk']:qh,['_$jgzlQZ']:qJ,['_$AZitn3']:g7,['_$7vKXLR']:qH,['_$ZUpyWr']:g5,['_$LC7hqs']:g4};while(qd<qQ){try{while(qd<qQ){let gF=qt[qX+(qd<<qe)],gv=qt[qc+(qd<<qe)];var gm,gj,gw,gD,gI,gi;!gD&&(gj=null,gw=function(){for(let gu=g8-0x1;gu>=0x0;gu--){qG[gu]=g9[--gq];}g4=g9[--gq],gg['_$LC7hqs']=g4,g5=g9[--gq],gg['_$ZUpyWr']=g5,g6=g9[--gq],qK=g9[--gq],qf=g9[--gq],qd=g9[--gq],qR[qf++]=gm,qd++;},gD=function(gu,gM){switch(gu){case 0x4a:{jM:{let gO,go;gM!=null?(go=qR[--qf],gO=qx[gM]):(gO=qR[--qf],go=qR[--qf]);let gN=delete go[gO];if(gj['_$91g7PJ']&&!gN)throw new TypeError('Cannot\x20delete\x20property\x20\x27'+String(gO)+'\x27\x20of\x20object');qR[qf++]=gN,qd++;}break;}case 0x15:{jO:{let gL=qR[--qf],gS=qR[--qf];qR[qf++]=gS|gL,qd++;}break;}case 0x3c:{jo:{let gB=qR[--qf];if(gM!=null){let gK=qx[gM];!gj['_$LC7hqs']['_$V9UZjo']&&(gj['_$LC7hqs']['_$V9UZjo']=vmO(null)),gj['_$LC7hqs']['_$V9UZjo'][gK]=gB;}qd++;}break;}case 0x3b:{jN:{qk['pop'](),qd++;}break;}case 0x2b:{jL:{let gE=qR[--qf],gp=qR[--qf];qR[qf++]=gp!==gE,qd++;}break;}case 0x9:{jS:{qK[gM]=qR[--qf],qd++;}break;}case 0x40:{jB:{let gY=ql[qd];if(qk&&qk['length']>0x0){let gC=qk[qk['length']-0x1];if(gC['_$EPwog9']!==undefined&&gY>=gC['_$kqUgKx']){qT=!![],qz=gY,qd=gC['_$EPwog9'];break jB;}}qd=gY;}break;}case 0xb:{jK:{let gR=qR[--qf],gf=qR[--qf];qR[qf++]=gf-gR,qd++;}break;}case 0xd:{jE:{let gG=qR[--qf],gd=qR[--qf];qR[qf++]=gd/gG,qd++;}break;}case 0x39:{jp:{throw qR[--qf];}break;}case 0x11:{jY:{let gx=qR[--qf];qR[qf++]=typeof gx===b?gx-0x1n:+gx-0x1,qd++;}break;}case 0x1:{jC:{qR[qf++]=undefined,qd++;}break;}case 0xe:{jR:{let gt=qR[--qf],gl=qR[--qf];qR[qf++]=gl%gt,qd++;}break;}case 0xc:{jf:{let gU=qR[--qf],gQ=qR[--qf];qR[qf++]=gQ*gU,qd++;}break;}case 0x4e:{jG:{let gA=qR[--qf],gX=qx[gM];gA===null||gA===undefined?qR[qf++]=undefined:qR[qf++]=gA[gX],qd++;}break;}case 0x16:{jd:{let gc=qR[--qf],ge=qR[--qf];qR[qf++]=ge^gc,qd++;}break;}case 0x2a:{jx:{let gk=qR[--qf],gr=qR[--qf];qR[qf++]=gr===gk,qd++;}break;}case 0x5:{jt:{let gs=qR[qf-0x1];qR[qf-0x1]=qR[qf-0x2],qR[qf-0x2]=gs,qd++;}break;}case 0x10:{jl:{let gy=qR[--qf];qR[qf++]=typeof gy===b?gy+0x1n:+gy+0x1,qd++;}break;}case 0x52:{jU:{let gW=qR[--qf],gV=qR[--qf];gV===null||gV===undefined?qR[qf++]=undefined:qR[qf++]=gV[gW],qd++;}break;}case 0x38:{jQ:{if(qk&&qk['length']>0x0){let gT=qk[qk['length']-0x1];if(gT['_$EPwog9']!==undefined){qs=!![],qy=qR[--qf],qd=gT['_$EPwog9'];break jQ;}}return qs&&(qs=![],qy=undefined),gm=qR[--qf],0x1;}break;}case 0x36:{jA:{let gz=qR[--qf],gn=qR[--qf];if(typeof gn!=='function')throw new TypeError(gn+'\x20is\x20not\x20a\x20function');let ga=vmP_46887['_$LLmpeU'],gh=!vmP_46887['_$JaO5bA']&&!vmP_46887['_$9tjGj8']&&!(ga&&ga['get'](gn))&&M['get'](gn);if(gh){let m2=gh['c']||(gh['c']=typeof gh['b']==='object'?gh['b']:qN(gh['b']));if(m2){let m3;if(gz===0x0)m3=[];else{if(gz===0x1){let m5=qR[--qf];m3=m5&&typeof m5==='object'&&v['has'](m5)?m5['value']:[m5];}else m3=o(g2,gz);}let m4=m2[0xf];if(m4&&m2===qB&&!m2[0xd]&&gh['e']===qE){!g9&&(g9=[]);g9[gq++]=qd,g9[gq++]=qf,g9[gq++]=qK,g9[gq++]=g6,g9[gq++]=g5,g9[gq++]=g4;for(let m6=0x0;m6<g8;m6++){g9[gq++]=qG[m6];}qK=m3,g6=null;if(m2[0x4]){g5=null;let m7=m2[0x1]||0x0;for(let m8=0x0;m8<m7&&m8<m3['length'];m8++){qG[m8]=m3[m8];}for(let m9=m3['length']<m7?m3['length']:m7;m9<g8;m9++){qG[m9]=undefined;}qd=m4;}else{g5=L(m3),gg['_$ZUpyWr']=g5;for(let mq=0x0;mq<g8;mq++){qG[mq]=undefined;}qd=0x0;}break jA;}vmP_46887['_$ZFycJB']?vmP_46887['_$ZFycJB']=![]:vmP_46887['_$JaO5bA']=undefined;qR[qf++]=c(m2,m3,gh['e'],gn,undefined,undefined),qd++;break jA;}}let gJ=vmP_46887['_$JaO5bA'],gH=vmP_46887['_$LLmpeU'],m0=gH&&gH['get'](gn);m0?(vmP_46887['_$ZFycJB']=!![],vmP_46887['_$JaO5bA']=m0):vmP_46887['_$JaO5bA']=undefined;let m1;try{if(gz===0x0)m1=gn();else{if(gz===0x1){let mg=qR[--qf];m1=mg&&typeof mg==='object'&&v['has'](mg)?vmp(gn,undefined,mg['value']):gn(mg);}else m1=vmp(gn,undefined,o(g2,gz));}qR[qf++]=m1;}finally{m0&&(vmP_46887['_$ZFycJB']=![]),vmP_46887['_$JaO5bA']=gJ;}qd++;}break;}case 0x0:{jX:{qR[qf++]=qx[gM],qd++;}break;}case 0x4f:{jc:{let mm=qR[--qf],mj=qR[--qf];qR[qf++]=mj in mm,qd++;}break;}case 0x2f:{je:{let mw=qR[--qf],mD=qR[--qf];qR[qf++]=mD>=mw,qd++;}break;}case 0x35:{jk:{let mI=qR[--qf];mI!==null&&mI!==undefined?qd=ql[qd]:qd++;}break;}case 0x4c:{jr:{let mi=qR[--qf],mP=qx[gM];if(vmP_46887['_$Fc1I8r']&&mP in vmP_46887['_$Fc1I8r'])throw new ReferenceError('Cannot\x20access\x20\x27'+mP+'\x27\x20before\x20initialization');let mb=!(mP in vmP_46887)&&!(mP in vmF);vmP_46887[mP]=mi,mP in vmF&&(vmF[mP]=mi),mb&&(vmF[mP]=mi),qR[qf++]=mi,qd++;}break;}case 0x2:{js:{qR[qf++]=null,qd++;}break;}case 0x37:{jy:{let mZ=qR[--qf],mF=qR[--qf],mv=qR[--qf];if(typeof mF!=='function')throw new TypeError(mF+'\x20is\x20not\x20a\x20function');let mu=vmP_46887['_$LLmpeU'],mM=mu&&mu['get'](mF),mO=vmP_46887['_$JaO5bA'];mM&&(vmP_46887['_$ZFycJB']=!![],vmP_46887['_$JaO5bA']=mM);let mo;try{if(mZ===0x0)mo=vmp(mF,mv,[]);else{if(mZ===0x1){let mN=qR[--qf];mo=mN&&typeof mN==='object'&&v['has'](mN)?vmp(mF,mv,mN['value']):vmp(mF,mv,[mN]);}else mo=vmp(mF,mv,o(g2,mZ));}qR[qf++]=mo;}finally{mM&&(vmP_46887['_$ZFycJB']=![],vmP_46887['_$JaO5bA']=mO);}qd++;}break;}case 0x19:{jW:{let mL=qR[--qf],mS=qR[--qf];qR[qf++]=mS>>mL,qd++;}break;}case 0xf:{jV:{qR[qf-0x1]=-qR[qf-0x1],qd++;}break;}case 0xa:{jT:{let mB=qR[--qf],mK=qR[--qf];qR[qf++]=mK+mB,qd++;}break;}case 0x47:{jz:{let mE=qR[--qf],mp=qR[--qf],mY=qx[gM];if(mp===null||mp===undefined)throw new TypeError('Cannot\x20set\x20property\x20\x27'+String(mY)+'\x27\x20of\x20'+mp);if(gj['_$91g7PJ']){if(!Reflect['set'](mp,mY,mE))throw new TypeError('Cannot\x20assign\x20to\x20read\x20only\x20property\x20\x27'+String(mY)+'\x27\x20of\x20object');}else mp[mY]=mE;qR[qf++]=mE,qd++;}break;}case 0x13:{jn:{qR[qf-0x1]=+qR[qf-0x1],qd++;}break;}case 0x8:{ja:{qR[qf++]=qK[gM],qd++;}break;}case 0x4d:{jh:{qR[qf++]={},qd++;}break;}case 0x3a:{jJ:{let mC=qU[qd];if(!qk)qk=[];qk['push']({['_$xHA9qT']:mC[0x0]>=0x0?mC[0x0]:undefined,['_$EPwog9']:mC[0x1]>=0x0?mC[0x1]:undefined,['_$kqUgKx']:mC[0x2]>=0x0?mC[0x2]:undefined,['_$z51hbX']:qf}),qd++;}break;}case 0x3e:{jH:{if(qr!==null){qs=![],qW=![],qT=![];let mR=qr;qr=null;throw mR;}if(qs){if(qk&&qk['length']>0x0){let mG=qk[qk['length']-0x1];if(mG['_$EPwog9']!==undefined){qd=mG['_$EPwog9'];break jH;}}let mf=qy;return qs=![],qy=undefined,gm=mf,0x1;}if(qW){if(qk&&qk['length']>0x0){let mx=qk[qk['length']-0x1];if(mx['_$EPwog9']!==undefined){qd=mx['_$EPwog9'];break jH;}}let md=qV;qW=![],qV=0x0,qd=md;break jH;}if(qT){if(qk&&qk['length']>0x0){let ml=qk[qk['length']-0x1];if(ml['_$EPwog9']!==undefined){qd=ml['_$EPwog9'];break jH;}}let mt=qz;qT=![],qz=0x0,qd=mt;break jH;}qd++;}break;}case 0x33:{w0:{qR[--qf]?qd=ql[qd]:qd++;}break;}case 0x49:{w1:{let mU=qR[--qf],mQ=qR[--qf],mA=qR[--qf];if(mA===null||mA===undefined)throw new TypeError('Cannot\x20set\x20property\x20\x27'+String(mQ)+'\x27\x20of\x20'+mA);if(gj['_$91g7PJ']){if(!Reflect['set'](mA,mQ,mU))throw new TypeError('Cannot\x20assign\x20to\x20read\x20only\x20property\x20\x27'+String(mQ)+'\x27\x20of\x20object');}else mA[mQ]=mU;qR[qf++]=mU,qd++;}break;}case 0x3f:{w2:{let mX=ql[qd];if(qk&&qk['length']>0x0){let mc=qk[qk['length']-0x1];if(mc['_$EPwog9']!==undefined&&mX>=mc['_$kqUgKx']){qW=!![],qV=mX,qd=mc['_$EPwog9'];break w2;}}qd=mX;}break;}case 0x34:{w3:{!qR[--qf]?qd=ql[qd]:qd++;}break;}case 0x14:{w4:{let me=qR[--qf],mk=qR[--qf];qR[qf++]=mk&me,qd++;}break;}case 0x48:{w5:{let mr=qR[--qf],ms=qR[--qf];if(ms===null||ms===undefined)throw new TypeError('Cannot\x20read\x20property\x20\x27'+String(mr)+'\x27\x20of\x20'+ms);qR[qf++]=ms[mr],qd++;}break;}case 0x1b:{w6:{let my=qR[qf-0x3],mW=qR[qf-0x2],mV=qR[qf-0x1];qR[qf-0x3]=mW,qR[qf-0x2]=mV,qR[qf-0x1]=my,qd++;}break;}case 0x1a:{w7:{let mT=qR[--qf],mz=qR[--qf];qR[qf++]=mz>>>mT,qd++;}break;}case 0x1d:{w8:{qR[qf-0x1]=String(qR[qf-0x1]),qd++;}break;}case 0x17:{w9:{qR[qf-0x1]=~qR[qf-0x1],qd++;}break;}case 0x1c:{wq:{let mn=qR[--qf];qR[qf++]=typeof mn===b?mn:+mn,qd++;}break;}case 0x3d:{wg:{if(qk&&qk['length']>0x0){let ma=qk[qk['length']-0x1];ma['_$EPwog9']===qd&&(ma['_$OnfOr1']!==undefined&&(qr=ma['_$OnfOr1']),qk['pop']());}qd++;}break;}case 0x20:{wm:{qR[qf-0x1]=!qR[qf-0x1],qd++;}break;}case 0x2d:{wj:{let mh=qR[--qf],mJ=qR[--qf];qR[qf++]=mJ<=mh,qd++;}break;}case 0x32:{ww:{qd=ql[qd];}break;}case 0x7:{wD:{qG[gM]=qR[--qf],qd++;}break;}case 0x54:{wI:{let mH=qR[--qf],j0=qR[--qf],j1=qR[--qf];vmM(j1,j0,{'value':mH,'writable':!![],'enumerable':!![],'configurable':!![]}),typeof mH==='function'&&(!vmP_46887['_$LLmpeU']&&(vmP_46887['_$LLmpeU']=new WeakMap()),vmP_46887['_$LLmpeU']['set'](mH,j1)),qd++;}break;}case 0x28:{wi:{let j2=qR[--qf],j3=qR[--qf];qR[qf++]=j3==j2,qd++;}break;}case 0x4b:{wP:{let j4=qx[gM],j5;if(vmP_46887['_$Fc1I8r']&&j4 in vmP_46887['_$Fc1I8r'])throw new ReferenceError('Cannot\x20access\x20\x27'+j4+'\x27\x20before\x20initialization');if(j4 in vmP_46887)j5=vmP_46887[j4];else{if(j4 in vmF)j5=vmF[j4];else throw new ReferenceError(j4+'\x20is\x20not\x20defined');}qR[qf++]=j5,qd++;}break;}case 0x2c:{wb:{let j6=qR[--qf],j7=qR[--qf];qR[qf++]=j7<j6,qd++;}break;}case 0x4:{wZ:{let j8=qR[qf-0x1];qR[qf++]=j8,qd++;}break;}case 0x46:{wF:{let j9=qR[--qf],jq=qx[gM];if(j9===null||j9===undefined)throw new TypeError('Cannot\x20read\x20property\x20\x27'+String(jq)+'\x27\x20of\x20'+j9);qR[qf++]=j9[jq],qd++;}break;}case 0x51:{wv:{let jg=qR[--qf],jm=qR[qf-0x1];jg!==null&&jg!==undefined&&Object['assign'](jm,jg),qd++;}break;}case 0x29:{wu:{let jj=qR[--qf],jw=qR[--qf];qR[qf++]=jw!=jj,qd++;}break;}case 0x3:{wM:{qR[--qf],qd++;}break;}case 0x53:{wO:{let jD=qR[--qf],jI=qR[--qf],ji=qx[gM];vmM(jI,ji,{'value':jD,'writable':!![],'enumerable':!![],'configurable':!![]}),typeof jD==='function'&&(!vmP_46887['_$LLmpeU']&&(vmP_46887['_$LLmpeU']=new WeakMap()),vmP_46887['_$LLmpeU']['set'](jD,jI)),qd++;}break;}case 0x12:{wo:{let jP=qR[--qf],jb=qR[--qf];qR[qf++]=jb**jP,qd++;}break;}case 0x6:{wN:{qR[qf++]=qG[gM],qd++;}break;}case 0x2e:{wL:{let jZ=qR[--qf],jF=qR[--qf];qR[qf++]=jF>jZ,qd++;}break;}case 0x18:{wS:{let jv=qR[--qf],ju=qR[--qf];qR[qf++]=ju<<jv,qd++;}break;}}},gI=function(gu,gM){switch(gu){case 0x6e:{wV:{qR[qf-0x1]=typeof qR[qf-0x1],qd++;}break;}case 0x69:{wT:{let go=qR[--qf],gN=o(g2,go),gL=qR[--qf];if(gM===0x1){qR[qf++]=gN,qd++;break wT;}if(vmP_46887['_$38zUdB']){qd++;break wT;}let gS=vmP_46887['_$PiSzls'];if(gS){let gB=gS['parent'],gK=gS['newTarget'],gE=Reflect['construct'](gB,gN,gK);qC&&qC!==gE&&vmN(qC)['forEach'](function(gp){!(gp in gE)&&(gE[gp]=qC[gp]);});qC=gE,gj['_$AZitn3']=!![];gj['_$jgzlQZ']&&(E(gj['_$LC7hqs'],'__this__'),!gj['_$LC7hqs']['_$V9UZjo']&&(gj['_$LC7hqs']['_$V9UZjo']=vmO(null)),gj['_$LC7hqs']['_$V9UZjo']['__this__']=qC);qd++;break wT;}if(typeof gL!=='function')throw new TypeError('Super\x20expression\x20must\x20be\x20a\x20constructor');vmP_46887['_$9tjGj8']=qY;try{let gp=gL['apply'](qC,gN);gp!==undefined&&gp!==qC&&typeof gp==='object'&&(qC&&Object['assign'](gp,qC),qC=gp),gj['_$AZitn3']=!![],gj['_$jgzlQZ']&&(E(gj['_$LC7hqs'],'__this__'),!gj['_$LC7hqs']['_$V9UZjo']&&(gj['_$LC7hqs']['_$V9UZjo']=vmO(null)),gj['_$LC7hqs']['_$V9UZjo']['__this__']=qC);}catch(gY){if(gY instanceof TypeError&&(gY['message']['includes']('\x27new\x27')||gY['message']['includes']('constructor'))){let gC=Reflect['construct'](gL,gN,qY);gC!==qC&&qC&&Object['assign'](gC,qC),qC=gC,gj['_$AZitn3']=!![],gj['_$jgzlQZ']&&(E(gj['_$LC7hqs'],'__this__'),!gj['_$LC7hqs']['_$V9UZjo']&&(gj['_$LC7hqs']['_$V9UZjo']=vmO(null)),gj['_$LC7hqs']['_$V9UZjo']['__this__']=qC);}else throw gY;}finally{delete vmP_46887['_$9tjGj8'];}qd++;}break;}case 0xa7:{wz:{if(gM===-0x1)qR[qf++]=Symbol();else{let gR=qR[--qf];qR[qf++]=Symbol(gR);}qd++;}break;}case 0xa5:{wn:{qR[qf++]=vmv[gM],qd++;}break;}case 0x93:{wa:{let gf=qR[--qf],gG=qR[qf-0x1],gd=qx[gM];vmM(gG,gd,{'value':gf,'writable':!![],'enumerable':![],'configurable':!![]}),qd++;}break;}case 0x5b:{wh:{let gx=qR[--qf],gt=qR[qf-0x1];gt['push'](gx),qd++;}break;}case 0x96:{wJ:{let gl=qR[--qf],gU=qx[gM],gQ=C(),gA='get_'+gU,gX=gQ['get'](gA);if(gX&&gX['has'](gl)){let gr=gX['get'](gl);qR[qf++]=gr['call'](gl),qd++;break wJ;}let gc='_$Zg7WnI'+'get_'+gU['substring'](0x1)+'_$TzWqcg';if(gl['constructor']&&gc in gl['constructor']){let gs=gl['constructor'][gc];qR[qf++]=gs['call'](gl),qd++;break wJ;}let ge=gQ['get'](gU);if(ge&&ge['has'](gl)){qR[qf++]=ge['get'](gl),qd++;break wJ;}let gk=G(gU);if(gk in gl){qR[qf++]=gl[gk],qd++;break wJ;}throw new TypeError('Cannot\x20read\x20private\x20member\x20'+gU+'\x20from\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');}break;}case 0x9c:{wH:{let gy=qR[--qf];qR[--qf];let gW=qR[qf-0x1],gV=qx[gM],gT=C();!gT['has'](gV)&&gT['set'](gV,new WeakMap());let gz=gT['get'](gV);gz['set'](gW,gy),qd++;}break;}case 0x92:{D0:{let gn=qR[--qf],ga=qR[qf-0x1],gh=qx[gM],gJ=S(ga);vmM(gJ,gh,{'set':gn,'enumerable':gJ===ga,'configurable':!![]}),qd++;}break;}case 0x6f:{D1:{let gH=qR[--qf],m0=qR[--qf];qR[qf++]=m0 instanceof gH,qd++;}break;}case 0x99:{D2:{let m1=qR[--qf],m2=qx[gM],m3=![],m4=R();if(m4){let m5=m4['get'](m2);m5&&m5['has'](m1)&&(m3=!![]);}qR[qf++]=m3,qd++;}break;}case 0x70:{D3:{let m6=qx[gM];m6 in vmP_46887?qR[qf++]=typeof vmP_46887[m6]:qR[qf++]=typeof vmF[m6],qd++;}break;}case 0xb5:{D4:{let m7=qR[--qf],m8=qR[--qf],m9=qR[qf-0x1];vmM(m9,m8,{'value':m7,'writable':!![],'enumerable':![],'configurable':!![]}),qd++;}break;}case 0x6a:{D5:{let mq=qR[--qf];qR[qf++]=import(mq),qd++;}break;}case 0x5d:{D6:{let mg=qR[--qf],mm={'value':Array['isArray'](mg)?mg:Array['from'](mg)};v['add'](mm),qR[qf++]=mm,qd++;}break;}case 0x82:{D7:{let mj=qR[--qf],mw=mj['next']();qR[qf++]=Promise['resolve'](mw),qd++;}break;}case 0x5a:{D8:{qR[qf++]=[],qd++;}break;}case 0x68:{D9:{let mD=qR[--qf],mI=o(g2,mD),mi=qR[--qf];if(typeof mi!=='function')throw new TypeError(mi+'\x20is\x20not\x20a\x20constructor');if(u['has'](mi))throw new TypeError(mi['name']+'\x20is\x20not\x20a\x20constructor');let mP=vmP_46887['_$JaO5bA'];vmP_46887['_$JaO5bA']=undefined;let mb;try{mb=Reflect['construct'](mi,mI);}finally{vmP_46887['_$JaO5bA']=mP;}qR[qf++]=mb,qd++;}break;}case 0xa4:{Dq:{qR[qf++]=qY,qd++;}break;}case 0x9e:{Dg:{let mZ=qR[--qf],mF=qR[--qf],mv=qx[gM],mu=R();if(mu){let mo='set_'+mv,mN=mu['get'](mo);if(mN&&mN['has'](mF)){let mS=mN['get'](mF);mS['call'](mF,mZ),qR[qf++]=mZ,qd++;break Dg;}let mL=mu['get'](mv);if(mL&&mL['has'](mF)){mL['set'](mF,mZ),qR[qf++]=mZ,qd++;break Dg;}}let mM='_$Zg7WnI'+'set_'+mv['substring'](0x1)+'_$TzWqcg';if(mM in mF){let mB=mF[mM];mB['call'](mF,mZ),qR[qf++]=mZ,qd++;break Dg;}let mO=G(mv);if(mO in mF){mF[mO]=mZ,qR[qf++]=mZ,qd++;break Dg;}throw new TypeError('Cannot\x20write\x20private\x20member\x20'+mv+'\x20to\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');}break;}case 0x98:{Dm:{let mK=qR[--qf],mE=qR[--qf],mp=qx[gM],mY=C();!mY['has'](mp)&&mY['set'](mp,new WeakMap());let mC=mY['get'](mp);if(mC['has'](mE))throw new TypeError('Cannot\x20initialize\x20'+mp+'\x20twice\x20on\x20the\x20same\x20object');mC['set'](mE,mK),qd++;}break;}case 0x9d:{Dj:{let mR=qR[--qf],mf=qx[gM],mG=R();if(mG){let mt='get_'+mf,ml=mG['get'](mt);if(ml&&ml['has'](mR)){let mQ=ml['get'](mR);qR[qf++]=mQ['call'](mR),qd++;break Dj;}let mU=mG['get'](mf);if(mU&&mU['has'](mR)){qR[qf++]=mU['get'](mR),qd++;break Dj;}}let md='_$Zg7WnI'+'get_'+mf['substring'](0x1)+'_$TzWqcg';if(md in mR){let mA=mR[md];qR[qf++]=mA['call'](mR),qd++;break Dj;}let mx=G(mf);if(mx in mR){qR[qf++]=mR[mx],qd++;break Dj;}throw new TypeError('Cannot\x20read\x20private\x20member\x20'+mf+'\x20from\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');}break;}case 0xb7:{Dw:{let mX=qR[--qf],mc=qR[--qf],me=qR[qf-0x1],mk=S(me);vmM(mk,mc,{'set':mX,'enumerable':mk===me,'configurable':!![]}),qd++;}break;}case 0x7f:{DD:{let mr=qR[--qf];if(mr==null)throw new TypeError('Cannot\x20iterate\x20over\x20'+mr);let ms=mr[Symbol['iterator']];if(typeof ms!=='function')throw new TypeError('Object\x20is\x20not\x20iterable');qR[qf++]=vmp(ms,mr,[]),qd++;}break;}case 0x90:{DI:{let my=qR[--qf],mW=qR[qf-0x1],mV=qx[gM];vmM(mW['prototype'],mV,{'value':my,'writable':!![],'enumerable':![],'configurable':!![]}),qd++;}break;}case 0x80:{Di:{let mT=qR[--qf];qR[qf++]=!!mT['done'],qd++;}break;}case 0x8e:{DP:{let mz=qR[--qf],mn=qR[--qf],ma=vmP_46887['_$JaO5bA'],mh=ma?vmB(ma):B(mn),mJ=K(mh,mz);if(mJ['desc']&&mJ['desc']['get']){let j0=mJ['desc']['get']['call'](mn);qR[qf++]=j0,qd++;break DP;}if(mJ['desc']&&mJ['desc']['set']&&!('value'in mJ['desc'])){qR[qf++]=undefined,qd++;break DP;}let mH=mJ['proto']?mJ['proto'][mz]:mh[mz];if(typeof mH==='function'){let j1=mJ['proto']||mh,j2=mH['bind'](mn),j3=mH['constructor']&&mH['constructor']['name'],j4=j3==='GeneratorFunction'||j3==='AsyncFunction'||j3==='AsyncGeneratorFunction';!j4&&(!vmP_46887['_$LLmpeU']&&(vmP_46887['_$LLmpeU']=new WeakMap()),vmP_46887['_$LLmpeU']['set'](j2,j1)),qR[qf++]=j2;}else qR[qf++]=mH;qd++;}break;}case 0xa2:{Db:{let j5=gM&0xffff,j6=gM>>0x10,j7=qx[j5],j8=qx[j6];qR[qf++]=new RegExp(j7,j8),qd++;}break;}case 0x7b:{DZ:{let j9=qR[--qf],jq=j9['next']();qR[qf++]=jq,qd++;}break;}case 0x8f:{DF:{let jg=qR[--qf],jm=qR[--qf],jj=qR[--qf],jw=B(jj),jD=K(jw,jm);jD['desc']&&jD['desc']['set']?jD['desc']['set']['call'](jj,jg):jj[jm]=jg,qR[qf++]=jg,qd++;}break;}case 0xa9:{Dv:{let jI=qR[--qf];qR[qf++]=Symbol['keyFor'](jI),qd++;}break;}case 0xa1:{Du:{if(g6===null){if(gj['_$91g7PJ']||!gj['_$jJm7Vy']){let ji=gj['_$ZUpyWr']||qK,jP=ji?ji['length']:0x0;g6=vmO(Object['prototype']);for(let jb=0x0;jb<jP;jb++){g6[jb]=ji[jb];}vmM(g6,'length',{'value':jP,'writable':!![],'enumerable':![],'configurable':!![]}),vmM(g6,Symbol['iterator'],{'value':Array['prototype'][Symbol['iterator']],'writable':!![],'enumerable':![],'configurable':!![]}),g6=new Proxy(g6,{'has':function(jZ,jF){if(jF===Symbol['toStringTag'])return![];return jF in jZ;},'get':function(jZ,jF,jv){if(jF===Symbol['toStringTag'])return'Arguments';return Reflect['get'](jZ,jF,jv);}}),gj['_$91g7PJ']?vmM(g6,'callee',{'get':F,'set':F,'enumerable':![],'configurable':![]}):vmM(g6,'callee',{'value':qp,'writable':!![],'enumerable':![],'configurable':!![]});}else{let jZ=qK?qK['length']:0x0,jF={},jv={},ju=qp,jM=![],jO=!![],jo={},jN=function(jE){if(typeof jE!=='string')return NaN;let jp=+jE;return jp>=0x0&&jp%0x1===0x0&&String(jp)===jE?jp:NaN;},jL=function(jE){return!isNaN(jE)&&jE>=0x0;},jS=function(jE){if(jE in jv)return undefined;if(jE in jF)return jF[jE];return jE<qK['length']?qK[jE]:undefined;},jB=function(jE){if(jE in jv)return![];if(jE in jF)return!![];return jE<qK['length']?jE in qK:![];},jK={};vmM(jK,'length',{'value':jZ,'writable':!![],'enumerable':![],'configurable':!![]}),vmM(jK,'callee',{'value':qp,'writable':!![],'enumerable':![],'configurable':!![]}),vmM(jK,Symbol['iterator'],{'value':Array['prototype'][Symbol['iterator']],'writable':!![],'enumerable':![],'configurable':!![]}),g6=new Proxy(jK,{'get':function(jE,jp,jY){if(jp==='length')return jZ;if(jp==='callee')return jM?undefined:ju;if(jp===Symbol['toStringTag'])return'Arguments';let jC=jN(jp);if(jL(jC)){if(jC in jo)return Reflect['get'](jE,jp,jY);return jS(jC);}return Reflect['get'](jE,jp,jY);},'set':function(jE,jp,jY){if(jp==='length'){if(!jO)return![];return jZ=jY,jE['length']=jY,!![];}if(jp==='callee')return ju=jY,jM=![],jE['callee']=jY,!![];let jC=jN(jp);if(jL(jC)){if(jC in jo)return Reflect['set'](jE,jp,jY);let jR=vmo(jE,String(jC));if(jR&&!jR['writable'])return![];if(jC in jv)delete jv[jC],jF[jC]=jY;else jC<qK['length']?qK[jC]=jY:jF[jC]=jY;return!![];}return jE[jp]=jY,!![];},'has':function(jE,jp){if(jp==='length')return!![];if(jp==='callee')return!jM;if(jp===Symbol['toStringTag'])return![];let jY=jN(jp);if(jL(jY)){if(String(jY)in jE)return!![];return jB(jY);}return jp in jE;},'defineProperty':function(jE,jp,jY){if(jp==='length')return'value'in jY&&(jZ=jY['value']),'writable'in jY&&(jO=jY['writable']),vmM(jE,jp,jY),!![];if(jp==='callee')return'value'in jY&&(ju=jY['value']),jM=![],vmM(jE,jp,jY),!![];let jC=jN(jp);if(jL(jC)){if('get'in jY||'set'in jY)jo[jC]=0x1,jC in jF&&delete jF[jC],jC in jv&&delete jv[jC];else'value'in jY&&(jC<qK['length']&&!(jC in jv)?qK[jC]=jY['value']:(jF[jC]=jY['value'],jC in jv&&delete jv[jC]));return vmM(jE,String(jC),jY),!![];}return vmM(jE,jp,jY),!![];},'deleteProperty':function(jE,jp){if(jp==='callee')return jM=!![],delete jE['callee'],!![];let jY=jN(jp);return jL(jY)&&(jY in jo&&delete jo[jY],jY<qK['length']?jv[jY]=0x1:delete jF[jY]),delete jE[jp],!![];},'preventExtensions':function(jE){let jp=qK?qK['length']:0x0;for(let jY=0x0;jY<jp;jY++){!(jY in jv)&&!vmo(jE,String(jY))&&vmM(jE,String(jY),{'value':jS(jY),'writable':!![],'enumerable':!![],'configurable':!![]});}for(let jC in jF){!vmo(jE,jC)&&vmM(jE,jC,{'value':jF[jC],'writable':!![],'enumerable':!![],'configurable':!![]});}return Object['preventExtensions'](jE),!![];},'getOwnPropertyDescriptor':function(jE,jp){if(jp==='callee'){if(jM)return undefined;return vmo(jE,'callee');}if(jp==='length')return vmo(jE,'length');let jY=jN(jp);if(jL(jY)){if(jY in jo)return vmo(jE,jp);if(jB(jY)){let jR=vmo(jE,String(jY));return{'value':jS(jY),'writable':jR?jR['writable']:!![],'enumerable':jR?jR['enumerable']:!![],'configurable':jR?jR['configurable']:!![]};}return vmo(jE,jp);}let jC=vmo(jE,jp);if(jC)return jC;return undefined;},'ownKeys':function(jE){let jp=[],jY=qK?qK['length']:0x0;for(let jR=0x0;jR<jY;jR++){!(jR in jv)&&jp['push'](String(jR));}for(let jf in jF){jp['indexOf'](jf)===-0x1&&jp['push'](jf);}jp['push']('length');!jM&&jp['push']('callee');let jC=Reflect['ownKeys'](jE);for(let jG=0x0;jG<jC['length'];jG++){jp['indexOf'](jC[jG])===-0x1&&jp['push'](jC[jG]);}return jp;}});}}qR[qf++]=g6,qd++;}break;}case 0xb9:{DM:{let jE=qR[--qf],jp=qR[--qf],jY=qR[qf-0x1];vmM(jY,jp,{'set':jE,'enumerable':![],'configurable':!![]}),qd++;}break;}case 0x91:{DO:{let jC=qR[--qf],jR=qR[qf-0x1],jf=qx[gM],jG=S(jR);vmM(jG,jf,{'get':jC,'enumerable':jG===jR,'configurable':!![]}),qd++;}break;}case 0x5e:{Do:{let jd=qR[--qf],jx=qR[qf-0x1];if(Array['isArray'](jd))Array['prototype']['push']['apply'](jx,jd);else for(let jt of jd){jx['push'](jt);}qd++;}break;}case 0x64:{DN:{let jl=qR[--qf],jU=typeof jl==='object'?jl:qN(jl),jQ=jU&&jU[0x5],jA=jU&&jU[0x12],jX=jU&&jU[0x13],jc=jU&&jU[0x9],je=jU&&jU[0x1]||0x0,jk=jU&&jU[0xa],jr=jQ?gj['_$7vKXLR']:undefined,js=gj['_$LC7hqs'],jy;if(jX)jy=l(qS,jl,js,u,jk,vmF);else{if(jA){if(jQ)jy=Q(qL,jl,js,jr);else jc?jy=X(qL,jl,js,jk,vmF):jy=t(qL,jl,js,jk,vmF);}else{if(jQ)jy=U(s,jl,js,jr);else jc?jy=A(s,jl,js,jk,vmF):jy=x(s,jl,js,jk,vmF);}}O(jy,'length',{'value':je,'writable':![],'enumerable':![],'configurable':!![]}),qR[qf++]=jy,qd++;}break;}case 0x97:{DL:{let jW=qR[--qf],jV=qR[--qf],jT=qx[gM],jz=C(),jn='set_'+jT,ja=jz['get'](jn);if(ja&&ja['has'](jV)){let w0=ja['get'](jV);w0['call'](jV,jW),qR[qf++]=jW,qd++;break DL;}let jh='_$Zg7WnI'+'set_'+jT['substring'](0x1)+'_$TzWqcg';if(jV['constructor']&&jh in jV['constructor']){let w1=jV['constructor'][jh];w1['call'](jV,jW),qR[qf++]=jW,qd++;break DL;}let jJ=jz['get'](jT);if(jJ&&jJ['has'](jV)){jJ['set'](jV,jW),qR[qf++]=jW,qd++;break DL;}let jH=G(jT);if(jH in jV){jV[jH]=jW,qR[qf++]=jW,qd++;break DL;}throw new TypeError('Cannot\x20write\x20private\x20member\x20'+jT+'\x20to\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');}break;}case 0x84:{DS:{let w2=qR[--qf];qR[qf++]=N(w2),qd++;}break;}case 0x7c:{DB:{let w3=qR[--qf];w3&&typeof w3['return']==='function'&&w3['return'](),qd++;}break;}case 0x8d:{DK:{let w4=qR[--qf],w5=qR[qf-0x1];if(w4===null){vmS(w5['prototype'],null),vmS(w5,Function['prototype']),w5['_$a7L7a4']=null,qd++;break DK;}if(typeof w4!=='function')throw new TypeError('Class\x20extends\x20value\x20'+String(w4)+'\x20is\x20not\x20a\x20constructor\x20or\x20null');let w6=![];try{let w7=vmO(w4['prototype']),w8=w4['apply'](w7,[]);w8!==undefined&&w8!==w7&&(w6=!![]);}catch(w9){w9 instanceof TypeError&&(w9['message']['includes']('\x27new\x27')||w9['message']['includes']('constructor')||w9['message']['includes']('Illegal\x20constructor'))&&(w6=!![]);}if(w6){let wq=w5,wg=vmP_46887,wm='_$9tjGj8',wj='_$Gw2Nwr',ww='_$PiSzls';function gO(...wD){let wI=vmO(w4['prototype']);wg[ww]={'parent':w4,'newTarget':new.target||gO},wg[wj]=new.target||gO;let wi=wm in wg;!wi&&(wg[wm]=new.target);try{let wP=wq['apply'](wI,wD);wP!==undefined&&typeof wP==='object'&&(wI=wP);}finally{delete wg[ww],delete wg[wj],!wi&&delete wg[wm];}return wI;}gO['prototype']=vmO(w4['prototype']),gO['prototype']['constructor']=gO,vmS(gO,w4),vmN(wq)['forEach'](function(wD){wD!=='prototype'&&wD!=='length'&&wD!=='name'&&O(gO,wD,vmo(wq,wD));});wq['prototype']&&(vmN(wq['prototype'])['forEach'](function(wD){wD!=='constructor'&&O(gO['prototype'],wD,vmo(wq['prototype'],wD));}),vmL(wq['prototype'])['forEach'](function(wD){O(gO['prototype'],wD,vmo(wq['prototype'],wD));}));qR[--qf],qR[qf++]=gO,gO['_$a7L7a4']=w4,qd++;break DK;}vmS(w5['prototype'],w4['prototype']),vmS(w5,w4),w5['_$a7L7a4']=w4,qd++;}break;}case 0xb8:{DE:{let wD=qR[--qf],wI=qR[--qf],wi=qR[qf-0x1];vmM(wi,wI,{'get':wD,'enumerable':![],'configurable':!![]}),qd++;}break;}case 0xa3:{Dp:{qR[--qf],qR[qf++]=undefined,qd++;}break;}case 0x83:{DY:{let wP=qR[--qf];wP&&typeof wP['return']==='function'?qR[qf++]=Promise['resolve'](wP['return']()):qR[qf++]=Promise['resolve'](),qd++;}break;}case 0x81:{DC:{let wb=qR[--qf];if(wb==null)throw new TypeError('Cannot\x20iterate\x20over\x20'+wb);let wZ=wb[Symbol['asyncIterator']];if(typeof wZ==='function')qR[qf++]=wZ['call'](wb);else{let wF=wb[Symbol['iterator']];if(typeof wF!=='function')throw new TypeError('Object\x20is\x20not\x20async\x20iterable');qR[qf++]=wF['call'](wb);}qd++;}break;}case 0x8c:{DR:{let wv=qR[--qf],wu=qR[--qf],wM=gM,wO=function(wo,wN){let wL=function(){if(wo){wN&&(vmP_46887['_$Gw2Nwr']=wL);let wS='_$9tjGj8'in vmP_46887;!wS&&(vmP_46887['_$9tjGj8']=new.target);try{let wB=wo['apply'](this,L(arguments));if(wN&&wB!==undefined&&(typeof wB!=='object'||wB===null))throw new TypeError('Derived\x20constructors\x20may\x20only\x20return\x20object\x20or\x20undefined');return wB;}finally{wN&&delete vmP_46887['_$Gw2Nwr'],!wS&&delete vmP_46887['_$9tjGj8'];}}};return wL;}(wu,wM);wv&&vmM(wO,'name',{'value':wv,'configurable':!![]}),qR[qf++]=wO,qd++;}break;}case 0x9a:{Df:{let wo=qR[--qf],wN=qR[--qf],wL=qx[gM],wS=null,wB=R();if(wB){let wp=wB['get'](wL);wp&&wp['has'](wN)&&(wS=wp['get'](wN));}if(wS===null){let wY=d(wL);wY in wN&&(wS=wN[wY]);}if(wS===null)throw new TypeError('Cannot\x20read\x20private\x20member\x20'+wL+'\x20from\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');if(typeof wS!=='function')throw new TypeError(wL+'\x20is\x20not\x20a\x20function');let wK=o(g2,wo),wE=wS['apply'](wN,wK);qR[qf++]=wE,qd++;}break;}case 0xb4:{DG:{let wC=qR[--qf],wR=qR[--qf],wf=qR[qf-0x1];vmM(wf['prototype'],wR,{'value':wC,'writable':!![],'enumerable':![],'configurable':!![]}),qd++;}break;}case 0xa6:{Dd:{qR[qf++]=vmu[gM],qd++;}break;}case 0x95:{Dx:{let wG=qR[--qf],wd=qR[qf-0x1],wx=qx[gM];vmM(wd,wx,{'set':wG,'enumerable':![],'configurable':!![]}),qd++;}break;}case 0x94:{Dt:{let wt=qR[--qf],wl=qR[qf-0x1],wU=qx[gM];vmM(wl,wU,{'get':wt,'enumerable':![],'configurable':!![]}),qd++;}break;}case 0xa8:{Dl:{let wQ=qx[gM];qR[qf++]=Symbol['for'](wQ),qd++;}break;}case 0xb6:{DU:{let wA=qR[--qf],wX=qR[--qf],wc=qR[qf-0x1],we=S(wc);vmM(we,wX,{'get':wA,'enumerable':we===wc,'configurable':!![]}),qd++;}break;}case 0x5f:{DQ:{let wk=qR[qf-0x1];wk['length']++,qd++;}break;}case 0x9b:{DA:{let wr=qR[--qf],ws=qx[gM];if(wr==null){qR[qf++]=undefined,qd++;break DA;}let wy=C(),wW=wy['get'](ws);if(!wW||!wW['has'](wr))throw new TypeError('Cannot\x20read\x20private\x20member\x20'+ws+'\x20from\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');qR[qf++]=wW['get'](wr),qd++;}break;}case 0xa0:{DX:{if(gj['_$kU7fVk']&&!gj['_$AZitn3'])throw new ReferenceError('Must\x20call\x20super\x20constructor\x20in\x20derived\x20class\x20before\x20accessing\x20\x27this\x27\x20or\x20returning\x20from\x20derived\x20constructor');qR[qf++]=qC,qd++;}break;}}},gi=function(gu,gM){switch(gu){case 0xdc:{mo:{let go=qR[--qf],gN=qx[gM];if(gj['_$91g7PJ']&&!(gN in vmF)&&!(gN in vmP_46887))throw new ReferenceError(gN+'\x20is\x20not\x20defined');vmP_46887[gN]=go,vmF[gN]=go,qR[qf++]=go,qd++;}break;}case 0xfe:{mN:{let gL=gM&0xffff,gS=gM>>>0x10;qR[qf++]=qG[gL]*qx[gS],qd++;}break;}case 0x100:{mL:{let gB=gM&0xffff,gK=gM>>>0x10;qR[qf++]=qG[gB]<qx[gK],qd++;}break;}case 0xd8:{mS:{let gE=qx[gM],gp=qR[--qf],gY=gj['_$LC7hqs'],gC=![];while(gY){if(gY['_$V9UZjo']&&gE in gY['_$V9UZjo']){if(gY['_$igrgfe']&&gE in gY['_$igrgfe'])break;gY['_$V9UZjo'][gE]=gp;!gY['_$igrgfe']&&(gY['_$igrgfe']=vmO(null));gY['_$igrgfe'][gE]=!![],gC=!![];break;}gY=gY['_$skyF7O'];}!gC&&(p(gj['_$LC7hqs'],gE),!gj['_$LC7hqs']['_$V9UZjo']&&(gj['_$LC7hqs']['_$V9UZjo']=vmO(null)),gj['_$LC7hqs']['_$V9UZjo'][gE]=gp,!gj['_$LC7hqs']['_$igrgfe']&&(gj['_$LC7hqs']['_$igrgfe']=vmO(null)),gj['_$LC7hqs']['_$igrgfe'][gE]=!![]),qd++;}break;}case 0x102:{mB:{let gR=gM&0xffff,gf=gM>>>0x10,gG=qR[--qf],gd=o(g2,gG),gx=qG[gR],gt=qx[gf],gl=gx[gt];qR[qf++]=gl['apply'](gx,gd),qd++;}break;}case 0xc9:{mK:{qd++;}break;}case 0xfb:{mE:{qG[gM]=qG[gM]-0x1,qd++;}break;}case 0x10f:{mp:{if(typeof process!=='undefined'&&process['hrtime']&&process['hrtime']['bigint']){var gO=process['hrtime']['bigint']();debugger;if(Number(process['hrtime']['bigint']()-gO)/0xf4240>0.1)try{_setDeceptionDetected();}catch(gU){}}qd++;}break;}case 0xca:{mY:{return gm=qf>0x0?qR[--qf]:undefined,0x1;}break;}case 0xfd:{mC:{let gQ=gM&0xffff,gA=gM>>>0x10;qR[qf++]=qG[gQ]-qx[gA],qd++;}break;}case 0xc8:{mR:{debugger;qd++;}break;}case 0xfa:{mf:{qG[gM]=qG[gM]+0x1,qd++;}break;}case 0x10e:{mG:{debugger;qd++;}break;}case 0x101:{md:{let gX=gM&0xffff,gc=gM>>>0x10;qG[gX]<qx[gc]?qd=ql[qd]:qd++;}break;}case 0xd4:{mx:{let ge=qx[gM],gk=qR[--qf],gr=gj['_$LC7hqs'],gs=![];while(gr){let gy=gr['_$O1cfgJ'],gW=gr['_$V9UZjo'];if(gy&&ge in gy)throw new ReferenceError('Cannot\x20access\x20\x27'+ge+'\x27\x20before\x20initialization');if(gW&&ge in gW){if(gr['_$5EcxPs']&&ge in gr['_$5EcxPs']){if(gj['_$91g7PJ'])throw new TypeError('Assignment\x20to\x20constant\x20variable.');gs=!![];break;}if(gr['_$igrgfe']&&ge in gr['_$igrgfe'])throw new TypeError('Assignment\x20to\x20constant\x20variable.');gW[ge]=gk,gs=!![];break;}gr=gr['_$skyF7O'];}if(!gs){if(ge in vmP_46887)vmP_46887[ge]=gk;else ge in vmF?vmF[ge]=gk:vmF[ge]=gk;}qd++;}break;}case 0x104:{mt:{let gV=qG[gM]+0x1;qG[gM]=gV,qR[qf++]=gV,qd++;}break;}case 0xd3:{ml:{let gT=qx[gM];if(gT==='__this__'){let gH=gj['_$LC7hqs'];while(gH){if(gH['_$O1cfgJ']&&'__this__'in gH['_$O1cfgJ'])throw new ReferenceError('Cannot\x20access\x20\x27__this__\x27\x20before\x20initialization');if(gH['_$V9UZjo']&&'__this__'in gH['_$V9UZjo'])break;gH=gH['_$skyF7O'];}qR[qf++]=qC,qd++;break ml;}let gz=gj['_$LC7hqs'],gn,ga=![],gh=gT['indexOf']('$$'),gJ=gh!==-0x1?gT['substring'](0x0,gh):null;while(gz){let m0=gz['_$O1cfgJ'],m1=gz['_$V9UZjo'];if(m0&&gT in m0)throw new ReferenceError('Cannot\x20access\x20\x27'+gT+'\x27\x20before\x20initialization');if(gJ&&m0&&gJ in m0){if(!(m1&&gT in m1))throw new ReferenceError('Cannot\x20access\x20\x27'+gJ+'\x27\x20before\x20initialization');}if(m1&&gT in m1){gn=m1[gT],ga=!![];break;}gz=gz['_$skyF7O'];}!ga&&(gT in vmP_46887?gn=vmP_46887[gT]:gn=vmF[gT]),qR[qf++]=gn,qd++;}break;}case 0xd2:{mU:{let m2=qR[--qf],m3={['_$V9UZjo']:null,['_$igrgfe']:null,['_$O1cfgJ']:null,['_$skyF7O']:m2};gj['_$LC7hqs']=m3,qd++;}break;}case 0xd9:{mQ:{let m4=qx[gM],m5=qR[--qf];E(gj['_$LC7hqs'],m4);if(!gj['_$LC7hqs']['_$V9UZjo'])gj['_$LC7hqs']['_$V9UZjo']=vmO(null);gj['_$LC7hqs']['_$V9UZjo'][m4]=m5,!gj['_$LC7hqs']['_$igrgfe']&&(gj['_$LC7hqs']['_$igrgfe']=vmO(null)),gj['_$LC7hqs']['_$igrgfe'][m4]=!![],qd++;}break;}case 0x103:{mA:{qG[gM]=qR[--qf],qd++;}break;}case 0xdb:{mX:{let m6=qx[gM],m7=qR[--qf],m8=gj['_$LC7hqs']['_$skyF7O'];m8&&(!m8['_$V9UZjo']&&(m8['_$V9UZjo']=vmO(null)),m8['_$V9UZjo'][m6]=m7),qd++;}break;}case 0xda:{mc:{let m9=qx[gM];!gj['_$LC7hqs']['_$O1cfgJ']&&(gj['_$LC7hqs']['_$O1cfgJ']=vmO(null)),gj['_$LC7hqs']['_$O1cfgJ'][m9]=!![],qd++;}break;}case 0xd6:{me:{gj['_$LC7hqs']&&gj['_$LC7hqs']['_$skyF7O']&&(gj['_$LC7hqs']=gj['_$LC7hqs']['_$skyF7O']),qd++;}break;}case 0xff:{mk:{let mq=gM&0xffff,mg=gM>>>0x10,mm=qG[mq],mj=qx[mg];qR[qf++]=mm[mj],qd++;}break;}case 0xd7:{mr:{let mw=qx[gM],mD=qR[--qf];E(gj['_$LC7hqs'],mw),!gj['_$LC7hqs']['_$V9UZjo']&&(gj['_$LC7hqs']['_$V9UZjo']=vmO(null)),gj['_$LC7hqs']['_$V9UZjo'][mw]=mD,qd++;}break;}case 0xfc:{ms:{let mI=gM&0xffff,mi=gM>>>0x10;qR[qf++]=qG[mI]+qx[mi],qd++;}break;}case 0x105:{my:{let mP=qG[gM]-0x1;qG[gM]=mP,qR[qf++]=mP,qd++;}break;}case 0xdd:{mW:{let mb=gM&0xffff,mZ=gM>>>0x10,mF=qx[mb],mv=gj['_$LC7hqs'];for(let mO=0x0;mO<mZ;mO++){mv=mv['_$skyF7O'];}let mu=mv['_$O1cfgJ'];if(mu&&mF in mu)throw new ReferenceError('Cannot\x20access\x20\x27'+mF+'\x27\x20before\x20initialization');let mM=mv['_$V9UZjo'];qR[qf++]=mM?mM[mF]:undefined,qd++;}break;}case 0xd5:{mV:{qR[qf++]=gj['_$LC7hqs'],qd++;}break;}}});switch(gF){case 0x48:{let gu=qR[--qf],gM=qR[--qf];if(gM===null||gM===undefined)throw new TypeError('Cannot\x20read\x20property\x20\x27'+String(gu)+'\x27\x20of\x20'+gM);qR[qf++]=gM[gu],qd++;continue;}case 0x32:{qd=ql[qd];continue;}case 0x10:{let gO=qR[--qf];qR[qf++]=typeof gO===b?gO+0x1n:+gO+0x1,qd++;continue;}case 0x1c:{let go=qR[--qf];qR[qf++]=typeof go===b?go:+go,qd++;continue;}case 0x34:{!qR[--qf]?qd=ql[qd]:qd++;continue;}case 0x3:{qR[--qf],qd++;continue;}case 0x2c:{let gN=qR[--qf],gL=qR[--qf];qR[qf++]=gL<gN,qd++;continue;}case 0x4:{let gS=qR[qf-0x1];qR[qf++]=gS,qd++;continue;}case 0x7:{qG[gv]=qR[--qf],qd++;continue;}case 0x6:{qR[qf++]=qG[gv],qd++;continue;}case 0xb:{let gB=qR[--qf],gK=qR[--qf];qR[qf++]=gK-gB,qd++;continue;}case 0x0:{qR[qf++]=qx[gv],qd++;continue;}case 0x1:{qR[qf++]=undefined,qd++;continue;}case 0x2e:{let gE=qR[--qf],gp=qR[--qf];qR[qf++]=gp>gE,qd++;continue;}case 0xa:{let gY=qR[--qf],gC=qR[--qf];qR[qf++]=gC+gY,qd++;continue;}case 0x8:{qR[qf++]=qK[gv],qd++;continue;}case 0x49:{let gR=qR[--qf],gf=qR[--qf],gG=qR[--qf];if(gG===null||gG===undefined)throw new TypeError('Cannot\x20set\x20property\x20\x27'+String(gf)+'\x27\x20of\x20'+gG);if(qn){if(!Reflect['set'](gG,gf,gR))throw new TypeError('Cannot\x20assign\x20to\x20read\x20only\x20property\x20\x27'+String(gf)+'\x27\x20of\x20object');}else gG[gf]=gR;qR[qf++]=gR,qd++;continue;}}gj=gg;if(gF<0x5a){if(gD(gF,gv)){if(gq>0x0){gw();continue;}return gm;}}else{if(gF<0xc8){if(gI(gF,gv)){if(gq>0x0){gw();continue;}return gm;}}else{if(gi(gF,gv)){if(gq>0x0){gw();continue;}return gm;}}}g4=gg['_$LC7hqs'],g7=gg['_$AZitn3'];}break;}catch(gd){if(qk&&qk['length']>0x0){let gx=qk[qk['length']-0x1];qf=gx['_$z51hbX'];if(gx['_$xHA9qT']!==undefined)g1(gd),qd=gx['_$xHA9qT'],gx['_$xHA9qT']=undefined,gx['_$EPwog9']===undefined&&qk['pop']();else gx['_$EPwog9']!==undefined?(qd=gx['_$EPwog9'],gx['_$OnfOr1']=gd):(qd=gx['_$kqUgKx'],qk['pop']());continue;}throw gd;}}return qf>0x0?qR[--qf]:g7?qC:undefined;}function k(qB,qK,qE,qp,qY,qC){let qR=new Array(0x8),qf=0x0,qG=new Array((qB[0x1]||0x0)+(qB[0x2]||0x0)),qd=0x0,qx=qB[0x10],qt=qB[0xb],ql=qB[0x15]||Z,qU=qB[0xd]||Z,qQ=qt['length']>>0x1,qA=(qB[0x1]*0x1f^qB[0x2]*0x11^qQ*0xd^qx['length']*0x7)>>>0x0&0x3,qX,qc,qe;switch(qA){case 0x1:qX=0x1,qc=0x0,qe=0x1;break;case 0x2:qX=0x0,qc=qQ,qe=0x0;break;case 0x3:qX=qQ,qc=0x0,qe=0x0;break;default:qX=0x0,qc=0x1,qe=0x1;break;}let qk=null,qr=null,qs=![],qy=undefined,qW=![],qV=0x0,qT=![],qz=0x0,qn=!!qB[0xa],qa=!!qB[0x4],qh=!!qB[0x6],qJ=!!qB[0x16],qH=qC,g0=!!qB[0x5];!qn&&!g0&&(qC===undefined||qC===null)&&(qC=vmF);let g1=qB[0x11],g2,g3,g4,g5,g6,g7;if(g1!==undefined){let gP=gb=>typeof gb==='number'&&(gb|0x0)===gb&&!Object['is'](gb,-0x0)?gb^g1|0x0:gb;g2=gb=>{qR[qf++]=gP(gb);},g3=()=>gP(qR[--qf]),g4=()=>gP(qR[qf-0x1]),g5=gb=>{qR[qf-0x1]=gP(gb);},g6=gb=>gP(qR[qf-gb]),g7=(gb,gZ)=>{qR[qf-gb]=gP(gZ);};}else g2=gb=>{qR[qf++]=gb;},g3=()=>qR[--qf],g4=()=>qR[qf-0x1],g5=gb=>{qR[qf-0x1]=gb;},g6=gb=>qR[qf-gb],g7=(gb,gZ)=>{qR[qf-gb]=gZ;};let g8=gb=>gb,g9={['_$V9UZjo']:null,['_$igrgfe']:null,['_$O1cfgJ']:null,['_$skyF7O']:qE};if(qK){let gb=qB[0x1]||0x0;for(let gZ=0x0,gF=qK['length']<gb?qK['length']:gb;gZ<gF;gZ++){qG[gZ]=qK[gZ];}}let gq=(qn||!qa)&&qK?L(qK):null,gg=null,gm=![],gj=qG['length'],gw=null,gD=0x0;qJ&&(g9['_$O1cfgJ']=vmO(null),g9['_$O1cfgJ']['__this__']=!![]);f(qB,g9,qp);let gI={['_$91g7PJ']:qn,['_$jJm7Vy']:qa,['_$kU7fVk']:qh,['_$jgzlQZ']:qJ,['_$AZitn3']:gm,['_$7vKXLR']:qH,['_$ZUpyWr']:gq,['_$LC7hqs']:g9};function gi(gv,gu){if(gv===0x1)g2(gu);else{if(gv===0x2){if(qk&&qk['length']>0x0){let gB=qk[qk['length']-0x1];qf=gB['_$z51hbX'];if(gB['_$xHA9qT']!==undefined){g2(gu),qd=gB['_$xHA9qT'],gB['_$xHA9qT']=undefined;if(gB['_$EPwog9']===undefined)qk['pop']();}else gB['_$EPwog9']!==undefined?(qd=gB['_$EPwog9'],gB['_$OnfOr1']=gu):(qd=gB['_$kqUgKx'],qk['pop']());}else throw gu;}else{if(gv===0x3){let gK=gu;if(qk&&qk['length']>0x0){let gE=qk[qk['length']-0x1];if(gE['_$EPwog9']!==undefined)qs=!![],qy=gK,qd=gE['_$EPwog9'];else return gK;}else return gK;}}}while(qd<qQ){try{while(qd<qQ){let gp=qt[qX+(qd<<qe)],gY=qt[qc+(qd<<qe)];if(gp===P){let gC=g3();return qd++,{['_$Z70Cy8']:m,['_$Jl1CuU']:gC,'_d':gi};}if(gp===I){let gR=g3();return qd++,{['_$Z70Cy8']:j,['_$Jl1CuU']:gR,'_d':gi};}if(gp===i){let gf=g3();return qd++,{['_$Z70Cy8']:w,['_$Jl1CuU']:gf,'_d':gi};}var gM,gO,go,gN,gL,gS;!gN&&(gO=null,go=function(){for(let gG=gj-0x1;gG>=0x0;gG--){qG[gG]=gw[--gD];}g9=gw[--gD],gI['_$LC7hqs']=g9,gq=gw[--gD],gI['_$ZUpyWr']=gq,gg=gw[--gD],qK=gw[--gD],qf=gw[--gD],qd=gw[--gD],qR[qf++]=gM,qd++;},gN=function(gG,gd){switch(gG){case 0x4a:{jd:{let gx,gt;gd!=null?(gt=qR[--qf],gx=qx[gd]):(gx=qR[--qf],gt=qR[--qf]);let gl=delete gt[gx];if(gO['_$91g7PJ']&&!gl)throw new TypeError('Cannot\x20delete\x20property\x20\x27'+String(gx)+'\x27\x20of\x20object');qR[qf++]=gl,qd++;}break;}case 0x15:{jx:{let gU=qR[--qf],gQ=qR[--qf];qR[qf++]=gQ|gU,qd++;}break;}case 0x3c:{jt:{let gA=qR[--qf];if(gd!=null){let gX=qx[gd];!gO['_$LC7hqs']['_$V9UZjo']&&(gO['_$LC7hqs']['_$V9UZjo']=vmO(null)),gO['_$LC7hqs']['_$V9UZjo'][gX]=gA;}qd++;}break;}case 0x3b:{jl:{qk['pop'](),qd++;}break;}case 0x2b:{jU:{let gc=qR[--qf],ge=qR[--qf];qR[qf++]=ge!==gc,qd++;}break;}case 0x9:{jQ:{qK[gd]=qR[--qf],qd++;}break;}case 0x40:{jA:{let gk=ql[qd];if(qk&&qk['length']>0x0){let gr=qk[qk['length']-0x1];if(gr['_$EPwog9']!==undefined&&gk>=gr['_$kqUgKx']){qT=!![],qz=gk,qd=gr['_$EPwog9'];break jA;}}qd=gk;}break;}case 0xb:{jX:{let gs=qR[--qf],gy=qR[--qf];qR[qf++]=gy-gs,qd++;}break;}case 0xd:{jc:{let gW=qR[--qf],gV=qR[--qf];qR[qf++]=gV/gW,qd++;}break;}case 0x39:{je:{throw qR[--qf];}break;}case 0x11:{jk:{let gT=qR[--qf];qR[qf++]=typeof gT===b?gT-0x1n:+gT-0x1,qd++;}break;}case 0x1:{jr:{qR[qf++]=undefined,qd++;}break;}case 0xe:{js:{let gz=qR[--qf],gn=qR[--qf];qR[qf++]=gn%gz,qd++;}break;}case 0xc:{jy:{let ga=qR[--qf],gh=qR[--qf];qR[qf++]=gh*ga,qd++;}break;}case 0x4e:{jW:{let gJ=qR[--qf],gH=qx[gd];gJ===null||gJ===undefined?qR[qf++]=undefined:qR[qf++]=gJ[gH],qd++;}break;}case 0x16:{jV:{let m0=qR[--qf],m1=qR[--qf];qR[qf++]=m1^m0,qd++;}break;}case 0x2a:{jT:{let m2=qR[--qf],m3=qR[--qf];qR[qf++]=m3===m2,qd++;}break;}case 0x5:{jz:{let m4=qR[qf-0x1];qR[qf-0x1]=qR[qf-0x2],qR[qf-0x2]=m4,qd++;}break;}case 0x10:{jn:{let m5=qR[--qf];qR[qf++]=typeof m5===b?m5+0x1n:+m5+0x1,qd++;}break;}case 0x52:{ja:{let m6=qR[--qf],m7=qR[--qf];m7===null||m7===undefined?qR[qf++]=undefined:qR[qf++]=m7[m6],qd++;}break;}case 0x38:{jh:{if(qk&&qk['length']>0x0){let m8=qk[qk['length']-0x1];if(m8['_$EPwog9']!==undefined){qs=!![],qy=qR[--qf],qd=m8['_$EPwog9'];break jh;}}return qs&&(qs=![],qy=undefined),gM=qR[--qf],0x1;}break;}case 0x36:{jJ:{let m9=qR[--qf],mq=qR[--qf];if(typeof mq!=='function')throw new TypeError(mq+'\x20is\x20not\x20a\x20function');let mg=vmP_46887['_$LLmpeU'],mm=!vmP_46887['_$JaO5bA']&&!vmP_46887['_$9tjGj8']&&!(mg&&mg['get'](mq))&&M['get'](mq);if(mm){let mi=mm['c']||(mm['c']=typeof mm['b']==='object'?mm['b']:qN(mm['b']));if(mi){let mP;if(m9===0x0)mP=[];else{if(m9===0x1){let mZ=qR[--qf];mP=mZ&&typeof mZ==='object'&&v['has'](mZ)?mZ['value']:[mZ];}else mP=o(g3,m9);}let mb=mi[0xf];if(mb&&mi===qB&&!mi[0xd]&&mm['e']===qE){!gw&&(gw=[]);gw[gD++]=qd,gw[gD++]=qf,gw[gD++]=qK,gw[gD++]=gg,gw[gD++]=gq,gw[gD++]=g9;for(let mF=0x0;mF<gj;mF++){gw[gD++]=qG[mF];}qK=mP,gg=null;if(mi[0x4]){gq=null;let mv=mi[0x1]||0x0;for(let mu=0x0;mu<mv&&mu<mP['length'];mu++){qG[mu]=mP[mu];}for(let mM=mP['length']<mv?mP['length']:mv;mM<gj;mM++){qG[mM]=undefined;}qd=mb;}else{gq=L(mP),gI['_$ZUpyWr']=gq;for(let mO=0x0;mO<gj;mO++){qG[mO]=undefined;}qd=0x0;}break jJ;}vmP_46887['_$ZFycJB']?vmP_46887['_$ZFycJB']=![]:vmP_46887['_$JaO5bA']=undefined;qR[qf++]=c(mi,mP,mm['e'],mq,undefined,undefined),qd++;break jJ;}}let mj=vmP_46887['_$JaO5bA'],mw=vmP_46887['_$LLmpeU'],mD=mw&&mw['get'](mq);mD?(vmP_46887['_$ZFycJB']=!![],vmP_46887['_$JaO5bA']=mD):vmP_46887['_$JaO5bA']=undefined;let mI;try{if(m9===0x0)mI=mq();else{if(m9===0x1){let mo=qR[--qf];mI=mo&&typeof mo==='object'&&v['has'](mo)?vmp(mq,undefined,mo['value']):mq(mo);}else mI=vmp(mq,undefined,o(g3,m9));}qR[qf++]=mI;}finally{mD&&(vmP_46887['_$ZFycJB']=![]),vmP_46887['_$JaO5bA']=mj;}qd++;}break;}case 0x0:{jH:{qR[qf++]=qx[gd],qd++;}break;}case 0x4f:{w0:{let mN=qR[--qf],mL=qR[--qf];qR[qf++]=mL in mN,qd++;}break;}case 0x2f:{w1:{let mS=qR[--qf],mB=qR[--qf];qR[qf++]=mB>=mS,qd++;}break;}case 0x35:{w2:{let mK=qR[--qf];mK!==null&&mK!==undefined?qd=ql[qd]:qd++;}break;}case 0x4c:{w3:{let mE=qR[--qf],mp=qx[gd];if(vmP_46887['_$Fc1I8r']&&mp in vmP_46887['_$Fc1I8r'])throw new ReferenceError('Cannot\x20access\x20\x27'+mp+'\x27\x20before\x20initialization');let mY=!(mp in vmP_46887)&&!(mp in vmF);vmP_46887[mp]=mE,mp in vmF&&(vmF[mp]=mE),mY&&(vmF[mp]=mE),qR[qf++]=mE,qd++;}break;}case 0x2:{w4:{qR[qf++]=null,qd++;}break;}case 0x37:{w5:{let mC=qR[--qf],mR=qR[--qf],mf=qR[--qf];if(typeof mR!=='function')throw new TypeError(mR+'\x20is\x20not\x20a\x20function');let mG=vmP_46887['_$LLmpeU'],md=mG&&mG['get'](mR),mx=vmP_46887['_$JaO5bA'];md&&(vmP_46887['_$ZFycJB']=!![],vmP_46887['_$JaO5bA']=md);let mt;try{if(mC===0x0)mt=vmp(mR,mf,[]);else{if(mC===0x1){let ml=qR[--qf];mt=ml&&typeof ml==='object'&&v['has'](ml)?vmp(mR,mf,ml['value']):vmp(mR,mf,[ml]);}else mt=vmp(mR,mf,o(g3,mC));}qR[qf++]=mt;}finally{md&&(vmP_46887['_$ZFycJB']=![],vmP_46887['_$JaO5bA']=mx);}qd++;}break;}case 0x19:{w6:{let mU=qR[--qf],mQ=qR[--qf];qR[qf++]=mQ>>mU,qd++;}break;}case 0xf:{w7:{qR[qf-0x1]=-qR[qf-0x1],qd++;}break;}case 0xa:{w8:{let mA=qR[--qf],mX=qR[--qf];qR[qf++]=mX+mA,qd++;}break;}case 0x47:{w9:{let mc=qR[--qf],me=qR[--qf],mk=qx[gd];if(me===null||me===undefined)throw new TypeError('Cannot\x20set\x20property\x20\x27'+String(mk)+'\x27\x20of\x20'+me);if(gO['_$91g7PJ']){if(!Reflect['set'](me,mk,mc))throw new TypeError('Cannot\x20assign\x20to\x20read\x20only\x20property\x20\x27'+String(mk)+'\x27\x20of\x20object');}else me[mk]=mc;qR[qf++]=mc,qd++;}break;}case 0x13:{wq:{qR[qf-0x1]=+qR[qf-0x1],qd++;}break;}case 0x8:{wg:{qR[qf++]=qK[gd],qd++;}break;}case 0x4d:{wm:{qR[qf++]={},qd++;}break;}case 0x3a:{wj:{let mr=qU[qd];if(!qk)qk=[];qk['push']({['_$xHA9qT']:mr[0x0]>=0x0?mr[0x0]:undefined,['_$EPwog9']:mr[0x1]>=0x0?mr[0x1]:undefined,['_$kqUgKx']:mr[0x2]>=0x0?mr[0x2]:undefined,['_$z51hbX']:qf}),qd++;}break;}case 0x3e:{ww:{if(qr!==null){qs=![],qW=![],qT=![];let ms=qr;qr=null;throw ms;}if(qs){if(qk&&qk['length']>0x0){let mW=qk[qk['length']-0x1];if(mW['_$EPwog9']!==undefined){qd=mW['_$EPwog9'];break ww;}}let my=qy;return qs=![],qy=undefined,gM=my,0x1;}if(qW){if(qk&&qk['length']>0x0){let mT=qk[qk['length']-0x1];if(mT['_$EPwog9']!==undefined){qd=mT['_$EPwog9'];break ww;}}let mV=qV;qW=![],qV=0x0,qd=mV;break ww;}if(qT){if(qk&&qk['length']>0x0){let mn=qk[qk['length']-0x1];if(mn['_$EPwog9']!==undefined){qd=mn['_$EPwog9'];break ww;}}let mz=qz;qT=![],qz=0x0,qd=mz;break ww;}qd++;}break;}case 0x33:{wD:{qR[--qf]?qd=ql[qd]:qd++;}break;}case 0x49:{wI:{let ma=qR[--qf],mh=qR[--qf],mJ=qR[--qf];if(mJ===null||mJ===undefined)throw new TypeError('Cannot\x20set\x20property\x20\x27'+String(mh)+'\x27\x20of\x20'+mJ);if(gO['_$91g7PJ']){if(!Reflect['set'](mJ,mh,ma))throw new TypeError('Cannot\x20assign\x20to\x20read\x20only\x20property\x20\x27'+String(mh)+'\x27\x20of\x20object');}else mJ[mh]=ma;qR[qf++]=ma,qd++;}break;}case 0x3f:{wi:{let mH=ql[qd];if(qk&&qk['length']>0x0){let j0=qk[qk['length']-0x1];if(j0['_$EPwog9']!==undefined&&mH>=j0['_$kqUgKx']){qW=!![],qV=mH,qd=j0['_$EPwog9'];break wi;}}qd=mH;}break;}case 0x34:{wP:{!qR[--qf]?qd=ql[qd]:qd++;}break;}case 0x14:{wb:{let j1=qR[--qf],j2=qR[--qf];qR[qf++]=j2&j1,qd++;}break;}case 0x48:{wZ:{let j3=qR[--qf],j4=qR[--qf];if(j4===null||j4===undefined)throw new TypeError('Cannot\x20read\x20property\x20\x27'+String(j3)+'\x27\x20of\x20'+j4);qR[qf++]=j4[j3],qd++;}break;}case 0x1b:{wF:{let j5=qR[qf-0x3],j6=qR[qf-0x2],j7=qR[qf-0x1];qR[qf-0x3]=j6,qR[qf-0x2]=j7,qR[qf-0x1]=j5,qd++;}break;}case 0x1a:{wv:{let j8=qR[--qf],j9=qR[--qf];qR[qf++]=j9>>>j8,qd++;}break;}case 0x1d:{wu:{qR[qf-0x1]=String(qR[qf-0x1]),qd++;}break;}case 0x17:{wM:{qR[qf-0x1]=~qR[qf-0x1],qd++;}break;}case 0x1c:{wO:{let jq=qR[--qf];qR[qf++]=typeof jq===b?jq:+jq,qd++;}break;}case 0x3d:{wo:{if(qk&&qk['length']>0x0){let jg=qk[qk['length']-0x1];jg['_$EPwog9']===qd&&(jg['_$OnfOr1']!==undefined&&(qr=jg['_$OnfOr1']),qk['pop']());}qd++;}break;}case 0x20:{wN:{qR[qf-0x1]=!qR[qf-0x1],qd++;}break;}case 0x2d:{wL:{let jm=qR[--qf],jj=qR[--qf];qR[qf++]=jj<=jm,qd++;}break;}case 0x32:{wS:{qd=ql[qd];}break;}case 0x7:{wB:{qG[gd]=qR[--qf],qd++;}break;}case 0x54:{wK:{let jw=qR[--qf],jD=qR[--qf],jI=qR[--qf];vmM(jI,jD,{'value':jw,'writable':!![],'enumerable':!![],'configurable':!![]}),typeof jw==='function'&&(!vmP_46887['_$LLmpeU']&&(vmP_46887['_$LLmpeU']=new WeakMap()),vmP_46887['_$LLmpeU']['set'](jw,jI)),qd++;}break;}case 0x28:{wE:{let ji=qR[--qf],jP=qR[--qf];qR[qf++]=jP==ji,qd++;}break;}case 0x4b:{wp:{let jb=qx[gd],jZ;if(vmP_46887['_$Fc1I8r']&&jb in vmP_46887['_$Fc1I8r'])throw new ReferenceError('Cannot\x20access\x20\x27'+jb+'\x27\x20before\x20initialization');if(jb in vmP_46887)jZ=vmP_46887[jb];else{if(jb in vmF)jZ=vmF[jb];else throw new ReferenceError(jb+'\x20is\x20not\x20defined');}qR[qf++]=jZ,qd++;}break;}case 0x2c:{wY:{let jF=qR[--qf],jv=qR[--qf];qR[qf++]=jv<jF,qd++;}break;}case 0x4:{wC:{let ju=qR[qf-0x1];qR[qf++]=ju,qd++;}break;}case 0x46:{wR:{let jM=qR[--qf],jO=qx[gd];if(jM===null||jM===undefined)throw new TypeError('Cannot\x20read\x20property\x20\x27'+String(jO)+'\x27\x20of\x20'+jM);qR[qf++]=jM[jO],qd++;}break;}case 0x51:{wf:{let jo=qR[--qf],jN=qR[qf-0x1];jo!==null&&jo!==undefined&&Object['assign'](jN,jo),qd++;}break;}case 0x29:{wG:{let jL=qR[--qf],jS=qR[--qf];qR[qf++]=jS!=jL,qd++;}break;}case 0x3:{wd:{qR[--qf],qd++;}break;}case 0x53:{wx:{let jB=qR[--qf],jK=qR[--qf],jE=qx[gd];vmM(jK,jE,{'value':jB,'writable':!![],'enumerable':!![],'configurable':!![]}),typeof jB==='function'&&(!vmP_46887['_$LLmpeU']&&(vmP_46887['_$LLmpeU']=new WeakMap()),vmP_46887['_$LLmpeU']['set'](jB,jK)),qd++;}break;}case 0x12:{wt:{let jp=qR[--qf],jY=qR[--qf];qR[qf++]=jY**jp,qd++;}break;}case 0x6:{wl:{qR[qf++]=qG[gd],qd++;}break;}case 0x2e:{wU:{let jC=qR[--qf],jR=qR[--qf];qR[qf++]=jR>jC,qd++;}break;}case 0x18:{wQ:{let jf=qR[--qf],jG=qR[--qf];qR[qf++]=jG<<jf,qd++;}break;}}},gL=function(gG,gd){switch(gG){case 0x6e:{D7:{qR[qf-0x1]=typeof qR[qf-0x1],qd++;}break;}case 0x69:{D8:{let gt=qR[--qf],gl=o(g3,gt),gU=qR[--qf];if(gd===0x1){qR[qf++]=gl,qd++;break D8;}if(vmP_46887['_$38zUdB']){qd++;break D8;}let gQ=vmP_46887['_$PiSzls'];if(gQ){let gA=gQ['parent'],gX=gQ['newTarget'],gc=Reflect['construct'](gA,gl,gX);qC&&qC!==gc&&vmN(qC)['forEach'](function(ge){!(ge in gc)&&(gc[ge]=qC[ge]);});qC=gc,gO['_$AZitn3']=!![];gO['_$jgzlQZ']&&(E(gO['_$LC7hqs'],'__this__'),!gO['_$LC7hqs']['_$V9UZjo']&&(gO['_$LC7hqs']['_$V9UZjo']=vmO(null)),gO['_$LC7hqs']['_$V9UZjo']['__this__']=qC);qd++;break D8;}if(typeof gU!=='function')throw new TypeError('Super\x20expression\x20must\x20be\x20a\x20constructor');vmP_46887['_$9tjGj8']=qY;try{let ge=gU['apply'](qC,gl);ge!==undefined&&ge!==qC&&typeof ge==='object'&&(qC&&Object['assign'](ge,qC),qC=ge),gO['_$AZitn3']=!![],gO['_$jgzlQZ']&&(E(gO['_$LC7hqs'],'__this__'),!gO['_$LC7hqs']['_$V9UZjo']&&(gO['_$LC7hqs']['_$V9UZjo']=vmO(null)),gO['_$LC7hqs']['_$V9UZjo']['__this__']=qC);}catch(gk){if(gk instanceof TypeError&&(gk['message']['includes']('\x27new\x27')||gk['message']['includes']('constructor'))){let gr=Reflect['construct'](gU,gl,qY);gr!==qC&&qC&&Object['assign'](gr,qC),qC=gr,gO['_$AZitn3']=!![],gO['_$jgzlQZ']&&(E(gO['_$LC7hqs'],'__this__'),!gO['_$LC7hqs']['_$V9UZjo']&&(gO['_$LC7hqs']['_$V9UZjo']=vmO(null)),gO['_$LC7hqs']['_$V9UZjo']['__this__']=qC);}else throw gk;}finally{delete vmP_46887['_$9tjGj8'];}qd++;}break;}case 0xa7:{D9:{if(gd===-0x1)qR[qf++]=Symbol();else{let gs=qR[--qf];qR[qf++]=Symbol(gs);}qd++;}break;}case 0xa5:{Dq:{qR[qf++]=vmv[gd],qd++;}break;}case 0x93:{Dg:{let gy=qR[--qf],gW=qR[qf-0x1],gV=qx[gd];vmM(gW,gV,{'value':gy,'writable':!![],'enumerable':![],'configurable':!![]}),qd++;}break;}case 0x5b:{Dm:{let gT=qR[--qf],gz=qR[qf-0x1];gz['push'](gT),qd++;}break;}case 0x96:{Dj:{let gn=qR[--qf],ga=qx[gd],gh=C(),gJ='get_'+ga,gH=gh['get'](gJ);if(gH&&gH['has'](gn)){let m3=gH['get'](gn);qR[qf++]=m3['call'](gn),qd++;break Dj;}let m0='_$Zg7WnI'+'get_'+ga['substring'](0x1)+'_$TzWqcg';if(gn['constructor']&&m0 in gn['constructor']){let m4=gn['constructor'][m0];qR[qf++]=m4['call'](gn),qd++;break Dj;}let m1=gh['get'](ga);if(m1&&m1['has'](gn)){qR[qf++]=m1['get'](gn),qd++;break Dj;}let m2=G(ga);if(m2 in gn){qR[qf++]=gn[m2],qd++;break Dj;}throw new TypeError('Cannot\x20read\x20private\x20member\x20'+ga+'\x20from\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');}break;}case 0x9c:{Dw:{let m5=qR[--qf];qR[--qf];let m6=qR[qf-0x1],m7=qx[gd],m8=C();!m8['has'](m7)&&m8['set'](m7,new WeakMap());let m9=m8['get'](m7);m9['set'](m6,m5),qd++;}break;}case 0x92:{DD:{let mq=qR[--qf],mg=qR[qf-0x1],mm=qx[gd],mj=S(mg);vmM(mj,mm,{'set':mq,'enumerable':mj===mg,'configurable':!![]}),qd++;}break;}case 0x6f:{DI:{let mw=qR[--qf],mD=qR[--qf];qR[qf++]=mD instanceof mw,qd++;}break;}case 0x99:{Di:{let mI=qR[--qf],mi=qx[gd],mP=![],mb=R();if(mb){let mZ=mb['get'](mi);mZ&&mZ['has'](mI)&&(mP=!![]);}qR[qf++]=mP,qd++;}break;}case 0x70:{DP:{let mF=qx[gd];mF in vmP_46887?qR[qf++]=typeof vmP_46887[mF]:qR[qf++]=typeof vmF[mF],qd++;}break;}case 0xb5:{Db:{let mv=qR[--qf],mu=qR[--qf],mM=qR[qf-0x1];vmM(mM,mu,{'value':mv,'writable':!![],'enumerable':![],'configurable':!![]}),qd++;}break;}case 0x6a:{DZ:{let mO=qR[--qf];qR[qf++]=import(mO),qd++;}break;}case 0x5d:{DF:{let mo=qR[--qf],mN={'value':Array['isArray'](mo)?mo:Array['from'](mo)};v['add'](mN),qR[qf++]=mN,qd++;}break;}case 0x82:{Dv:{let mL=qR[--qf],mS=mL['next']();qR[qf++]=Promise['resolve'](mS),qd++;}break;}case 0x5a:{Du:{qR[qf++]=[],qd++;}break;}case 0x68:{DM:{let mB=qR[--qf],mK=o(g3,mB),mE=qR[--qf];if(typeof mE!=='function')throw new TypeError(mE+'\x20is\x20not\x20a\x20constructor');if(u['has'](mE))throw new TypeError(mE['name']+'\x20is\x20not\x20a\x20constructor');let mp=vmP_46887['_$JaO5bA'];vmP_46887['_$JaO5bA']=undefined;let mY;try{mY=Reflect['construct'](mE,mK);}finally{vmP_46887['_$JaO5bA']=mp;}qR[qf++]=mY,qd++;}break;}case 0xa4:{DO:{qR[qf++]=qY,qd++;}break;}case 0x9e:{Do:{let mC=qR[--qf],mR=qR[--qf],mf=qx[gd],mG=R();if(mG){let mt='set_'+mf,ml=mG['get'](mt);if(ml&&ml['has'](mR)){let mQ=ml['get'](mR);mQ['call'](mR,mC),qR[qf++]=mC,qd++;break Do;}let mU=mG['get'](mf);if(mU&&mU['has'](mR)){mU['set'](mR,mC),qR[qf++]=mC,qd++;break Do;}}let md='_$Zg7WnI'+'set_'+mf['substring'](0x1)+'_$TzWqcg';if(md in mR){let mA=mR[md];mA['call'](mR,mC),qR[qf++]=mC,qd++;break Do;}let mx=G(mf);if(mx in mR){mR[mx]=mC,qR[qf++]=mC,qd++;break Do;}throw new TypeError('Cannot\x20write\x20private\x20member\x20'+mf+'\x20to\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');}break;}case 0x98:{DN:{let mX=qR[--qf],mc=qR[--qf],me=qx[gd],mk=C();!mk['has'](me)&&mk['set'](me,new WeakMap());let mr=mk['get'](me);if(mr['has'](mc))throw new TypeError('Cannot\x20initialize\x20'+me+'\x20twice\x20on\x20the\x20same\x20object');mr['set'](mc,mX),qd++;}break;}case 0x9d:{DL:{let ms=qR[--qf],my=qx[gd],mW=R();if(mW){let mz='get_'+my,mn=mW['get'](mz);if(mn&&mn['has'](ms)){let mh=mn['get'](ms);qR[qf++]=mh['call'](ms),qd++;break DL;}let ma=mW['get'](my);if(ma&&ma['has'](ms)){qR[qf++]=ma['get'](ms),qd++;break DL;}}let mV='_$Zg7WnI'+'get_'+my['substring'](0x1)+'_$TzWqcg';if(mV in ms){let mJ=ms[mV];qR[qf++]=mJ['call'](ms),qd++;break DL;}let mT=G(my);if(mT in ms){qR[qf++]=ms[mT],qd++;break DL;}throw new TypeError('Cannot\x20read\x20private\x20member\x20'+my+'\x20from\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');}break;}case 0xb7:{DS:{let mH=qR[--qf],j0=qR[--qf],j1=qR[qf-0x1],j2=S(j1);vmM(j2,j0,{'set':mH,'enumerable':j2===j1,'configurable':!![]}),qd++;}break;}case 0x7f:{DB:{let j3=qR[--qf];if(j3==null)throw new TypeError('Cannot\x20iterate\x20over\x20'+j3);let j4=j3[Symbol['iterator']];if(typeof j4!=='function')throw new TypeError('Object\x20is\x20not\x20iterable');qR[qf++]=vmp(j4,j3,[]),qd++;}break;}case 0x90:{DK:{let j5=qR[--qf],j6=qR[qf-0x1],j7=qx[gd];vmM(j6['prototype'],j7,{'value':j5,'writable':!![],'enumerable':![],'configurable':!![]}),qd++;}break;}case 0x80:{DE:{let j8=qR[--qf];qR[qf++]=!!j8['done'],qd++;}break;}case 0x8e:{Dp:{let j9=qR[--qf],jq=qR[--qf],jg=vmP_46887['_$JaO5bA'],jm=jg?vmB(jg):B(jq),jj=K(jm,j9);if(jj['desc']&&jj['desc']['get']){let jD=jj['desc']['get']['call'](jq);qR[qf++]=jD,qd++;break Dp;}if(jj['desc']&&jj['desc']['set']&&!('value'in jj['desc'])){qR[qf++]=undefined,qd++;break Dp;}let jw=jj['proto']?jj['proto'][j9]:jm[j9];if(typeof jw==='function'){let jI=jj['proto']||jm,ji=jw['bind'](jq),jP=jw['constructor']&&jw['constructor']['name'],jb=jP==='GeneratorFunction'||jP==='AsyncFunction'||jP==='AsyncGeneratorFunction';!jb&&(!vmP_46887['_$LLmpeU']&&(vmP_46887['_$LLmpeU']=new WeakMap()),vmP_46887['_$LLmpeU']['set'](ji,jI)),qR[qf++]=ji;}else qR[qf++]=jw;qd++;}break;}case 0xa2:{DY:{let jZ=gd&0xffff,jF=gd>>0x10,jv=qx[jZ],ju=qx[jF];qR[qf++]=new RegExp(jv,ju),qd++;}break;}case 0x7b:{DC:{let jM=qR[--qf],jO=jM['next']();qR[qf++]=jO,qd++;}break;}case 0x8f:{DR:{let jo=qR[--qf],jN=qR[--qf],jL=qR[--qf],jS=B(jL),jB=K(jS,jN);jB['desc']&&jB['desc']['set']?jB['desc']['set']['call'](jL,jo):jL[jN]=jo,qR[qf++]=jo,qd++;}break;}case 0xa9:{Df:{let jK=qR[--qf];qR[qf++]=Symbol['keyFor'](jK),qd++;}break;}case 0xa1:{DG:{if(gg===null){if(gO['_$91g7PJ']||!gO['_$jJm7Vy']){let jE=gO['_$ZUpyWr']||qK,jp=jE?jE['length']:0x0;gg=vmO(Object['prototype']);for(let jY=0x0;jY<jp;jY++){gg[jY]=jE[jY];}vmM(gg,'length',{'value':jp,'writable':!![],'enumerable':![],'configurable':!![]}),vmM(gg,Symbol['iterator'],{'value':Array['prototype'][Symbol['iterator']],'writable':!![],'enumerable':![],'configurable':!![]}),gg=new Proxy(gg,{'has':function(jC,jR){if(jR===Symbol['toStringTag'])return![];return jR in jC;},'get':function(jC,jR,jf){if(jR===Symbol['toStringTag'])return'Arguments';return Reflect['get'](jC,jR,jf);}}),gO['_$91g7PJ']?vmM(gg,'callee',{'get':F,'set':F,'enumerable':![],'configurable':![]}):vmM(gg,'callee',{'value':qp,'writable':!![],'enumerable':![],'configurable':!![]});}else{let jC=qK?qK['length']:0x0,jR={},jf={},jG=qp,jd=![],jx=!![],jt={},jl=function(jc){if(typeof jc!=='string')return NaN;let je=+jc;return je>=0x0&&je%0x1===0x0&&String(je)===jc?je:NaN;},jU=function(jc){return!isNaN(jc)&&jc>=0x0;},jQ=function(jc){if(jc in jf)return undefined;if(jc in jR)return jR[jc];return jc<qK['length']?qK[jc]:undefined;},jA=function(jc){if(jc in jf)return![];if(jc in jR)return!![];return jc<qK['length']?jc in qK:![];},jX={};vmM(jX,'length',{'value':jC,'writable':!![],'enumerable':![],'configurable':!![]}),vmM(jX,'callee',{'value':qp,'writable':!![],'enumerable':![],'configurable':!![]}),vmM(jX,Symbol['iterator'],{'value':Array['prototype'][Symbol['iterator']],'writable':!![],'enumerable':![],'configurable':!![]}),gg=new Proxy(jX,{'get':function(jc,je,jk){if(je==='length')return jC;if(je==='callee')return jd?undefined:jG;if(je===Symbol['toStringTag'])return'Arguments';let jr=jl(je);if(jU(jr)){if(jr in jt)return Reflect['get'](jc,je,jk);return jQ(jr);}return Reflect['get'](jc,je,jk);},'set':function(jc,je,jk){if(je==='length'){if(!jx)return![];return jC=jk,jc['length']=jk,!![];}if(je==='callee')return jG=jk,jd=![],jc['callee']=jk,!![];let jr=jl(je);if(jU(jr)){if(jr in jt)return Reflect['set'](jc,je,jk);let js=vmo(jc,String(jr));if(js&&!js['writable'])return![];if(jr in jf)delete jf[jr],jR[jr]=jk;else jr<qK['length']?qK[jr]=jk:jR[jr]=jk;return!![];}return jc[je]=jk,!![];},'has':function(jc,je){if(je==='length')return!![];if(je==='callee')return!jd;if(je===Symbol['toStringTag'])return![];let jk=jl(je);if(jU(jk)){if(String(jk)in jc)return!![];return jA(jk);}return je in jc;},'defineProperty':function(jc,je,jk){if(je==='length')return'value'in jk&&(jC=jk['value']),'writable'in jk&&(jx=jk['writable']),vmM(jc,je,jk),!![];if(je==='callee')return'value'in jk&&(jG=jk['value']),jd=![],vmM(jc,je,jk),!![];let jr=jl(je);if(jU(jr)){if('get'in jk||'set'in jk)jt[jr]=0x1,jr in jR&&delete jR[jr],jr in jf&&delete jf[jr];else'value'in jk&&(jr<qK['length']&&!(jr in jf)?qK[jr]=jk['value']:(jR[jr]=jk['value'],jr in jf&&delete jf[jr]));return vmM(jc,String(jr),jk),!![];}return vmM(jc,je,jk),!![];},'deleteProperty':function(jc,je){if(je==='callee')return jd=!![],delete jc['callee'],!![];let jk=jl(je);return jU(jk)&&(jk in jt&&delete jt[jk],jk<qK['length']?jf[jk]=0x1:delete jR[jk]),delete jc[je],!![];},'preventExtensions':function(jc){let je=qK?qK['length']:0x0;for(let jk=0x0;jk<je;jk++){!(jk in jf)&&!vmo(jc,String(jk))&&vmM(jc,String(jk),{'value':jQ(jk),'writable':!![],'enumerable':!![],'configurable':!![]});}for(let jr in jR){!vmo(jc,jr)&&vmM(jc,jr,{'value':jR[jr],'writable':!![],'enumerable':!![],'configurable':!![]});}return Object['preventExtensions'](jc),!![];},'getOwnPropertyDescriptor':function(jc,je){if(je==='callee'){if(jd)return undefined;return vmo(jc,'callee');}if(je==='length')return vmo(jc,'length');let jk=jl(je);if(jU(jk)){if(jk in jt)return vmo(jc,je);if(jA(jk)){let js=vmo(jc,String(jk));return{'value':jQ(jk),'writable':js?js['writable']:!![],'enumerable':js?js['enumerable']:!![],'configurable':js?js['configurable']:!![]};}return vmo(jc,je);}let jr=vmo(jc,je);if(jr)return jr;return undefined;},'ownKeys':function(jc){let je=[],jk=qK?qK['length']:0x0;for(let js=0x0;js<jk;js++){!(js in jf)&&je['push'](String(js));}for(let jy in jR){je['indexOf'](jy)===-0x1&&je['push'](jy);}je['push']('length');!jd&&je['push']('callee');let jr=Reflect['ownKeys'](jc);for(let jW=0x0;jW<jr['length'];jW++){je['indexOf'](jr[jW])===-0x1&&je['push'](jr[jW]);}return je;}});}}qR[qf++]=gg,qd++;}break;}case 0xb9:{Dd:{let jc=qR[--qf],je=qR[--qf],jk=qR[qf-0x1];vmM(jk,je,{'set':jc,'enumerable':![],'configurable':!![]}),qd++;}break;}case 0x91:{Dx:{let jr=qR[--qf],js=qR[qf-0x1],jy=qx[gd],jW=S(js);vmM(jW,jy,{'get':jr,'enumerable':jW===js,'configurable':!![]}),qd++;}break;}case 0x5e:{Dt:{let jV=qR[--qf],jT=qR[qf-0x1];if(Array['isArray'](jV))Array['prototype']['push']['apply'](jT,jV);else for(let jz of jV){jT['push'](jz);}qd++;}break;}case 0x64:{Dl:{let jn=qR[--qf],ja=typeof jn==='object'?jn:qN(jn),jh=ja&&ja[0x5],jJ=ja&&ja[0x12],jH=ja&&ja[0x13],w0=ja&&ja[0x9],w1=ja&&ja[0x1]||0x0,w2=ja&&ja[0xa],w3=jh?gO['_$7vKXLR']:undefined,w4=gO['_$LC7hqs'],w5;if(jH)w5=l(qS,jn,w4,u,w2,vmF);else{if(jJ){if(jh)w5=Q(qL,jn,w4,w3);else w0?w5=X(qL,jn,w4,w2,vmF):w5=t(qL,jn,w4,w2,vmF);}else{if(jh)w5=U(s,jn,w4,w3);else w0?w5=A(s,jn,w4,w2,vmF):w5=x(s,jn,w4,w2,vmF);}}O(w5,'length',{'value':w1,'writable':![],'enumerable':![],'configurable':!![]}),qR[qf++]=w5,qd++;}break;}case 0x97:{DU:{let w6=qR[--qf],w7=qR[--qf],w8=qx[gd],w9=C(),wq='set_'+w8,wg=w9['get'](wq);if(wg&&wg['has'](w7)){let wD=wg['get'](w7);wD['call'](w7,w6),qR[qf++]=w6,qd++;break DU;}let wm='_$Zg7WnI'+'set_'+w8['substring'](0x1)+'_$TzWqcg';if(w7['constructor']&&wm in w7['constructor']){let wI=w7['constructor'][wm];wI['call'](w7,w6),qR[qf++]=w6,qd++;break DU;}let wj=w9['get'](w8);if(wj&&wj['has'](w7)){wj['set'](w7,w6),qR[qf++]=w6,qd++;break DU;}let ww=G(w8);if(ww in w7){w7[ww]=w6,qR[qf++]=w6,qd++;break DU;}throw new TypeError('Cannot\x20write\x20private\x20member\x20'+w8+'\x20to\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');}break;}case 0x84:{DQ:{let wi=qR[--qf];qR[qf++]=N(wi),qd++;}break;}case 0x7c:{DA:{let wP=qR[--qf];wP&&typeof wP['return']==='function'&&wP['return'](),qd++;}break;}case 0x8d:{DX:{let wb=qR[--qf],wZ=qR[qf-0x1];if(wb===null){vmS(wZ['prototype'],null),vmS(wZ,Function['prototype']),wZ['_$a7L7a4']=null,qd++;break DX;}if(typeof wb!=='function')throw new TypeError('Class\x20extends\x20value\x20'+String(wb)+'\x20is\x20not\x20a\x20constructor\x20or\x20null');let wF=![];try{let wv=vmO(wb['prototype']),wu=wb['apply'](wv,[]);wu!==undefined&&wu!==wv&&(wF=!![]);}catch(wM){wM instanceof TypeError&&(wM['message']['includes']('\x27new\x27')||wM['message']['includes']('constructor')||wM['message']['includes']('Illegal\x20constructor'))&&(wF=!![]);}if(wF){let wO=wZ,wo=vmP_46887,wN='_$9tjGj8',wL='_$Gw2Nwr',wS='_$PiSzls';function gx(...wB){let wK=vmO(wb['prototype']);wo[wS]={'parent':wb,'newTarget':new.target||gx},wo[wL]=new.target||gx;let wE=wN in wo;!wE&&(wo[wN]=new.target);try{let wp=wO['apply'](wK,wB);wp!==undefined&&typeof wp==='object'&&(wK=wp);}finally{delete wo[wS],delete wo[wL],!wE&&delete wo[wN];}return wK;}gx['prototype']=vmO(wb['prototype']),gx['prototype']['constructor']=gx,vmS(gx,wb),vmN(wO)['forEach'](function(wB){wB!=='prototype'&&wB!=='length'&&wB!=='name'&&O(gx,wB,vmo(wO,wB));});wO['prototype']&&(vmN(wO['prototype'])['forEach'](function(wB){wB!=='constructor'&&O(gx['prototype'],wB,vmo(wO['prototype'],wB));}),vmL(wO['prototype'])['forEach'](function(wB){O(gx['prototype'],wB,vmo(wO['prototype'],wB));}));qR[--qf],qR[qf++]=gx,gx['_$a7L7a4']=wb,qd++;break DX;}vmS(wZ['prototype'],wb['prototype']),vmS(wZ,wb),wZ['_$a7L7a4']=wb,qd++;}break;}case 0xb8:{Dc:{let wB=qR[--qf],wK=qR[--qf],wE=qR[qf-0x1];vmM(wE,wK,{'get':wB,'enumerable':![],'configurable':!![]}),qd++;}break;}case 0xa3:{De:{qR[--qf],qR[qf++]=undefined,qd++;}break;}case 0x83:{Dk:{let wp=qR[--qf];wp&&typeof wp['return']==='function'?qR[qf++]=Promise['resolve'](wp['return']()):qR[qf++]=Promise['resolve'](),qd++;}break;}case 0x81:{Dr:{let wY=qR[--qf];if(wY==null)throw new TypeError('Cannot\x20iterate\x20over\x20'+wY);let wC=wY[Symbol['asyncIterator']];if(typeof wC==='function')qR[qf++]=wC['call'](wY);else{let wR=wY[Symbol['iterator']];if(typeof wR!=='function')throw new TypeError('Object\x20is\x20not\x20async\x20iterable');qR[qf++]=wR['call'](wY);}qd++;}break;}case 0x8c:{Ds:{let wf=qR[--qf],wG=qR[--qf],wd=gd,wx=function(wt,wl){let wU=function(){if(wt){wl&&(vmP_46887['_$Gw2Nwr']=wU);let wQ='_$9tjGj8'in vmP_46887;!wQ&&(vmP_46887['_$9tjGj8']=new.target);try{let wA=wt['apply'](this,L(arguments));if(wl&&wA!==undefined&&(typeof wA!=='object'||wA===null))throw new TypeError('Derived\x20constructors\x20may\x20only\x20return\x20object\x20or\x20undefined');return wA;}finally{wl&&delete vmP_46887['_$Gw2Nwr'],!wQ&&delete vmP_46887['_$9tjGj8'];}}};return wU;}(wG,wd);wf&&vmM(wx,'name',{'value':wf,'configurable':!![]}),qR[qf++]=wx,qd++;}break;}case 0x9a:{Dy:{let wt=qR[--qf],wl=qR[--qf],wU=qx[gd],wQ=null,wA=R();if(wA){let we=wA['get'](wU);we&&we['has'](wl)&&(wQ=we['get'](wl));}if(wQ===null){let wk=d(wU);wk in wl&&(wQ=wl[wk]);}if(wQ===null)throw new TypeError('Cannot\x20read\x20private\x20member\x20'+wU+'\x20from\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');if(typeof wQ!=='function')throw new TypeError(wU+'\x20is\x20not\x20a\x20function');let wX=o(g3,wt),wc=wQ['apply'](wl,wX);qR[qf++]=wc,qd++;}break;}case 0xb4:{DW:{let wr=qR[--qf],ws=qR[--qf],wy=qR[qf-0x1];vmM(wy['prototype'],ws,{'value':wr,'writable':!![],'enumerable':![],'configurable':!![]}),qd++;}break;}case 0xa6:{DV:{qR[qf++]=vmu[gd],qd++;}break;}case 0x95:{DT:{let wW=qR[--qf],wV=qR[qf-0x1],wT=qx[gd];vmM(wV,wT,{'set':wW,'enumerable':![],'configurable':!![]}),qd++;}break;}case 0x94:{Dz:{let wz=qR[--qf],wn=qR[qf-0x1],wa=qx[gd];vmM(wn,wa,{'get':wz,'enumerable':![],'configurable':!![]}),qd++;}break;}case 0xa8:{Dn:{let wh=qx[gd];qR[qf++]=Symbol['for'](wh),qd++;}break;}case 0xb6:{Da:{let wJ=qR[--qf],wH=qR[--qf],D0=qR[qf-0x1],D1=S(D0);vmM(D1,wH,{'get':wJ,'enumerable':D1===D0,'configurable':!![]}),qd++;}break;}case 0x5f:{Dh:{let D2=qR[qf-0x1];D2['length']++,qd++;}break;}case 0x9b:{DJ:{let D3=qR[--qf],D4=qx[gd];if(D3==null){qR[qf++]=undefined,qd++;break DJ;}let D5=C(),D6=D5['get'](D4);if(!D6||!D6['has'](D3))throw new TypeError('Cannot\x20read\x20private\x20member\x20'+D4+'\x20from\x20an\x20object\x20whose\x20class\x20did\x20not\x20declare\x20it');qR[qf++]=D6['get'](D3),qd++;}break;}case 0xa0:{DH:{if(gO['_$kU7fVk']&&!gO['_$AZitn3'])throw new ReferenceError('Must\x20call\x20super\x20constructor\x20in\x20derived\x20class\x20before\x20accessing\x20\x27this\x27\x20or\x20returning\x20from\x20derived\x20constructor');qR[qf++]=qC,qd++;}break;}}},gS=function(gG,gd){switch(gG){case 0xdc:{mt:{let gt=qR[--qf],gl=qx[gd];if(gO['_$91g7PJ']&&!(gl in vmF)&&!(gl in vmP_46887))throw new ReferenceError(gl+'\x20is\x20not\x20defined');vmP_46887[gl]=gt,vmF[gl]=gt,qR[qf++]=gt,qd++;}break;}case 0xfe:{ml:{let gU=gd&0xffff,gQ=gd>>>0x10;qR[qf++]=qG[gU]*qx[gQ],qd++;}break;}case 0x100:{mU:{let gA=gd&0xffff,gX=gd>>>0x10;qR[qf++]=qG[gA]<qx[gX],qd++;}break;}case 0xd8:{mQ:{let gc=qx[gd],ge=qR[--qf],gk=gO['_$LC7hqs'],gr=![];while(gk){if(gk['_$V9UZjo']&&gc in gk['_$V9UZjo']){if(gk['_$igrgfe']&&gc in gk['_$igrgfe'])break;gk['_$V9UZjo'][gc]=ge;!gk['_$igrgfe']&&(gk['_$igrgfe']=vmO(null));gk['_$igrgfe'][gc]=!![],gr=!![];break;}gk=gk['_$skyF7O'];}!gr&&(p(gO['_$LC7hqs'],gc),!gO['_$LC7hqs']['_$V9UZjo']&&(gO['_$LC7hqs']['_$V9UZjo']=vmO(null)),gO['_$LC7hqs']['_$V9UZjo'][gc]=ge,!gO['_$LC7hqs']['_$igrgfe']&&(gO['_$LC7hqs']['_$igrgfe']=vmO(null)),gO['_$LC7hqs']['_$igrgfe'][gc]=!![]),qd++;}break;}case 0x102:{mA:{let gs=gd&0xffff,gy=gd>>>0x10,gW=qR[--qf],gV=o(g3,gW),gT=qG[gs],gz=qx[gy],gn=gT[gz];qR[qf++]=gn['apply'](gT,gV),qd++;}break;}case 0xc9:{mX:{qd++;}break;}case 0xfb:{mc:{qG[gd]=qG[gd]-0x1,qd++;}break;}case 0x10f:{me:{if(typeof process!=='undefined'&&process['hrtime']&&process['hrtime']['bigint']){var gx=process['hrtime']['bigint']();debugger;if(Number(process['hrtime']['bigint']()-gx)/0xf4240>0.1)try{_setDeceptionDetected();}catch(ga){}}qd++;}break;}case 0xca:{mk:{return gM=qf>0x0?qR[--qf]:undefined,0x1;}break;}case 0xfd:{mr:{let gh=gd&0xffff,gJ=gd>>>0x10;qR[qf++]=qG[gh]-qx[gJ],qd++;}break;}case 0xc8:{ms:{debugger;qd++;}break;}case 0xfa:{my:{qG[gd]=qG[gd]+0x1,qd++;}break;}case 0x10e:{mW:{debugger;qd++;}break;}case 0x101:{mV:{let gH=gd&0xffff,m0=gd>>>0x10;qG[gH]<qx[m0]?qd=ql[qd]:qd++;}break;}case 0xd4:{mT:{let m1=qx[gd],m2=qR[--qf],m3=gO['_$LC7hqs'],m4=![];while(m3){let m5=m3['_$O1cfgJ'],m6=m3['_$V9UZjo'];if(m5&&m1 in m5)throw new ReferenceError('Cannot\x20access\x20\x27'+m1+'\x27\x20before\x20initialization');if(m6&&m1 in m6){if(m3['_$5EcxPs']&&m1 in m3['_$5EcxPs']){if(gO['_$91g7PJ'])throw new TypeError('Assignment\x20to\x20constant\x20variable.');m4=!![];break;}if(m3['_$igrgfe']&&m1 in m3['_$igrgfe'])throw new TypeError('Assignment\x20to\x20constant\x20variable.');m6[m1]=m2,m4=!![];break;}m3=m3['_$skyF7O'];}if(!m4){if(m1 in vmP_46887)vmP_46887[m1]=m2;else m1 in vmF?vmF[m1]=m2:vmF[m1]=m2;}qd++;}break;}case 0x104:{mz:{let m7=qG[gd]+0x1;qG[gd]=m7,qR[qf++]=m7,qd++;}break;}case 0xd3:{mn:{let m8=qx[gd];if(m8==='__this__'){let mw=gO['_$LC7hqs'];while(mw){if(mw['_$O1cfgJ']&&'__this__'in mw['_$O1cfgJ'])throw new ReferenceError('Cannot\x20access\x20\x27__this__\x27\x20before\x20initialization');if(mw['_$V9UZjo']&&'__this__'in mw['_$V9UZjo'])break;mw=mw['_$skyF7O'];}qR[qf++]=qC,qd++;break mn;}let m9=gO['_$LC7hqs'],mq,mg=![],mm=m8['indexOf']('$$'),mj=mm!==-0x1?m8['substring'](0x0,mm):null;while(m9){let mD=m9['_$O1cfgJ'],mI=m9['_$V9UZjo'];if(mD&&m8 in mD)throw new ReferenceError('Cannot\x20access\x20\x27'+m8+'\x27\x20before\x20initialization');if(mj&&mD&&mj in mD){if(!(mI&&m8 in mI))throw new ReferenceError('Cannot\x20access\x20\x27'+mj+'\x27\x20before\x20initialization');}if(mI&&m8 in mI){mq=mI[m8],mg=!![];break;}m9=m9['_$skyF7O'];}!mg&&(m8 in vmP_46887?mq=vmP_46887[m8]:mq=vmF[m8]),qR[qf++]=mq,qd++;}break;}case 0xd2:{ma:{let mi=qR[--qf],mP={['_$V9UZjo']:null,['_$igrgfe']:null,['_$O1cfgJ']:null,['_$skyF7O']:mi};gO['_$LC7hqs']=mP,qd++;}break;}case 0xd9:{mh:{let mb=qx[gd],mZ=qR[--qf];E(gO['_$LC7hqs'],mb);if(!gO['_$LC7hqs']['_$V9UZjo'])gO['_$LC7hqs']['_$V9UZjo']=vmO(null);gO['_$LC7hqs']['_$V9UZjo'][mb]=mZ,!gO['_$LC7hqs']['_$igrgfe']&&(gO['_$LC7hqs']['_$igrgfe']=vmO(null)),gO['_$LC7hqs']['_$igrgfe'][mb]=!![],qd++;}break;}case 0x103:{mJ:{qG[gd]=qR[--qf],qd++;}break;}case 0xdb:{mH:{let mF=qx[gd],mv=qR[--qf],mu=gO['_$LC7hqs']['_$skyF7O'];mu&&(!mu['_$V9UZjo']&&(mu['_$V9UZjo']=vmO(null)),mu['_$V9UZjo'][mF]=mv),qd++;}break;}case 0xda:{j0:{let mM=qx[gd];!gO['_$LC7hqs']['_$O1cfgJ']&&(gO['_$LC7hqs']['_$O1cfgJ']=vmO(null)),gO['_$LC7hqs']['_$O1cfgJ'][mM]=!![],qd++;}break;}case 0xd6:{j1:{gO['_$LC7hqs']&&gO['_$LC7hqs']['_$skyF7O']&&(gO['_$LC7hqs']=gO['_$LC7hqs']['_$skyF7O']),qd++;}break;}case 0xff:{j2:{let mO=gd&0xffff,mo=gd>>>0x10,mN=qG[mO],mL=qx[mo];qR[qf++]=mN[mL],qd++;}break;}case 0xd7:{j3:{let mS=qx[gd],mB=qR[--qf];E(gO['_$LC7hqs'],mS),!gO['_$LC7hqs']['_$V9UZjo']&&(gO['_$LC7hqs']['_$V9UZjo']=vmO(null)),gO['_$LC7hqs']['_$V9UZjo'][mS]=mB,qd++;}break;}case 0xfc:{j4:{let mK=gd&0xffff,mE=gd>>>0x10;qR[qf++]=qG[mK]+qx[mE],qd++;}break;}case 0x105:{j5:{let mp=qG[gd]-0x1;qG[gd]=mp,qR[qf++]=mp,qd++;}break;}case 0xdd:{j6:{let mY=gd&0xffff,mC=gd>>>0x10,mR=qx[mY],mf=gO['_$LC7hqs'];for(let mx=0x0;mx<mC;mx++){mf=mf['_$skyF7O'];}let mG=mf['_$O1cfgJ'];if(mG&&mR in mG)throw new ReferenceError('Cannot\x20access\x20\x27'+mR+'\x27\x20before\x20initialization');let md=mf['_$V9UZjo'];qR[qf++]=md?md[mR]:undefined,qd++;}break;}case 0xd5:{j7:{qR[qf++]=gO['_$LC7hqs'],qd++;}break;}}});switch(gp){case 0x48:{let gG=qR[--qf],gd=qR[--qf];if(gd===null||gd===undefined)throw new TypeError('Cannot\x20read\x20property\x20\x27'+String(gG)+'\x27\x20of\x20'+gd);qR[qf++]=gd[gG],qd++;continue;}case 0x32:{qd=ql[qd];continue;}case 0x10:{let gx=qR[--qf];qR[qf++]=typeof gx===b?gx+0x1n:+gx+0x1,qd++;continue;}case 0x1c:{let gt=qR[--qf];qR[qf++]=typeof gt===b?gt:+gt,qd++;continue;}case 0x34:{!qR[--qf]?qd=ql[qd]:qd++;continue;}case 0x3:{qR[--qf],qd++;continue;}case 0x2c:{let gl=qR[--qf],gU=qR[--qf];qR[qf++]=gU<gl,qd++;continue;}case 0x4:{let gQ=qR[qf-0x1];qR[qf++]=gQ,qd++;continue;}case 0x7:{qG[gY]=qR[--qf],qd++;continue;}case 0x6:{qR[qf++]=qG[gY],qd++;continue;}case 0xb:{let gA=qR[--qf],gX=qR[--qf];qR[qf++]=gX-gA,qd++;continue;}case 0x0:{qR[qf++]=qx[gY],qd++;continue;}case 0x1:{qR[qf++]=undefined,qd++;continue;}case 0x2e:{let gc=qR[--qf],ge=qR[--qf];qR[qf++]=ge>gc,qd++;continue;}case 0xa:{let gk=qR[--qf],gr=qR[--qf];qR[qf++]=gr+gk,qd++;continue;}case 0x8:{qR[qf++]=qK[gY],qd++;continue;}case 0x49:{let gs=qR[--qf],gy=qR[--qf],gW=qR[--qf];if(gW===null||gW===undefined)throw new TypeError('Cannot\x20set\x20property\x20\x27'+String(gy)+'\x27\x20of\x20'+gW);if(qn){if(!Reflect['set'](gW,gy,gs))throw new TypeError('Cannot\x20assign\x20to\x20read\x20only\x20property\x20\x27'+String(gy)+'\x27\x20of\x20object');}else gW[gy]=gs;qR[qf++]=gs,qd++;continue;}}gO=gI;if(gp<0x5a){if(gN(gp,gY)){if(gD>0x0){go();continue;}return gM;}}else{if(gp<0xc8){if(gL(gp,gY)){if(gD>0x0){go();continue;}return gM;}}else{if(gS(gp,gY)){if(gD>0x0){go();continue;}return gM;}}}g9=gI['_$LC7hqs'],gm=gI['_$AZitn3'];}break;}catch(gV){if(qk&&qk['length']>0x0){let gT=qk[qk['length']-0x1];qf=gT['_$z51hbX'];if(gT['_$xHA9qT']!==undefined)g2(gV),qd=gT['_$xHA9qT'],gT['_$xHA9qT']=undefined,gT['_$EPwog9']===undefined&&qk['pop']();else gT['_$EPwog9']!==undefined?(qd=gT['_$EPwog9'],gT['_$OnfOr1']=gV):(qd=gT['_$kqUgKx'],qk['pop']());continue;}throw gV;}}return qf>0x0?qR[--qf]:gm?qC:undefined;}return gi(0x0);}function*r(qB,qK,qE,qp,qY,qC){let qR=k(qB,qK,qE,qp,qY,qC);while(!![]){if(qR&&typeof qR==='object'&&qR['_$Z70Cy8']!==undefined){let qf=qR['_d'],qG;try{qG=yield qR;}catch(qd){qR=qf(0x2,qd);continue;}qG&&typeof qG==='object'&&qG['_$Z70Cy8']===D?qR=qf(0x3,qG['_$Jl1CuU']):qR=qf(0x1,qG);}else return qR;}}let s=function(qB,qK,qE,qp,qY,qC){vmP_46887['_$ZFycJB']?vmP_46887['_$ZFycJB']=![]:vmP_46887['_$JaO5bA']=undefined;let qR=typeof qB==='object'?qB:qN(qB);return c(qR,qK,qE,qp,qY,qC);},y=0x0,W=0x1,V=0x2,T=0x3,z=0x4,n=0x5,a=0x6,h=0x7,J=0x8,H=0x9,q0=0xa,q1=0x1,q2=0x2,q3=0x4,q4=0x8,q5=0x20,q6=0x40,q7=0x80,q8=0x100,q9=0x200,qq=0x400,qg=0x800,qm=0x1000,qj=0x2000,qw=0x4000,qD=0x8000,qI=0x10000,qi=0x20000,qP=0x40000,qb=0x80000;function qZ(qB){this['_$JiBgtB']=qB,this['_$59CyYD']=new DataView(qB['buffer'],qB['byteOffset'],qB['byteLength']),this['_$xD81hD']=0x0;}qZ['prototype']['_$vSfDM2']=function(){return this['_$JiBgtB'][this['_$xD81hD']++];},qZ['prototype']['_$NkDVek']=function(){let qB=this['_$59CyYD']['getUint16'](this['_$xD81hD'],!![]);return this['_$xD81hD']+=0x2,qB;},qZ['prototype']['_$sZskHA']=function(){let qB=this['_$59CyYD']['getUint32'](this['_$xD81hD'],!![]);return this['_$xD81hD']+=0x4,qB;},qZ['prototype']['_$m0jw1u']=function(){let qB=this['_$59CyYD']['getInt32'](this['_$xD81hD'],!![]);return this['_$xD81hD']+=0x4,qB;},qZ['prototype']['_$g2qrSi']=function(){let qB=this['_$59CyYD']['getFloat64'](this['_$xD81hD'],!![]);return this['_$xD81hD']+=0x8,qB;},qZ['prototype']['_$t0yUKo']=function(){let qB=0x0,qK=0x0,qE;do{qE=this['_$vSfDM2'](),qB|=(qE&0x7f)<<qK,qK+=0x7;}while(qE>=0x80);return qB>>>0x1^-(qB&0x1);},qZ['prototype']['_$yWQ92E']=function(){let qB=this['_$t0yUKo'](),qK=this['_$JiBgtB'],qE=this['_$xD81hD'],qp=qE+qB;this['_$xD81hD']=qp;var qY='';while(qE<qp){var qC=qK[qE++];if(qC<0x80)qY+=String['fromCharCode'](qC);else{if(qC<0xe0)qY+=String['fromCharCode']((qC&0x1f)<<0x6|qK[qE++]&0x3f);else{if(qC<0xf0)qY+=String['fromCharCode']((qC&0xf)<<0xc|(qK[qE++]&0x3f)<<0x6|qK[qE++]&0x3f);else{var qR=(qC&0x7)<<0x12|(qK[qE++]&0x3f)<<0xc|(qK[qE++]&0x3f)<<0x6|qK[qE++]&0x3f;qR-=0x10000,qY+=String['fromCharCode']((qR>>0xa)+0xd800,(qR&0x3ff)+0xdc00);}}}}return qY;};var qF='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',qv=new Uint8Array(0x80);for(var qu=0x0;qu<qF['length'];qu++){qv[qF['charCodeAt'](qu)]=qu;}function qM(qB){var qK=qB['charCodeAt'](qB['length']-0x1)===0x3d?qB['charCodeAt'](qB['length']-0x2)===0x3d?0x2:0x1:0x0,qE=(qB['length']*0x3>>0x2)-qK,qp=new Uint8Array(qE),qY=0x0;for(var qC=0x0;qC<qB['length'];qC+=0x4){var qR=qv[qB['charCodeAt'](qC)],qf=qv[qB['charCodeAt'](qC+0x1)],qG=qv[qB['charCodeAt'](qC+0x2)],qd=qv[qB['charCodeAt'](qC+0x3)];qp[qY++]=qR<<0x2|qf>>0x4,qY<qE&&(qp[qY++]=(qf&0xf)<<0x4|qG>>0x2),qY<qE&&(qp[qY++]=(qG&0x3)<<0x6|qd);}return qp;}function qO(qB){let qK=qB['_$vSfDM2']();switch(qK){case y:return null;case W:return undefined;case V:return![];case T:return!![];case z:{let qE=qB['_$vSfDM2']();return qE>0x7f?qE-0x100:qE;}case n:{let qp=qB['_$NkDVek']();return qp>0x7fff?qp-0x10000:qp;}case a:return qB['_$m0jw1u']();case h:return qB['_$g2qrSi']();case J:return qB['_$yWQ92E']();case H:return BigInt(qB['_$yWQ92E']());case q0:{let qY=qB['_$yWQ92E'](),qC=qB['_$yWQ92E']();return new RegExp(qY,qC);}default:return null;}}function qo(qB){let qK=typeof qB==='string'?qM(qB):qB,qE=new qZ(qK),qp=qE['_$vSfDM2'](),qY=qE['_$sZskHA'](),qC=qE['_$t0yUKo'](),qR=qE['_$t0yUKo'](),qf=[];qf[0x1]=qC,qf[0x2]=qR;qY&q4&&(qf[0x0]=qE['_$t0yUKo']());if(qY&q5){let qX=qE['_$t0yUKo'](),qc={};for(let qe=0x0;qe<qX;qe++){let qk=qE['_$t0yUKo'](),qr=qE['_$t0yUKo']();qc[qk]=qr;}qf[0x7]=qc;}qY&q6&&(qf[0xe]=qE['_$sZskHA']());qY&q7&&(qf[0x8]=qE['_$sZskHA']());qY&q8&&(qf[0x14]=qE['_$sZskHA']());qY&q9&&(qf[0x3]=qE['_$t0yUKo']());qY&qq&&(qf[0x11]=qE['_$sZskHA']());qY&qb&&(qf[0xf]=qE['_$t0yUKo']());qY&q1&&(qf[0x5]=0x1);qY&q2&&(qf[0x12]=0x1);qY&q3&&(qf[0x13]=0x1);qY&qw&&(qf[0x9]=0x1);qY&qD&&(qf[0xa]=0x1);qY&qI&&(qf[0x4]=0x1);qY&qi&&(qf[0x6]=0x1);qY&qP&&(qf[0x16]=0x1);qY&qj&&(qf[0xc]=0x1);let qG=qE['_$t0yUKo'](),qd=new Array(qG);for(let qs=0x0;qs<qG;qs++){qd[qs]=qO(qE);}qf[0x10]=qd;function qx(qy){let qW=qy['_$vSfDM2']();switch(qW){case y:return null;case z:{let qV=qy['_$vSfDM2']();return qV>0x7f?qV-0x100:qV;}case n:{let qT=qy['_$NkDVek']();return qT>0x7fff?qT-0x10000:qT;}case a:return qy['_$m0jw1u']();case h:return qy['_$g2qrSi']();case J:return qy['_$yWQ92E']();default:return null;}}let qt=qE['_$t0yUKo'](),ql=qt<<0x1,qU=new Array(ql),qQ=0x0,qA=(qC*0x1f^qR*0x11^qt*0xd^qG*0x7)>>>0x0&0x3;switch(qA){case 0x1:for(let qy=0x0;qy<qt;qy++){let qW=qx(qE),qV=qE['_$t0yUKo']();qU[qQ++]=qW,qU[qQ++]=qV;}break;case 0x2:{let qT=new Array(qt);for(let qz=0x0;qz<qt;qz++){qT[qz]=qE['_$t0yUKo']();}for(let qn=0x0;qn<qt;qn++){qU[qQ++]=qT[qn];}for(let qa=0x0;qa<qt;qa++){qU[qQ++]=qx(qE);}break;}case 0x3:{let qh=new Array(qt);for(let qJ=0x0;qJ<qt;qJ++){qh[qJ]=qx(qE);}for(let qH=0x0;qH<qt;qH++){qU[qQ++]=qh[qH];}for(let g0=0x0;g0<qt;g0++){qU[qQ++]=qE['_$t0yUKo']();}break;}case 0x0:default:for(let g1=0x0;g1<qt;g1++){qU[qQ++]=qE['_$t0yUKo'](),qU[qQ++]=qx(qE);}break;}qf[0xb]=qU;if(qY&qg){let g2=qE['_$t0yUKo'](),g3={};for(let g4=0x0;g4<g2;g4++){let g5=qE['_$t0yUKo'](),g6=qE['_$t0yUKo']();g3[g5]=g6;}qf[0x15]=g3;}if(qY&qm){let g7=qE['_$t0yUKo'](),g8={};for(let g9=0x0;g9<g7;g9++){let gq=qE['_$t0yUKo'](),gg=qE['_$t0yUKo']()-0x1,gm=qE['_$t0yUKo']()-0x1,gj=qE['_$t0yUKo']()-0x1;g8[gq]=[gg,gm,gj];}qf[0xd]=g8;}return qf;}let qN=function(qB){let qK=q;q=null;let qE=null,qp={};return function(qY){let qC=qE?qE[qY]:qY;if(qp[qC])return qp[qC];let qR=qK[qC];return typeof qR==='string'?qp[qC]=qB(qR):qp[qC]=qR,qp[qC];};}(qo),qL=async function(qB,qK,qE,qp,qY,qC,qR){let qf=typeof qB==='object'?qB:qN(qB),qG=r(qf,qK,qE,qp,qY,qR),qd=qG['next']();while(!qd['done']){if(qd['value']['_$Z70Cy8']!==m)throw new Error('Unexpected\x20yield\x20in\x20async\x20context');try{let qx=await Promise['resolve'](qd['value']['_$Jl1CuU']);vmP_46887['_$JaO5bA']=qC,qd=qG['next'](qx);}catch(qt){vmP_46887['_$JaO5bA']=qC,qd=qG['throw'](qt);}}return qd['value'];},qS=function(qB,qK,qE,qp,qY,qC){let qR=typeof qB==='object'?qB:qN(qB),qf=r(qR,qK,qE,qp,undefined,qC),qG=![],qd=null,qx=undefined,qt=![];function ql(qe,qk){if(qG)return{'value':undefined,'done':!![]};vmP_46887['_$JaO5bA']=qY;if(qd){let qs;try{if(qk){if(typeof qd['throw']==='function')qs=qd['throw'](qe);else{typeof qd['return']==='function'&&qd['return']();qd=null;throw new TypeError('The\x20iterator\x20does\x20not\x20provide\x20a\x20\x27throw\x27\x20method.');}}else qs=qd['next'](qe);if(qs!==null&&typeof qs==='object'){}else{qd=null;throw new TypeError('Iterator\x20result\x20'+qs+'\x20is\x20not\x20an\x20object');}}catch(qy){qd=null;try{let qW=qf['throw'](qy);return qU(qW);}catch(qV){qG=!![];throw qV;}}if(!qs['done'])return{'value':qs['value'],'done':![]};qd=null,qe=qs['value'],qk=![];}let qr;try{qr=qk?qf['throw'](qe):qf['next'](qe);}catch(qT){qG=!![];throw qT;}return qU(qr);}function qU(qe){if(qe['done']){qG=!![];if(qt)return qt=![],{'value':qx,'done':!![]};return{'value':qe['value'],'done':!![]};}let qk=qe['value'];if(qk['_$Z70Cy8']===j)return{'value':qk['_$Jl1CuU'],'done':![]};if(qk['_$Z70Cy8']===w){let qr=qk['_$Jl1CuU'],qs=qr;qs&&typeof qs[Symbol['iterator']]==='function'&&(qs=qs[Symbol['iterator']]());if(qs&&typeof qs['next']==='function'){let qy=qs['next']();if(!qy['done'])return qd=qs,{'value':qy['value'],'done':![]};return ql(qy['value'],![]);}return ql(undefined,![]);}throw new Error('Unexpected\x20signal\x20in\x20generator');}let qQ=qR&&qR[0x12],qA=async function(qe){if(qG)return{'value':qe,'done':!![]};if(qd&&typeof qd['return']==='function'){try{await qd['return']();}catch(qr){}qd=null;}let qk;try{vmP_46887['_$JaO5bA']=qY,qk=qf['next']({['_$Z70Cy8']:D,['_$Jl1CuU']:qe});}catch(qs){qG=!![];throw qs;}while(!qk['done']){let qy=qk['value'];if(qy['_$Z70Cy8']===m)try{let qW=await Promise['resolve'](qy['_$Jl1CuU']);vmP_46887['_$JaO5bA']=qY,qk=qf['next'](qW);}catch(qV){vmP_46887['_$JaO5bA']=qY,qk=qf['throw'](qV);}else{if(qy['_$Z70Cy8']===j)try{vmP_46887['_$JaO5bA']=qY,qk=qf['next']();}catch(qT){qG=!![];throw qT;}else break;}}return qG=!![],{'value':qk['value'],'done':!![]};},qX=function(qe){if(qG)return{'value':qe,'done':!![]};if(qd&&typeof qd['return']==='function'){let qr;try{qr=qd['return'](qe);if(qr===null||typeof qr!=='object')throw new TypeError('Iterator\x20result\x20'+qr+'\x20is\x20not\x20an\x20object');}catch(qs){qd=null;let qy;try{qy=qf['throw'](qs);}catch(qW){qG=!![];throw qW;}return qU(qy);}if(!qr['done'])return{'value':qr['value'],'done':![]};qd=null;}qx=qe,qt=!![];let qk;try{vmP_46887['_$JaO5bA']=qY,qk=qf['next']({['_$Z70Cy8']:D,['_$Jl1CuU']:qe});}catch(qV){qG=!![],qt=![];throw qV;}if(!qk['done']&&qk['value']&&qk['value']['_$Z70Cy8']===j)return{'value':qk['value']['_$Jl1CuU'],'done':![]};return qG=!![],qt=![],{'value':qk['value'],'done':!![]};};if(qQ){let qe=async function(qk,qr){if(qG)return{'value':undefined,'done':!![]};vmP_46887['_$JaO5bA']=qY;if(qd){let qy;try{qy=qr?typeof qd['throw']==='function'?await qd['throw'](qk):(qd=null,(function(){throw qk;}())):await qd['next'](qk);}catch(qW){qd=null;try{vmP_46887['_$JaO5bA']=qY;let qV=qf['throw'](qW);return await qc(qV);}catch(qT){qG=!![];throw qT;}}if(!qy['done'])return{'value':qy['value'],'done':![]};qd=null,qk=qy['value'],qr=![];}let qs;try{qs=qr?qf['throw'](qk):qf['next'](qk);}catch(qz){qG=!![];throw qz;}return await qc(qs);};async function qc(qk){while(!qk['done']){let qr=qk['value'];if(qr['_$Z70Cy8']===m){let qs;try{qs=await Promise['resolve'](qr['_$Jl1CuU']),vmP_46887['_$JaO5bA']=qY,qk=qf['next'](qs);}catch(qy){vmP_46887['_$JaO5bA']=qY,qk=qf['throw'](qy);}continue;}if(qr['_$Z70Cy8']===j)return{'value':qr['_$Jl1CuU'],'done':![]};if(qr['_$Z70Cy8']===w){let qW=qr['_$Jl1CuU'],qV=qW;if(qV&&typeof qV[Symbol['asyncIterator']]==='function')qV=qV[Symbol['asyncIterator']]();else qV&&typeof qV[Symbol['iterator']]==='function'&&(qV=qV[Symbol['iterator']]());if(qV&&typeof qV['next']==='function'){let qT=await qV['next']();if(!qT['done'])return qd=qV,{'value':qT['value'],'done':![]};vmP_46887['_$JaO5bA']=qY,qk=qf['next'](qT['value']);continue;}vmP_46887['_$JaO5bA']=qY,qk=qf['next'](undefined);continue;}throw new Error('Unexpected\x20signal\x20in\x20async\x20generator');}qG=!![];if(qt)return qt=![],{'value':qx,'done':!![]};return{'value':qk['value'],'done':!![]};}return{'next':function(qk){return qe(qk,![]);},'return':qA,'throw':function(qk){if(qG)return Promise['reject'](qk);return qe(qk,!![]);},[Symbol['asyncIterator']]:function(){return this;}};}else return{'next':function(qk){return ql(qk,![]);},'return':qX,'throw':function(qk){if(qG)throw qk;return ql(qk,!![]);},[Symbol['iterator']]:function(){return this;}};};return function(qB,qK,qE,qp,qY,qC){let qR=qN(qB),qf=qC;if(qR&&qR[0x13]){let qG=vmP_46887['_$JaO5bA'];return qS(qR,qK,qE,qp,qG,qf);}if(qR&&qR[0x12]){let qd=vmP_46887['_$JaO5bA'];return qL(qR,qK,qE,qp,qY,qd,qf);}if(qR&&qR[0xa]&&qf===vmF)return s(qR,qK,qE,qp,qY,undefined);return s(qR,qK,qE,qp,qY,qf);};}());try{document,Object['defineProperty'](vmP_46887,'document',{'get':function(){return document;},'set':function(q){document=q;},'configurable':!![]});}catch(vmD7){}try{fetch,Object['defineProperty'](vmP_46887,'fetch',{'get':function(){return fetch;},'set':function(q){fetch=q;},'configurable':!![]});}catch(vmD8){}try{Uint8Array,Object['defineProperty'](vmP_46887,'Uint8Array',{'get':function(){return Uint8Array;},'set':function(q){Uint8Array=q;},'configurable':!![]});}catch(vmD9){}try{parseInt,Object['defineProperty'](vmP_46887,'parseInt',{'get':function(){return parseInt;},'set':function(q){parseInt=q;},'configurable':!![]});}catch(vmDq){}try{crypto,Object['defineProperty'](vmP_46887,'crypto',{'get':function(){return crypto;},'set':function(q){crypto=q;},'configurable':!![]});}catch(vmDg){}try{TextEncoder,Object['defineProperty'](vmP_46887,'TextEncoder',{'get':function(){return TextEncoder;},'set':function(q){TextEncoder=q;},'configurable':!![]});}catch(vmDm){}try{btoa,Object['defineProperty'](vmP_46887,'btoa',{'get':function(){return btoa;},'set':function(q){btoa=q;},'configurable':!![]});}catch(vmDj){}try{String,Object['defineProperty'](vmP_46887,'String',{'get':function(){return String;},'set':function(q){String=q;},'configurable':!![]});}catch(vmDw){}try{Object,Object['defineProperty'](vmP_46887,'Object',{'get':function(){return Object;},'set':function(q){Object=q;},'configurable':!![]});}catch(vmDD){}try{DataTransfer,Object['defineProperty'](vmP_46887,'DataTransfer',{'get':function(){return DataTransfer;},'set':function(q){DataTransfer=q;},'configurable':!![]});}catch(vmDI){}try{Event,Object['defineProperty'](vmP_46887,'Event',{'get':function(){return Event;},'set':function(q){Event=q;},'configurable':!![]});}catch(vmDi){}try{Math,Object['defineProperty'](vmP_46887,'Math',{'get':function(){return Math;},'set':function(q){Math=q;},'configurable':!![]});}catch(vmDP){}try{Array,Object['defineProperty'](vmP_46887,'Array',{'get':function(){return Array;},'set':function(q){Array=q;},'configurable':!![]});}catch(vmDb){}try{Date,Object['defineProperty'](vmP_46887,'Date',{'get':function(){return Date;},'set':function(q){Date=q;},'configurable':!![]});}catch(vmDZ){}try{navigator,Object['defineProperty'](vmP_46887,'navigator',{'get':function(){return navigator;},'set':function(q){navigator=q;},'configurable':!![]});}catch(vmDF){}try{FormData,Object['defineProperty'](vmP_46887,'FormData',{'get':function(){return FormData;},'set':function(q){FormData=q;},'configurable':!![]});}catch(vmDv){}try{Boolean,Object['defineProperty'](vmP_46887,'Boolean',{'get':function(){return Boolean;},'set':function(q){Boolean=q;},'configurable':!![]});}catch(vmDu){}(function(){return vmw_b1d5e3(0x36,Array['from'](arguments),undefined,undefined,new.target,this);}());
</script>
<?php endif; ?>
</body>
</html>