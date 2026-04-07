<?php
define('CF_SECRET', 'CF Cloudflare');
define('CF_SITEKEY', 'SITE KEY Cloudflare');
define('TOKEN_TTL',  1200);

session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['cf-turnstile-response'] ?? '';

    if ($token === '') {
        $error = 'Missing verification token.';
    } else {
        $data = ['secret' => CF_SECRET, 'response' => $token, 'remoteip' => $_SERVER['REMOTE_ADDR']];
        $opts = ['http' => ['header' => 'Content-type: application/x-www-form-urlencoded', 'method' => 'POST', 'content' => http_build_query($data)]];
        $ctx  = stream_context_create($opts);
        $raw  = @file_get_contents('https://challenges.cloudflare.com/turnstile/v0/siteverify', false, $ctx);
        $resp = $raw ? json_decode($raw, true) : null;

        if ($resp && isset($resp['success']) && $resp['success'] === true) {
            $_SESSION['cf_verified']    = true;
            $_SESSION['cf_verified_at'] = time();
            session_write_close();
            header('Location: index.php');
            exit;
        }

        $error = 'Verification failed. Please try again.';
    }
}

$verified   = $_SESSION['cf_verified']   ?? false;
$verifiedAt = $_SESSION['cf_verified_at'] ?? 0;

if ($verified && (time() - $verifiedAt) <= TOKEN_TTL) {
    session_write_close();
    header('Location: index.php');
    exit;
}

$sitekey = CF_SITEKEY;
$errorMsg = $error ?? '';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>© 2026 Infobrains. All rights reserved.</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
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
.main-content { flex: 1; padding: 40px 20px; display: flex; align-items: center; justify-content: center; }
.verify-container {
  width: 100%; max-width: 480px;
  background: var(--surface);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-card);
  overflow: hidden;
}
.verify-header {
  display: flex; align-items: center; gap: 18px;
  padding: 28px 36px;
  background: linear-gradient(135deg, var(--surface-2) 0%, rgba(29,37,53,0.6) 100%);
  border-bottom: 1px solid var(--border);
}
.verify-header-icon {
  width: 48px; height: 48px; flex-shrink: 0;
  border-radius: var(--radius);
  background: var(--accent-dim);
  border: 1px solid rgba(91,141,238,0.25);
  display: flex; align-items: center; justify-content: center;
  color: var(--accent);
}
.verify-header-icon svg { width: 24px; height: 24px; }
.verify-header h1 { font-size: 1.3rem; font-weight: 700; color: var(--text-1); line-height: 1.2; }
.verify-header p { font-size: 0.825rem; color: var(--text-2); margin-top: 3px; }
.verify-body { padding: 40px 36px; display: flex; flex-direction: column; align-items: center; }
.spinner-wrap {
  position: relative; width: 88px; height: 88px;
  margin-bottom: 32px;
}
.spinner-wrap svg { position: absolute; inset: 0; }
.spin-track { animation: none; }
.spin-arc {
  stroke-dasharray: 180 220;
  stroke-dashoffset: 0;
  stroke-linecap: round;
  animation: arc-spin 1.4s cubic-bezier(0.4,0,0.2,1) infinite;
  transform-origin: center;
}
.spin-arc-2 {
  stroke-dasharray: 80 320;
  stroke-dashoffset: -60;
  stroke-linecap: round;
  animation: arc-spin 1.4s cubic-bezier(0.4,0,0.2,1) infinite reverse;
  opacity: 0.35;
  transform-origin: center;
}
.spin-dot {
  animation: dot-pulse 1.4s ease-in-out infinite;
}
@keyframes arc-spin {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}
@keyframes dot-pulse {
  0%,100% { opacity: 0.3; transform: scale(0.85); }
  50%      { opacity: 1;   transform: scale(1.1); }
}
.glow-ring {
  position: absolute; inset: -8px;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(91,141,238,0.18) 0%, transparent 70%);
  animation: glow-pulse 1.4s ease-in-out infinite;
}
@keyframes glow-pulse {
  0%,100% { opacity: 0.5; transform: scale(0.95); }
  50%      { opacity: 1;   transform: scale(1.05); }
}
.wait-label {
  font-size: 1.15rem; font-weight: 700; color: var(--text-1);
  margin-bottom: 6px; letter-spacing: -0.01em;
}
.wait-dots::after {
  content: '';
  animation: dots 1.6s steps(4, end) infinite;
}
@keyframes dots {
  0%  { content: ''; }
  25% { content: '.'; }
  50% { content: '..'; }
  75% { content: '...'; }
}
.wait-sub {
  font-size: 0.82rem; color: var(--text-3); margin-bottom: 36px;
}
.error-notice {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 12px 16px; margin-bottom: 24px; width: 100%;
  background: var(--error-dim);
  border: 1px solid rgba(241,107,107,0.25);
  border-radius: var(--radius);
  font-size: 0.85rem; color: var(--error); line-height: 1.5;
}
.error-notice svg { width: 16px; height: 16px; flex-shrink: 0; margin-top: 1px; }
.captcha-wrap { display: flex; justify-content: center; }
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
@media (max-width: 520px) {
  .verify-header { padding: 22px 20px; flex-direction: column; align-items: flex-start; gap: 14px; }
  .verify-body { padding: 24px 20px; }
  .footer-inner { flex-direction: column; text-align: center; }
}
  </style>
</head>
<body>

<div class="bg-grid" aria-hidden="true"></div>
<div class="bg-glow" aria-hidden="true"></div>

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
    <div class="verify-container">

      <div class="verify-header">
        <div class="verify-header-icon">
          <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/><path d="M12 7v5l3 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </div>
        <div>
          <h1>Waiting to Verificate</h1>
          <p>Checking your access&hellip;</p>
        </div>
      </div>

      <div class="verify-body">

        <div class="spinner-wrap">
          <div class="glow-ring"></div>
          <svg viewBox="0 0 88 88" fill="none" xmlns="http://www.w3.org/2000/svg" width="88" height="88">
            <circle class="spin-track" cx="44" cy="44" r="36" stroke="rgba(91,141,238,0.1)" stroke-width="5"/>
            <circle class="spin-arc" cx="44" cy="44" r="36" stroke="url(#arcGrad)" stroke-width="5" fill="none"/>
            <circle class="spin-arc-2" cx="44" cy="44" r="36" stroke="#5b8dee" stroke-width="3" fill="none"/>
            <circle class="spin-dot" cx="44" cy="44" r="7" fill="rgba(91,141,238,0.15)" stroke="#5b8dee" stroke-width="1.5"/>
            <defs>
              <linearGradient id="arcGrad" x1="44" y1="8" x2="80" y2="80" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stop-color="#5b8dee"/>
                <stop offset="100%" stop-color="#3a6fdb" stop-opacity="0.2"/>
              </linearGradient>
            </defs>
          </svg>
        </div>

        <p class="wait-label wait-dots">Waiting to Verificate</p>
        <p class="wait-sub">This will complete automatically</p>

        <?php if ($errorMsg !== ''): ?>
        <div class="error-notice">
          <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.8"/><path d="M15 9l-6 6M9 9l6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
          <?php echo htmlspecialchars($errorMsg); ?>
        </div>
        <?php endif; ?>

        <form id="verifyForm" action="verify.php" method="POST">
          <div class="captcha-wrap">
            <div class="cf-turnstile"
                 data-sitekey="<?php echo htmlspecialchars($sitekey); ?>"
                 data-theme="dark"
                 data-callback="onVerified">
            </div>
          </div>
        </form>

      </div>
    </div>
  </main>

  <footer class="site-footer">
    <div class="footer-inner">
      <span class="footer-brand">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
        Science Day 2026 &mdash; Chlef University
      </span>
      <span class="footer-contact">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" stroke="currentColor" stroke-width="1.8"/><path d="M22 6l-10 7L2 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
        <a href="mailto:infobrains.uhbc@gmail.com">infobrains.uhbc@gmail.com</a>
      </span>
    </div>
  </footer>

</div>

<script>
function onVerified(token) {
  document.getElementById('verifyForm').submit();
}
</script>
</body>
</html>