/* ===== Theme Toggle ===== */
function initTheme() {
  const saved = localStorage.getItem('jwt-theme');
  if (saved) {
    document.documentElement.setAttribute('data-theme', saved);
  } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('jwt-theme', next);
}

/* ===== Base64URL Encode/Decode ===== */
function b64urlDecode(str) {
  var base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) base64 += '=';
  return decodeURIComponent(atob(base64).split('').map(function(c) { return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2); }).join(''));
}

function b64urlEncode(str) {
  return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/* ===== JSON Syntax Highlighting ===== */
function formatJson(obj) {
  var json = JSON.stringify(obj, null, 2);
  return json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"([^"]+)"(?=\s*:)/g, '<span class="json-key">"$1"</span>')
    .replace(/:\s*"([^"]*)"/g, ': <span class="json-string">"$1"</span>')
    .replace(/:\s*(\d+)/g, ': <span class="json-number">$1</span>')
    .replace(/:\s*(true|false)/g, ': <span class="json-boolean">$1</span>')
    .replace(/:\s*(null)/g, ': <span class="json-null">$1</span>');
}

/* ===== Parse JWT ===== */
function parseJwt(token) {
  var parts = token.trim().split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT: must contain exactly 3 parts separated by dots');
  var header, payload;
  try { header = JSON.parse(b64urlDecode(parts[0])); } catch (e) { throw new Error('Cannot decode JWT header — not valid Base64URL'); }
  try { payload = JSON.parse(b64urlDecode(parts[1])); } catch (e) { throw new Error('Cannot decode JWT payload — not valid Base64URL'); }
  return { header, payload, signature: parts[2], raw: { header: parts[0], payload: parts[1], signature: parts[2] } };
}

/* ===== Analyze Header ===== */
function analyzeHeader(header) {
  var findings = [];
  if (!header.alg) findings.push({ type: 'error', label: 'Missing Algorithm', detail: 'No "alg" claim found in the header' });
  else if (header.alg === 'none') findings.push({ type: 'error', label: 'Critical: "none" Algorithm', detail: 'This token uses the "none" algorithm — no signature is required, meaning anyone can forge it' });
  else if (header.alg === 'HS256') findings.push({ type: 'success', label: 'Algorithm: HS256', detail: 'HMAC using SHA-256 — can be verified with a shared secret' });
  else if (header.alg && header.alg.indexOf('HS') === 0) findings.push({ type: 'info', label: 'Algorithm: ' + header.alg, detail: 'HMAC variant — this tool only verifies HS256' });
  else if (header.alg) findings.push({ type: 'warning', label: 'Algorithm: ' + header.alg, detail: 'Asymmetric algorithm — this tool only supports HS256 signature verification' });
  
  if (header.typ) findings.push({ type: 'info', label: 'Type', detail: header.typ });
  if (header.kid) findings.push({ type: 'info', label: 'Key ID', detail: header.kid });
  
  // ADVANCED: JKU Header Injection check
  if (header.jku) findings.push({ type: 'error', label: 'Critical: "jku" Header Detected', detail: '"jku" (JWK Set URL) allows the token to specify its own key location. This is highly vulnerable to injection attacks.' });

  return findings;
}

/* ===== Analyze Payload Claims ===== */
function analyzeClaims(payload) {
  var findings = [];
  var now = Math.floor(Date.now() / 1000);

  if (payload.exp !== undefined) {
    if (payload.exp < now) {
      var expiredAgo = now - payload.exp; var unit, value;
      if (expiredAgo > 86400) { unit = 'days'; value = Math.floor(expiredAgo / 86400); } else if (expiredAgo > 3600) { unit = 'hours'; value = Math.floor(expiredAgo / 3600); } else { unit = 'minutes'; value = Math.floor(expiredAgo / 60); }
      findings.push({ type: 'error', label: 'Token Expired', detail: 'Expired ' + value + ' ' + unit + ' ago (' + new Date(payload.exp * 1000).toLocaleString() + ')' });
    } else {
      var remaining = payload.exp - now; var rUnit, rValue;
      if (remaining > 86400) { rUnit = 'days'; rValue = Math.floor(remaining / 86400); } else if (remaining > 3600) { rUnit = 'hours'; rValue = Math.floor(remaining / 3600); } else { rUnit = 'minutes'; rValue = Math.floor(remaining / 60); }
      findings.push({ type: 'success', label: 'Not Expired', detail: 'Expires in ' + rValue + ' ' + rUnit + ' (' + new Date(payload.exp * 1000).toLocaleString() + ')' });
    }
  } else {
    findings.push({ type: 'warning', label: 'No Expiration', detail: 'No "exp" claim — this token will never expire' });
  }

  if (payload.iat !== undefined) {
    findings.push({ type: 'info', label: 'Issued At', detail: new Date(payload.iat * 1000).toLocaleString() + ' (timestamp: ' + payload.iat + ')' });
    if (payload.iat > now + 60) findings.push({ type: 'error', label: 'Future "iat"', detail: '"iat" is set in the future — possible clock skew or tampering' });
  }
  if (payload.nbf !== undefined) {
    if (payload.nbf > now) findings.push({ type: 'warning', label: 'Not Yet Valid', detail: '"nbf" claim is in the future — token should not be accepted yet' });
    else findings.push({ type: 'info', label: 'Not Before', detail: new Date(payload.nbf * 1000).toLocaleString() });
  }

  if (payload.iss !== undefined) findings.push({ type: 'info', label: 'Issuer (iss)', detail: String(payload.iss) });
  if (payload.sub !== undefined) findings.push({ type: 'info', label: 'Subject (sub)', detail: String(payload.sub) });
  if (payload.aud !== undefined) findings.push({ type: 'info', label: 'Audience (aud)', detail: Array.isArray(payload.aud) ? payload.aud.join(', ') : String(payload.aud) });
  if (payload.jti !== undefined) findings.push({ type: 'info', label: 'JWT ID (jti)', detail: String(payload.jti) });

  var sensitiveKeys = ['password', 'secret', 'api_key', 'apikey', 'private', 'credit', 'ssn'];
  var foundSensitive = Object.keys(payload).filter(function(k) { return sensitiveKeys.some(function(s) { return k.toLowerCase().indexOf(s) !== -1; }); });
  if (foundSensitive.length > 0) findings.push({ type: 'warning', label: 'Sensitive Data Detected', detail: 'Payload contains fields that look sensitive: ' + foundSensitive.join(', ') });

  return findings;
}

/* ===== Render Timeline Graph ===== */
function renderTimeline(payload) {
  var panel = document.getElementById('timeline-panel');
  var iat = payload.iat || payload.nbf;
  var exp = payload.exp;
  
  if (!iat || !exp) {
    panel.style.display = 'none';
    return;
  }

  panel.style.display = 'block';
  var now = Math.floor(Date.now() / 1000);
  var totalDuration = exp - iat;
  
  if (totalDuration <= 0) {
     panel.style.display = 'none';
     return;
  }

  var activeWidth = ((now - iat) / totalDuration) * 100;
  activeWidth = Math.max(0, Math.min(100, activeWidth));

  var activeBar = document.getElementById('timeline-active');
  var nowMarker = document.getElementById('timeline-now');
  
  activeBar.style.width = activeWidth + '%';
  nowMarker.style.left = activeWidth + '%';

  if (now > exp) {
    activeBar.classList.add('expired');
  } else {
    activeBar.classList.remove('expired');
  }

  document.getElementById('timeline-start').textContent = new Date(iat * 1000).toLocaleTimeString();
  document.getElementById('timeline-end').textContent = new Date(exp * 1000).toLocaleTimeString();
}

/* ===== Render Metrics ===== */
function renderMetrics(raw) {
  // Calculate byte size (Base64 encodes 3 bytes to 4 chars, so length * 0.75 is approximate bytes, + overhead)
  var hBytes = Math.ceil(raw.header.length * 0.75);
  var pBytes = Math.ceil(raw.payload.length * 0.75);
  var sBytes = Math.ceil(raw.signature.length * 0.75);
  var totalBytes = hBytes + pBytes + sBytes + 2; // +2 for the dots

  document.getElementById('met-header').textContent = hBytes + ' B';
  document.getElementById('met-payload').textContent = pBytes + ' B';
  document.getElementById('met-signature').textContent = sBytes + ' B';
  
  var totalEl = document.getElementById('met-total');
  totalEl.textContent = totalBytes + ' B';
  
  // Warn if > 4096 bytes (standard cookie limit)
  if (totalBytes > 4096) {
    totalEl.style.color = 'var(--error)';
    totalEl.textContent = totalBytes + ' B (Too large for cookies!)';
  } else {
    totalEl.style.color = '';
  }
}

/* ===== Toast & Clipboard ===== */
function showToast(message, type) {
  type = type || 'info';
  var container = document.getElementById('toast-container');
  var toast = document.createElement('div');
  toast.className = 'toast toast-' + type;
  toast.textContent = message;
  container.appendChild(toast);
  requestAnimationFrame(function() { toast.classList.add('show'); });
  setTimeout(function() { toast.classList.remove('show'); setTimeout(function() { toast.remove(); }, 300); }, 3000);
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(function() {
    var original = btn.textContent; btn.textContent = 'Copied!'; btn.classList.add('copied');
    setTimeout(function() { btn.textContent = original; btn.classList.remove('copied'); }, 2000);
  }).catch(function() { showToast('Failed to copy', 'error'); });
}

/* ===== Signature Verification ===== */
function verifySignature(token, secret) {
  return fetch('/.netlify/functions/verify-jwt', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: token, secret: secret })
  }).then(function(r) { return r.json(); }).catch(function() { return { valid: false, error: 'Network error' }; });
}

/* ===== Main Decode Logic ===== */
var decodeTimeout = null;
function handleInput() {
  clearTimeout(decodeTimeout);
  decodeTimeout = setTimeout(function() {
    var token = document.getElementById('jwt-input').value.trim();
    var resultsSection = document.getElementById('results');
    var verifyPanel = document.getElementById('verify-panel');
    var tokenStructure = document.getElementById('token-structure');
    var encodedOutput = document.getElementById('encoded-output');

    if (!token) {
      resultsSection.style.display = 'none';
      tokenStructure.classList.remove('visible');
      return;
    }

    try {
      var parsed = parseJwt(token);
      resultsSection.style.display = 'block';
      encodedOutput.style.display = 'none';

      // Metrics Graph
      renderMetrics(parsed.raw);

      // Structure Bar
      tokenStructure.classList.add('visible');
      document.getElementById('struct-header').textContent = parsed.raw.header;
      document.getElementById('struct-payload').textContent = parsed.raw.payload;
      document.getElementById('struct-signature').textContent = parsed.raw.signature;

      // Panels
      document.getElementById('header-json').innerHTML = formatJson(parsed.header);
      document.getElementById('header-raw').textContent = parsed.raw.header;
      document.getElementById('payload-json').innerHTML = formatJson(parsed.payload);
      document.getElementById('payload-raw').textContent = parsed.raw.payload;
      document.getElementById('signature-value').textContent = parsed.raw.signature;
      document.getElementById('signature-length').textContent = parsed.raw.signature.length + ' characters';

      // Graphs
      renderTimeline(parsed.payload);

      // Analysis
      var allFindings = analyzeHeader(parsed.header).concat(analyzeClaims(parsed.payload));
      document.getElementById('analysis-content').innerHTML = allFindings.map(function(f) {
        var icon = f.type === 'error' ? '\u2715' : f.type === 'warning' ? '\u26A0' : f.type === 'success' ? '\u2713' : '\u2139';
        return '<div class="finding finding-' + f.type + '"><span class="finding-icon">' + icon + '</span><span class="finding-label">' + f.label + '</span><span class="finding-detail">' + f.detail + '</span></div>';
      }).join('');

      // Verify Panel
      if (parsed.header.alg === 'HS256') {
        verifyPanel.style.display = 'block';
        document.getElementById('verify-result').innerHTML = '';
        document.getElementById('verify-btn').disabled = false;
        document.getElementById('verify-btn').textContent = 'Verify Signature';
      } else {
        verifyPanel.style.display = 'none';
      }

    } catch (err) {
      resultsSection.style.display = 'block';
      tokenStructure.classList.remove('visible');
      document.getElementById('timeline-panel').style.display = 'none';
      document.getElementById('encoded-output').style.display = 'none';
      document.getElementById('header-json').innerHTML = '';
      document.getElementById('payload-json').innerHTML = '';
      document.getElementById('signature-value').textContent = '';
      document.getElementById('analysis-content').innerHTML = '<div class="finding finding-error"><span class="finding-icon">\u2715</span><span class="finding-label">Decode Error</span><span class="finding-detail">' + err.message + '</span></div>';
      verifyPanel.style.display = 'none';
    }
  }, 200);
}

/* ===== Encoder Logic ===== */
function handleEncode() {
  try {
    var headerEl = document.getElementById('header-json');
    var payloadEl = document.getElementById('payload-json');
    
    // Extract plain text from HTML highlighted elements
    var headerStr = headerEl.innerText || headerEl.textContent;
    var payloadStr = payloadEl.innerText || payloadEl.textContent;
    
    var headerObj = JSON.parse(headerStr);
    var payloadObj = JSON.parse(payloadStr);

    var encodedHeader = b64urlEncode(JSON.stringify(headerObj));
    var encodedPayload = b64urlEncode(JSON.stringify(payloadObj));
    
    // Generate unsigned token (signature is empty)
    var newToken = encodedHeader + '.' + encodedPayload + '.';

    document.getElementById('encoded-value').textContent = newToken;
    document.getElementById('encoded-output').style.display = 'block';
    showToast('Token generated successfully (Unsigned)', 'success');
  } catch (e) {
    showToast('Invalid JSON: Cannot encode. Fix syntax errors in the payload panel.', 'error');
  }
}

/* ===== Initialize Everything ===== */
document.addEventListener('DOMContentLoaded', function() {
  initTheme();

  document.getElementById('theme-toggle').addEventListener('click', toggleTheme);
  document.getElementById('theme-toggle').addEventListener('keydown', function(e) { if(e.key === 'Enter' || e.key === ' ') toggleTheme(); });

  document.getElementById('jwt-input').addEventListener('input', handleInput);
  document.getElementById('verify-btn').addEventListener('click', function() {
    var token = document.getElementById('jwt-input').value.trim();
    var secret = document.getElementById('secret-input').value;
    var resultDiv = document.getElementById('verify-result');
    var btn = document.getElementById('verify-btn');
    if (!secret) { showToast('Enter a secret key', 'warning'); return; }
    btn.disabled = true; btn.textContent = 'Verifying...';
    resultDiv.innerHTML = '<div class="verify-loading" style="color:var(--text-muted);font-size:13px">Verifying...</div>';
    verifySignature(token, secret).then(function(result) {
      resultDiv.innerHTML = result.valid ? 
        '<div class="verify-result verify-valid"><span class="verify-icon">\u2713</span><div><strong>Signature Valid</strong><p>Matches secret using HS256.</p></div></div>' : 
        '<div class="verify-result verify-invalid"><span class="verify-icon">\u2715</span><div><strong>Signature Invalid</strong><p>' + (result.error || 'Does not match secret.') + '</p></div></div>';
      btn.disabled = false; btn.textContent = 'Verify Signature';
    });
  });

  document.getElementById('secret-input').addEventListener('keydown', function(e) { if (e.key === 'Enter') document.getElementById('verify-btn').click(); });
  
  document.getElementById('copy-header').addEventListener('click', function() { var r = document.getElementById('header-raw').textContent; if(r) copyToClipboard(r, this); });
  document.getElementById('copy-payload').addEventListener('click', function() { var r = document.getElementById('payload-raw').textContent; if(r) copyToClipboard(r, this); });
  document.getElementById('copy-signature').addEventListener('click', function() { var r = document.getElementById('signature-value').textContent; if(r) copyToClipboard(r, this); });
  document.getElementById('copy-header-json').addEventListener('click', function() { var el = document.getElementById('header-json'); if(el.textContent) copyToClipboard(el.textContent, this); });
  document.getElementById('copy-payload-json').addEventListener('click', function() { var el = document.getElementById('payload-json'); if(el.textContent) copyToClipboard(el.textContent, this); });
  document.getElementById('copy-encoded').addEventListener('click', function() { var el = document.getElementById('encoded-value'); if(el.textContent) copyToClipboard(el.textContent, this); });

  document.getElementById('clear-btn').addEventListener('click', function() {
    document.getElementById('jwt-input').value = '';
    document.getElementById('results').style.display = 'none';
    document.getElementById('token-structure').classList.remove('visible');
    document.getElementById('jwt-input').focus();
  });

  document.getElementById('paste-btn').addEventListener('click', function() {
    navigator.clipboard.readText().then(function(text) {
      document.getElementById('jwt-input').value = text; handleInput(); showToast('Pasted from clipboard', 'success');
    }).catch(function() { showToast('Cannot read clipboard', 'warning'); });
  });

  document.getElementById('sample-btn').addEventListener('click', function() {
    document.getElementById('jwt-input').value = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    handleInput(); showToast('Sample loaded. Secret: your-256-bit-secret', 'info');
  });

  document.getElementById('toggle-secret-btn').addEventListener('click', function() {
    var input = document.getElementById('secret-input'); var btn = document.getElementById('toggle-secret-btn');
    if (input.type === 'password') { input.type = 'text'; btn.textContent = 'Hide'; } else { input.type = 'password'; btn.textContent = 'Show'; }
  });

  document.getElementById('encode-btn').addEventListener('click', handleEncode);
});
