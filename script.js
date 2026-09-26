// Background particle network animation
(() => {
  const canvas = document.getElementById('bgParticles');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const LINK_DIST = 130;
  let w = 0, h = 0, dpr = 1, particles = [], raf = 0, running = false;
  const mouse = { x: -9999, y: -9999 };

  function size() {
    w = window.innerWidth;
    h = window.innerHeight;
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const count = Math.min(110, Math.max(30, Math.round((w * h) / 15000)));
    particles = Array.from({ length: count }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.5 + 0.8,
    }));
  }

  function frame() {
    ctx.clearRect(0, 0, w, h);

    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > w) p.vx *= -1;
      if (p.y < 0 || p.y > h) p.vy *= -1;
      const dx = mouse.x - p.x, dy = mouse.y - p.y, d2 = dx * dx + dy * dy;
      if (d2 < 24000 && d2 > 1) {
        p.x += dx / d2 * 18;
        p.y += dy / d2 * 18;
      }
    }

    ctx.beginPath();
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const d2 = dx * dx + dy * dy;
        if (d2 < LINK_DIST * LINK_DIST) {
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
        }
      }
    }
    ctx.strokeStyle = 'rgba(139, 92, 246, 0.16)';
    ctx.lineWidth = 1;
    ctx.stroke();

    ctx.fillStyle = 'rgba(34, 211, 238, 0.55)';
    for (const p of particles) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();
    }

    if (running) raf = requestAnimationFrame(frame);
  }

  function start() { if (!running && !reduceMotion) { running = true; raf = requestAnimationFrame(frame); } }
  function stop() { running = false; cancelAnimationFrame(raf); }

  size();
  if (reduceMotion) {
    frame(); // draw one static frame, no loop
  } else {
    start();
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) stop(); else start();
    });
  }

  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { size(); if (reduceMotion) frame(); }, 160);
  });

  window.addEventListener('pointermove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  }, { passive: true });

  window.addEventListener('pointerleave', () => { mouse.x = mouse.y = -9999; });
})();

// ============================================================
// API & UI logic
// const API_BASE = 'http://127.0.0.1:8001';
const API_BASE = 'https://url-security-checker-production.up.railway.app';

// Category-level representation of the real backend checks, used only
// to pace the radar's progress percentage and cycle the status text.
const CHECK_SEQUENCE = [
  'URL length', "'@' symbol check", 'IP address as domain', 'Suspicious TLD',
  'Redirect chain', 'HTTPS enforced', 'SSL certificate validity', 'TLS version',
  'HSTS header', 'URL shortener check', 'Domain age', 'Google Safe Browsing',
  'URLhaus malware database', 'Certificate transparency', 'ML phishing classifier',
  'Security headers', 'Cookie flags', 'Mixed content', 'Server disclosure',
  'Exposed sensitive files',
];

const STATUS_PHASES = [
  { upTo: 3, text: 'Reading the URL & structure…' },
  { upTo: 8, text: 'Verifying encryption & certificates…' },
  { upTo: 13, text: 'Cross-referencing threat intel…' },
  { upTo: 14, text: 'Running the ML phishing model…' },
  { upTo: 19, text: 'Auditing headers, cookies & content…' },
];

const scanForm = document.getElementById('scanForm');
const urlInput = document.getElementById('urlInput');
const scanButton = document.getElementById('scanButton');
const statusLine = document.getElementById('statusLine');
const report = document.getElementById('report');
const scanProgress = document.getElementById('scanProgress');
const scanTargetUrl = document.getElementById('scanTargetUrl');
const scanStatusText = document.getElementById('scanStatusText');
const scanPercent = document.getElementById('scanPercent');
const radarFill = document.getElementById('radarFill');
const scanTimer = document.getElementById('scanTimer');
const ledgerTable = document.getElementById('ledgerTable');
const gaugeFill = document.getElementById('gaugeFill');

const GAUGE_CIRCUMFERENCE = 326.7256; // 2 * PI * r(52) — final score gauge
const RADAR_CIRCUMFERENCE = 402.1239; // 2 * PI * r(64) — in-progress radar ring
const RADAR_CAP = 92; // never claim 100% before real data arrives

let scanStepTimeout = null;
let scanTimerInterval = null;

function classificationClass(classification) {
  if (classification === 'Safe') return 'safe';
  if (classification === 'Suspicious') return 'suspicious';
  return 'risk';
}

function setRadarProgress(percent) {
  const offset = RADAR_CIRCUMFERENCE - (RADAR_CIRCUMFERENCE * percent) / 100;
  radarFill.style.strokeDashoffset = String(offset);
  scanPercent.textContent = `${Math.round(percent)}%`;
}

function updateStatusText(stepIndex) {
  const phase = STATUS_PHASES.find((p) => stepIndex <= p.upTo);
  if (phase) scanStatusText.textContent = phase.text;
}

function startScanAnimation(url) {
  scanTargetUrl.textContent = url;
  scanStatusText.textContent = 'Booting scanner…';
  setRadarProgress(0);

  const startTime = Date.now();
  let stepIndex = 0;
  updateStatusText(0);

  const scheduleNext = () => {
    const delay = 380 + Math.random() * 380;
    scanStepTimeout = setTimeout(() => {
      stepIndex += 1;
      const percent = Math.min(RADAR_CAP, Math.round((stepIndex / CHECK_SEQUENCE.length) * 100));
      setRadarProgress(percent);
      if (stepIndex < CHECK_SEQUENCE.length && percent < RADAR_CAP) {
        updateStatusText(stepIndex);
        scheduleNext();
      }
    }, delay);
  };
  scheduleNext();

  scanTimer.textContent = '0.0s elapsed';
  scanTimerInterval = setInterval(() => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    scanTimer.textContent = `${elapsed}s elapsed`;
  }, 100);
}

function stopScanAnimation() {
  clearTimeout(scanStepTimeout);
  clearInterval(scanTimerInterval);
  scanStepTimeout = null;
  scanTimerInterval = null;
}

function finishScanAnimation(callback) {
  stopScanAnimation();
  scanStatusText.textContent = 'Done.';
  setRadarProgress(100);
  setTimeout(callback, 350);
}

function animateGauge(score, cls) {
  gaugeFill.classList.remove('safe', 'suspicious', 'risk');
  gaugeFill.classList.add(cls);
  gaugeFill.style.transition = 'none';
  gaugeFill.style.strokeDashoffset = String(GAUGE_CIRCUMFERENCE);
  void gaugeFill.getBoundingClientRect();
  gaugeFill.style.transition = '';
  const offset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE * score) / 100;
  requestAnimationFrame(() => { gaugeFill.style.strokeDashoffset = String(offset); });
}

function renderReport(data, { celebrate } = { celebrate: false }) {
  document.getElementById('submittedUrl').textContent = data.submitted_url;
  document.getElementById('finalUrl').textContent = data.final_url;
  document.getElementById('gradeLetter').textContent = data.grade;
  document.getElementById('gradeScore').textContent = `${data.score}/100`;
  document.getElementById('checksMeta').textContent = `${data.checks_performed} checks run`;

  const cls = classificationClass(data.classification);
  const badge = document.getElementById('classificationBadge');
  badge.className = 'verdict-badge ' + cls;
  badge.textContent = data.classification;

  animateGauge(data.score, cls);

  const list = document.getElementById('findingsList');
  list.innerHTML = '';
  data.findings.forEach((f) => {
    const li = document.createElement('li');
    li.className = f.passed ? 'pass' : 'fail';

    const mark = document.createElement('span');
    mark.className = 'mark';
    mark.textContent = f.passed ? '\u2713' : '\u2715';

    const body = document.createElement('span');
    const checkName = document.createElement('span');
    checkName.className = 'check-name';
    checkName.textContent = f.check;

    const impact = document.createElement('span');
    impact.className = 'impact';
    impact.textContent = `${f.impact > 0 ? '+' : ''}${f.impact}`;

    const detail = document.createElement('span');
    detail.className = 'detail';
    detail.textContent = f.detail;

    body.appendChild(checkName);
    body.appendChild(impact);
    body.appendChild(document.createElement('br'));
    body.appendChild(detail);

    li.appendChild(mark);
    li.appendChild(body);
    list.appendChild(li);
  });

  report.classList.toggle('just-scored', Boolean(celebrate));
  report.classList.add('visible');
}

async function runScan(url) {
  statusLine.textContent = '';
  statusLine.classList.remove('error');
  report.classList.remove('visible');
  scanButton.disabled = true;
  scanButton.textContent = 'Scanning…';
  scanProgress.classList.add('visible');
  startScanAnimation(url);

  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Request failed (${res.status})`);
    }

    const data = await res.json();

    finishScanAnimation(() => {
      scanProgress.classList.remove('visible');
      renderReport(data, { celebrate: true });
    });

    loadHistory();
  } catch (e) {
    stopScanAnimation();
    scanProgress.classList.remove('visible');
    statusLine.textContent = `Scan failed: ${e.message}. Is the backend running at ${API_BASE}?`;
    statusLine.classList.add('error');
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = 'Scan it';
  }
}

async function loadReportById(id) {
  statusLine.textContent = '';
  statusLine.classList.remove('error');
  try {
    const res = await fetch(`${API_BASE}/report/${id}`);
    if (!res.ok) throw new Error(`Report not found (${res.status})`);
    const data = await res.json();
    renderReport(data, { celebrate: true });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } catch (e) {
    statusLine.textContent = `Could not load report: ${e.message}`;
    statusLine.classList.add('error');
  }
}

function formatDate(iso) {
  const d = new Date(iso);
  return (
    d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
    ', ' +
    d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  );
}

async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/history?limit=20`);
    if (!res.ok) throw new Error('History unavailable');
    const scans = await res.json();

    if (!scans.length) {
      ledgerTable.innerHTML = '<div class="ledger-empty">No scans yet — paste a link above to get started.</div>';
      return;
    }

    ledgerTable.innerHTML = '';
    scans.forEach((scan) => {
      const cls = classificationClass(scan.classification);
      const row = document.createElement('div');
      row.className = 'ledger-row';
      row.tabIndex = 0;

      const urlCell = document.createElement('span');
      urlCell.className = 'url-cell';
      urlCell.textContent = scan.submitted_url;

      const gradeCell = document.createElement('span');
      gradeCell.className = `grade-cell ${cls}`;
      gradeCell.textContent = scan.grade;

      const dateCell = document.createElement('span');
      dateCell.className = 'date-cell';
      dateCell.textContent = formatDate(scan.scanned_at);

      row.appendChild(urlCell);
      row.appendChild(gradeCell);
      row.appendChild(dateCell);
      row.addEventListener('click', () => loadReportById(scan.id));
      row.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          loadReportById(scan.id);
        }
      });
      ledgerTable.appendChild(row);
    });
  } catch (e) {
    ledgerTable.innerHTML = `<div class="ledger-empty">Could not reach the backend at ${API_BASE}.</div>`;
  }
}

scanForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (url) runScan(url);
});

loadHistory();
