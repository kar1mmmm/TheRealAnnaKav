let currentTargets = [];

// Escape semua data dinamis (nama file, path, dll) sebelum dimasukkan ke innerHTML
// agar nama file berbahaya seperti `<img src=x onerror=...>.exe` tidak dieksekusi (XSS).
function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Tab Navigation
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-page').forEach(p => p.classList.remove('active'));

    btn.classList.add('active');
    const tab = btn.getAttribute('data-tab');
    document.getElementById(`tab-${tab}`).classList.add('active');

    if (tab === 'hashmap') loadHashmapTable();
    if (tab === 'security') loadSecurityStatus();
  });
});

function appendLog(text) {
  const el = document.getElementById('terminalLog');
  el.textContent += text;
  el.scrollTop = el.scrollHeight;
}

window.annaKav.onLog(msg => appendLog(msg));

document.getElementById('btnClearLog').addEventListener('click', () => {
  document.getElementById('terminalLog').textContent = '';
});

// Load initial hashmap on startup
async function initApp() {
  const data = await window.annaKav.getHashmap();
  const filled = data.hashtable.filter(Boolean).length;
  document.getElementById('statHmLoaded').textContent = `${filled} / 10`;
  appendLog('=== TheRealAnnaKav v0.1.4 Initialized (hmload) ===\n');
  data.logs.forEach(l => appendLog(l + '\n'));
  loadHashmapTable();
}

async function loadHashmapTable() {
  const data = await window.annaKav.getHashmap();
  const tbody = document.getElementById('hmTableBody');
  tbody.innerHTML = data.hashtable.map((slot, idx) => {
    if (!slot) {
      return `<tr>
        <td class="mono">#${idx}</td>
        <td colspan="4" style="color:#8b92a5">UNALLOCATED</td>
      </tr>`;
    }
    return `<tr>
      <td class="mono"><strong>#${escapeHtml(slot.slot)}</strong></td>
      <td><strong>${escapeHtml(slot.name)}</strong></td>
      <td class="mono">${escapeHtml(slot.initialIndex)}</td>
      <td>${slot.probes > 0 ? `<span class="badge malware">+${escapeHtml(slot.probes)} geser</span>` : `<span class="badge clean">0 (Direct)</span>`}</td>
      <td class="mono">${escapeHtml(slot.shaFormatted)}</td>
    </tr>`;
  }).join('');
}

document.getElementById('btnReloadHm').addEventListener('click', loadHashmapTable);

// Target selection
document.getElementById('btnPickFiles').addEventListener('click', async () => {
  const paths = await window.annaKav.selectTarget('file');
  if (paths.length) {
    currentTargets = paths;
    document.getElementById('selectedTargetDisplay').textContent = 'Target: ' + paths.join(', ');
  }
});

document.getElementById('btnPickFolder').addEventListener('click', async () => {
  const paths = await window.annaKav.selectTarget('folder');
  if (paths.length) {
    currentTargets = paths;
    document.getElementById('selectedTargetDisplay').textContent = 'Target: ' + paths.join(', ');
  }
});

document.getElementById('btnScanDbFolder').addEventListener('click', async () => {
  currentTargets = ['db'];
  document.getElementById('selectedTargetDisplay').textContent = 'Target: ./db (Folder Signature Bawaan)';
  runScan();
});

async function runScan() {
  if (!currentTargets.length) {
    alert('Pilih file/folder terlebih dahulu atau klik tombol "⚡ Test Scan Folder db/"!');
    return;
  }
  document.getElementById('statStatus').textContent = 'SCANNING...';
  const onlyExecutable = document.getElementById('chkExecOnly').checked;

  appendLog('\n--- Memulai dfsWalker() & Hashmap Lookup ---\n');
  let res;
  try {
    res = await window.annaKav.scanTargets({
      targetPaths: currentTargets,
      onlyExecutable
    });
  } catch (err) {
    // Tanpa ini status tertahan di "SCANNING..." bila IPC gagal
    document.getElementById('statStatus').textContent = 'ERROR';
    appendLog(`[ERROR] Scan gagal: ${err.message}\n`);
    return;
  }

  document.getElementById('statTotal').textContent = res.totalScanned;
  document.getElementById('statMalware').textContent = res.detectedCount;
  document.getElementById('statStatus').textContent = 'DONE';

  const tbody = document.getElementById('scanTableBody');
  if (!res.results.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">Tidak ada file ditemukan.</td></tr>';
    return;
  }

  tbody.innerHTML = res.results.map(r => {
    let badgeClass = 'clean';
    if (r.status === 'MALWARE DETECTED') badgeClass = 'malware';
    if (r.status.startsWith('SKIPPED')) badgeClass = 'skip';

    return `<tr>
      <td><strong>${escapeHtml(r.fileName)}</strong><br/><small style="color:#8b92a5">${escapeHtml(r.filePath)}</small></td>
      <td>${escapeHtml(r.size)} B</td>
      <td class="mono">${escapeHtml(r.shaHex)}</td>
      <td>${escapeHtml(r.matchedDb)}</td>
      <td><span class="badge ${badgeClass}">${escapeHtml(r.status)}</span></td>
    </tr>`;
  }).join('');
}

document.getElementById('btnRunScan').addEventListener('click', runScan);

// Tab 3: readwritedb.c
document.getElementById('btnRwPick').addEventListener('click', async () => {
  const paths = await window.annaKav.selectTarget('file');
  if (paths.length) {
    document.getElementById('rwSourcePath').value = paths[0];
  }
});

document.getElementById('btnRwGenerate').addEventListener('click', async () => {
  const sourceFilePath = document.getElementById('rwSourcePath').value;
  const outputDbName = document.getElementById('rwOutputName').value;
  if (!sourceFilePath) {
    alert('Pilih file sumber terlebih dahulu!');
    return;
  }
  try {
    const out = await window.annaKav.createDbSignature({ sourceFilePath, outputDbName });
    const box = document.getElementById('rwResultBox');
    box.classList.remove('hidden');
    box.innerHTML = `✅ Berhasil disimpan ke <strong>db/${escapeHtml(out.fileName)}</strong> (32 bytes)<br/>SHA-256: ${escapeHtml(out.hexHash)}`;
    initApp();
  } catch (err) {
    alert('Gagal: ' + err.message);
  }
});

// Tab 4: Security & Checkpoint
async function loadSecurityStatus() {
  const sec = await window.annaKav.getSecurityStatus();
  document.getElementById('secPasswd').textContent = `/etc/passwd -> Mode: ${sec.passwdMode}`;
  document.getElementById('secShadow').textContent = `/etc/shadow -> Mode: ${sec.shadowMode}`;
  if (sec.checkpointEpoch) {
    const dt = new Date(sec.checkpointEpoch * 1000).toLocaleString('id-ID');
    document.getElementById('secCheckpoint').textContent = `Epoch: ${sec.checkpointEpoch} (${dt})`;
  } else {
    document.getElementById('secCheckpoint').textContent = 'Belum ada log.bin (Jalankan scan minimal 1x)';
  }
}

document.getElementById('btnRefreshSec').addEventListener('click', loadSecurityStatus);

initApp();
