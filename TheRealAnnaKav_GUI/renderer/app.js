let currentTargets = [];

// Escape semua data dinamis sebelum dimasukkan ke innerHTML (mencegah XSS)
function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const mascotImg = document.getElementById('mascotImg');
if (mascotImg) {
  mascotImg.addEventListener('error', () => {
    mascotImg.style.display = 'none';
  });
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
    if (tab === 'quarantine') loadQuarantineTable();
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
  try {
    const data = await window.annaKav.getHashmap();
    const filled = data.hashtable.filter(Boolean).length;
    const cap = data.capacity || data.hashtable.length;
    document.getElementById('statHmLoaded').textContent = `${filled} / ${cap}`;
    appendLog(`=== TheRealAnnaKav v0.1.5 Initialized (hmload: ${filled}/${cap} slots) ===\n`);
    data.logs.forEach(l => appendLog(l + '\n'));
    loadHashmapTable();
  } catch (err) {
    appendLog(`[ERROR] Gagal memuat Hashmap: ${err.message}\n`);
  }
}

async function loadHashmapTable() {
  const data = await window.annaKav.getHashmap();
  const filled = data.hashtable.filter(Boolean).length;
  const cap = data.capacity || data.hashtable.length;
  document.getElementById('statHmLoaded').textContent = `${filled} / ${cap}`;

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
  const incrementalCheckpoint = document.getElementById('chkIncremental').checked;

  appendLog('\n--- Memulai dfsWalker() & O(1) Hashmap Lookup ---\n');
  let res;
  try {
    res = await window.annaKav.scanTargets({
      targetPaths: currentTargets,
      onlyExecutable,
      incrementalCheckpoint
    });
  } catch (err) {
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

  tbody.innerHTML = res.results.map((r, idx) => {
    let badgeClass = 'clean';
    if (r.status === 'MALWARE DETECTED') badgeClass = 'malware';
    if (r.status.startsWith('SKIPPED')) badgeClass = 'skip';

    const quarantineBtn = r.status === 'MALWARE DETECTED'
      ? ` <button class="btn-mini btn-danger-mini" data-q-idx="${idx}" title="Pindahkan file ini ke folder quarantine/">🛡️ Karantina</button>`
      : '';

    return `<tr>
      <td><strong>${escapeHtml(r.fileName)}</strong><br/><small style="color:#8b92a5">${escapeHtml(r.filePath)}</small></td>
      <td>${escapeHtml(r.size)} B</td>
      <td class="mono">${escapeHtml(r.shaHex)}</td>
      <td>${escapeHtml(r.matchedDb)}</td>
      <td><span class="badge ${badgeClass}">${escapeHtml(r.status)}</span>${quarantineBtn}</td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('[data-q-idx]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const item = res.results[Number(btn.getAttribute('data-q-idx'))];
      if (!item) return;
      try {
        await window.annaKav.quarantineFile({
          filePath: item.filePath,
          matchedDb: item.matchedDb,
          shaHex: item.shaHex
        });
        btn.textContent = '✓ Dikarantina';
        btn.disabled = true;
      } catch (err) {
        alert('Gagal mengkarantina: ' + err.message);
      }
    });
  });
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

// Tab 4: Quarantine Vault (v0.1.5)
async function loadQuarantineTable() {
  const list = await window.annaKav.getQuarantineList();
  const tbody = document.getElementById('quarantineTableBody');
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">Belum ada file di dalam karantina.</td></tr>';
    return;
  }

  tbody.innerHTML = list.map(item => {
    const dt = new Date(item.quarantinedAt).toLocaleString('id-ID');
    return `<tr>
      <td><strong>${escapeHtml(item.originalName)}</strong><br/><small style="color:#8b92a5">${escapeHtml(item.originalPath)}</small></td>
      <td><span class="badge malware">${escapeHtml(item.matchedDb)}</span></td>
      <td class="mono">${escapeHtml(item.shaHex)}</td>
      <td>${escapeHtml(dt)}</td>
      <td>
        <button class="btn-mini" data-restore-id="${escapeHtml(item.id)}">↩ Restore</button>
        <button class="btn-mini btn-danger-mini" data-delete-id="${escapeHtml(item.id)}">🗑 Hapus</button>
      </td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('[data-restore-id]').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await window.annaKav.restoreQuarantine(btn.getAttribute('data-restore-id'));
        loadQuarantineTable();
      } catch (err) {
        alert('Gagal memulihkan: ' + err.message);
      }
    });
  });

  tbody.querySelectorAll('[data-delete-id]').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await window.annaKav.deleteQuarantine(btn.getAttribute('data-delete-id'));
        loadQuarantineTable();
      } catch (err) {
        alert('Gagal menghapus: ' + err.message);
      }
    });
  });
}

document.getElementById('btnRefreshQuarantine').addEventListener('click', loadQuarantineTable);

// Tab 5: Security & Checkpoint
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
