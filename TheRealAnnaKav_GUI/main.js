const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

let mainWindow;
const PROJECT_ROOT = __dirname;
const DB_DIR = path.join(PROJECT_ROOT, 'db');
const LOG_BIN_PATH = path.join(PROJECT_ROOT, 'log.bin');
const QUARANTINE_DIR = path.join(PROJECT_ROOT, 'quarantine');
const QUARANTINE_MANIFEST = path.join(QUARANTINE_DIR, 'manifest.json');
const INITIAL_SL = 16; // v0.1.5 Dynamic Hashmap initial capacity (sha.h #define SL 16)

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1240,
    height: 820,
    minWidth: 980,
    minHeight: 650,
    backgroundColor: '#111216',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ============================================================================
// EXACT C ENGINE IMPLEMENTATION v0.1.5
// (Dynamic Hashmap, O(1) Ihash Lookup, Incremental Checkpoint, Quarantine)
// ============================================================================

// From hashmap.c: uint Ihash(u32t * sha)
function Ihash(shaU32Array) {
  let hashval = 0 >>> 0;
  for (let i = 0; i < 8; i++) {
    hashval = (hashval + Math.imul(shaU32Array[i] >>> 0, 3)) >>> 0;
  }
  return hashval >>> 0;
}

// Buffer (32 bytes) to 8 x uint32_t (Little Endian, matching x86 read(Fp, &shafile[i], sizeof(u32t)))
function bufferToU32ArrayLE(buf) {
  const arr = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    if (i * 4 + 4 <= buf.length) {
      arr[i] = buf.readUInt32LE(i * 4);
    } else {
      arr[i] = 0;
    }
  }
  return arr;
}

// Standard SHA256 Digest (Big Endian bytes) to 8 x uint32_t (matching sha256() in sha.c)
function sha256BufferToU32ArrayBE(digestBuf) {
  const arr = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    arr[i] = digestBuf.readUInt32BE(i * 4);
  }
  return arr;
}

// Format 8 x uint32_t using printf("%08x", sha[i]) from annakav.c
function formatU32ArrayHex(arr) {
  return Array.from(arr).map(v => (v >>> 0).toString(16).padStart(8, '0')).join('');
}

// O(1) Hashmap get() replica from hashmap.c (linear probing from Ihash(sha) % cap)
function hmGet(hashtable, shaU32) {
  const cap = hashtable.length;
  if (!cap) return null;
  let t = Ihash(shaU32) % cap;
  let count = 0;

  while (count < cap && hashtable[t] !== null) {
    const entry = hashtable[t];
    let match = true;
    for (let i = 0; i < 8; i++) {
      if ((entry.shaU32[i] >>> 0) !== (shaU32[i] >>> 0)) {
        match = false;
        break;
      }
    }
    if (match) return entry;
    t = (t + 1) % cap;
    count++;
  }
  return null;
}

// Load Dynamic Hashmap from db/ directory (v0.1.5 replica of hmload() with 2x resize at 70% load)
function hmload() {
  let capacity = INITIAL_SL;
  let hashtable = new Array(capacity).fill(null);
  let count = 0;
  const logs = [];

  if (!fs.existsSync(DB_DIR)) {
    logs.push('[ERROR] Folder db/ tidak ditemukan: ' + DB_DIR);
    return { hashtable, capacity, count, logs };
  }

  function placeItem(table, cap, item) {
    let idx = Ihash(item.shaU32) % cap;
    let probes = 0;
    while (probes < cap) {
      if (table[idx] === null) {
        table[idx] = {
          ...item,
          slot: idx,
          initialIndex: Ihash(item.shaU32) % cap,
          probes
        };
        return true;
      }
      idx = (idx + 1) % cap;
      probes++;
    }
    return false;
  }

  function resizeHm(newCap) {
    const oldTable = hashtable;
    const oldCap = capacity;
    hashtable = new Array(newCap).fill(null);
    capacity = newCap;
    count = 0;
    for (let i = 0; i < oldCap; i++) {
      if (oldTable[i] !== null) {
        placeItem(hashtable, capacity, oldTable[i]);
        count++;
      }
    }
    logs.push(`[Hashmap] Resized capacity ${oldCap} -> ${capacity}`);
  }

  const entries = fs.readdirSync(DB_DIR);
  for (const name of entries) {
    if (name === '.' || name === '..') continue;
    const fullPath = path.join(DB_DIR, name);
    const stat = fs.statSync(fullPath);
    if (!stat.isFile()) continue;

    const rawBuf = fs.readFileSync(fullPath);
    if (rawBuf.length !== 32) {
      logs.push(`WARNING: ${name} bukan signature 32-byte (${rawBuf.length} B), dilewati`);
      continue;
    }

    if ((count + 1) * 10 >= capacity * 7) {
      resizeHm(capacity * 2);
    }

    const shafile = bufferToU32ArrayLE(rawBuf);
    const rawHexBE = rawBuf.subarray(0, 32).toString('hex');

    const placed = placeItem(hashtable, capacity, {
      name,
      shaU32: Array.from(shafile),
      shaFormatted: formatU32ArrayHex(shafile),
      rawHex: rawHexBE,
      size: rawBuf.length
    });

    if (placed) {
      count++;
    } else {
      logs.push('ALERT:HASHMAP IS FULL (ketika memasukkan ' + name + ')');
    }
  }

  for (let j = 0; j < capacity; j++) {
    if (hashtable[j] !== null) {
      logs.push(`${j} | sha of ${hashtable[j].name}  = ${hashtable[j].shaFormatted}`);
    } else {
      logs.push(`${j} | UNALLOCATED`);
    }
  }

  return { hashtable, capacity, count, logs };
}

function readCheckpointEpoch() {
  if (!fs.existsSync(LOG_BIN_PATH)) return null;
  try {
    const b = fs.readFileSync(LOG_BIN_PATH);
    if (b.length >= 8) return Number(b.readBigInt64LE(0));
    if (b.length >= 4) return b.readUInt32LE(0);
  } catch (_) {}
  return null;
}

// Kirim log ke renderer dengan aman
function sendLog(msg) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('annakav:log', msg);
  }
}

// Hash file secara streaming agar file besar tidak dimuat penuh ke RAM
function sha256File(fpath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(fpath);
    stream.on('error', reject);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest()));
  });
}

function resolveTarget(p) {
  return path.isAbsolute(p) ? p : path.resolve(PROJECT_ROOT, p);
}

// IPC: Get Hashmap & DB State
ipcMain.handle('annakav:getHashmap', async () => {
  return hmload();
});

// IPC: Dialog pilih folder atau file
ipcMain.handle('annakav:selectTarget', async (_event, mode) => {
  const properties = mode === 'folder' ? ['openDirectory'] : ['openFile', 'multiSelections'];
  const res = await dialog.showOpenDialog(mainWindow, {
    title: mode === 'folder' ? 'Pilih Folder untuk dfsWalker()' : 'Pilih File untuk di-Scan / Hash',
    properties
  });
  return res.canceled ? [] : res.filePaths;
});

// IPC: Run dfsWalker + HashAfile + O(1) Hashmap get() + Incremental Checkpoint
ipcMain.handle('annakav:scanTargets', async (_event, { targetPaths, onlyExecutable, incrementalCheckpoint } = {}) => {
  if (!Array.isArray(targetPaths) || targetPaths.length === 0) {
    throw new Error('Tidak ada target scan.');
  }

  const { hashtable, logs: hmLogs } = hmload();
  hmLogs.forEach(l => sendLog(l + '\n'));

  const lastCheckpoint = incrementalCheckpoint ? (readCheckpointEpoch() || 0) : 0;
  if (incrementalCheckpoint && lastCheckpoint > 0) {
    sendLog(`[Checkpoint] Mode Incremental aktif (hanya file yang berubah setelah epoch ${lastCheckpoint})\n`);
  }

  const filesToScan = [];
  let skippedCount = 0;

  async function walk(currPath) {
    let st;
    try {
      st = await fs.promises.lstat(currPath);
    } catch (err) {
      skippedCount++;
      sendLog(`can't open ${currPath}: ${err.code || err.message}\n`);
      return;
    }

    if (st.isSymbolicLink()) {
      sendLog(`symlink dilewati : ${currPath}\n`);
      return;
    }

    if (st.isFile()) {
      filesToScan.push(currPath);
      return;
    }

    if (st.isDirectory()) {
      // Jangan memindai ulang isi folder quarantine
      if (path.resolve(currPath) === path.resolve(QUARANTINE_DIR)) return;
      sendLog(`folder name : ${path.basename(currPath)}\n`);
      let children;
      try {
        children = await fs.promises.readdir(currPath);
      } catch (err) {
        skippedCount++;
        sendLog(`can't open folder ${currPath}: ${err.code || err.message}\n`);
        return;
      }
      for (const ch of children) {
        if (ch === '.' || ch === '..') continue;
        await walk(path.join(currPath, ch));
      }
    }
  }

  for (const target of targetPaths) {
    await walk(resolveTarget(String(target)));
  }

  const results = [];
  for (const fpath of filesToScan) {
    try {
      const st = await fs.promises.stat(fpath);
      const fname = path.basename(fpath);
      const ext = path.extname(fname).toLowerCase();
      const isExec = Boolean((st.mode & 0o111) || ['.exe', '.bat', '.cmd', '.sh', '.bin', '.ps1', '.msi'].includes(ext));

      sendLog(`file name : ${fname}\n`);

      if (onlyExecutable && !isExec) {
        sendLog(`${fname} is not executable\n`);
        results.push({
          fileName: fname,
          filePath: fpath,
          size: st.size,
          mtime: st.mtimeMs,
          isExecutable: false,
          shaHex: '-',
          status: 'SKIPPED (Not Executable)',
          matchedDb: '-'
        });
        continue;
      }

      const fileMtimeSec = Math.floor(st.mtimeMs / 1000);
      if (incrementalCheckpoint && lastCheckpoint > 0 && fileMtimeSec <= lastCheckpoint) {
        sendLog(`${fname} unchanged since checkpoint (${lastCheckpoint}), skipped\n`);
        results.push({
          fileName: fname,
          filePath: fpath,
          size: st.size,
          mtime: st.mtimeMs,
          isExecutable: isExec,
          shaHex: '-',
          status: 'SKIPPED (Unchanged)',
          matchedDb: '-'
        });
        continue;
      }

      const digest = await sha256File(fpath);
      const u32BE = sha256BufferToU32ArrayBE(digest);
      const u32LE = bufferToU32ArrayLE(digest);
      const shaBE = formatU32ArrayHex(u32BE);

      // O(1) Hashmap lookup using hmGet (matching get() in hashmap.c)
      let matchedEntry = hmGet(hashtable, u32BE) || hmGet(hashtable, u32LE);

      // Support testing directly against raw 32-byte signature files inside db/
      if (!matchedEntry && st.size === 32) {
        const rawU32 = bufferToU32ArrayLE(await fs.promises.readFile(fpath));
        matchedEntry = hmGet(hashtable, rawU32);
      }

      if (matchedEntry) {
        sendLog(`There is something here\nfile ${fname} is a ${matchedEntry.name}\n`);
      }

      results.push({
        fileName: fname,
        filePath: fpath,
        size: st.size,
        mtime: st.mtimeMs,
        isExecutable: isExec,
        shaHex: shaBE,
        status: matchedEntry ? 'MALWARE DETECTED' : 'CLEAN',
        matchedDb: matchedEntry ? `${matchedEntry.name} (Slot #${matchedEntry.slot})` : '-'
      });
    } catch (err) {
      skippedCount++;
      sendLog(`Can't open ${fpath}: ${err.code || err.message}\n`);
    }
  }

  if (skippedCount > 0) {
    sendLog(`[INFO] ${skippedCount} file/folder tidak bisa dibaca dan dilewati.\n`);
  }

  const nowSec = Math.floor(Date.now() / 1000);
  try {
    const logBuf = Buffer.alloc(8);
    logBuf.writeBigInt64LE(BigInt(nowSec), 0);
    await fs.promises.writeFile(LOG_BIN_PATH, logBuf);
    sendLog(`[Checkpoint] log.bin diperbarui pada epoch ${nowSec}\n`);
  } catch (err) {
    sendLog(`[Checkpoint] Gagal menulis log.bin: ${err.message}\n`);
  }

  return {
    totalScanned: results.length,
    detectedCount: results.filter(r => r.status === 'MALWARE DETECTED').length,
    skippedCount,
    checkpointEpoch: nowSec,
    results
  };
});

// ============================================================================
// v0.1.5: QUARANTINE MANAGEMENT (Quarantine, List, Restore, Delete)
// ============================================================================

function loadQuarantineManifest() {
  if (!fs.existsSync(QUARANTINE_MANIFEST)) return [];
  try {
    const data = JSON.parse(fs.readFileSync(QUARANTINE_MANIFEST, 'utf8'));
    return Array.isArray(data) ? data : [];
  } catch (_) {
    return [];
  }
}

function saveQuarantineManifest(items) {
  if (!fs.existsSync(QUARANTINE_DIR)) {
    fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
  }
  fs.writeFileSync(QUARANTINE_MANIFEST, JSON.stringify(items, null, 2), 'utf8');
}

// Pindahkan file secara aman termasuk lintas partisi/drive (mis. C: -> D: menimbulkan EXDEV pada rename)
async function moveFileSafe(srcPath, destPath) {
  try { await fs.promises.chmod(srcPath, 0o666); } catch (_) {}
  try {
    await fs.promises.rename(srcPath, destPath);
  } catch (err) {
    if (err.code === 'EXDEV') {
      await fs.promises.copyFile(srcPath, destPath);
      await fs.promises.unlink(srcPath);
    } else {
      throw err;
    }
  }
}

ipcMain.handle('annakav:getQuarantineList', async () => {
  const list = loadQuarantineManifest();
  return list.filter(item => fs.existsSync(path.join(QUARANTINE_DIR, item.quarantinedName)));
});

ipcMain.handle('annakav:quarantineFile', async (_event, { filePath, matchedDb, shaHex } = {}) => {
  if (!filePath || !fs.existsSync(filePath)) {
    throw new Error('File tidak ditemukan atau sudah dipindahkan.');
  }
  // Cegah mengkarantina file signature bawaan di dalam folder db/
  if (path.resolve(path.dirname(filePath)) === path.resolve(DB_DIR)) {
    throw new Error('File di dalam folder signature db/ tidak boleh dikarantina.');
  }

  if (!fs.existsSync(QUARANTINE_DIR)) {
    fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
  }

  const st = fs.statSync(filePath);
  const id = `${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  const baseName = path.basename(filePath);
  const quarantinedName = `${id}_${baseName}.quarantined`;
  const destPath = path.join(QUARANTINE_DIR, quarantinedName);

  await moveFileSafe(filePath, destPath);
  try {
    await fs.promises.chmod(destPath, 0o400);
  } catch (_) {}

  const manifest = loadQuarantineManifest();
  const entry = {
    id,
    originalName: baseName,
    originalPath: path.resolve(filePath),
    originalMode: st.mode & 0o777,
    quarantinedName,
    matchedDb: matchedDb || '-',
    shaHex: shaHex || '-',
    size: st.size,
    quarantinedAt: Date.now()
  };
  manifest.unshift(entry);
  saveQuarantineManifest(manifest);

  sendLog(`[QUARANTINE] ${filePath} dipindahkan ke quarantine/${quarantinedName}\n`);
  return entry;
});

ipcMain.handle('annakav:restoreQuarantine', async (_event, id) => {
  const manifest = loadQuarantineManifest();
  const idx = manifest.findIndex(x => x.id === id);
  if (idx === -1) throw new Error('Data karantina tidak ditemukan.');

  const item = manifest[idx];
  const qPath = path.join(QUARANTINE_DIR, item.quarantinedName);
  if (!fs.existsSync(qPath)) {
    manifest.splice(idx, 1);
    saveQuarantineManifest(manifest);
    throw new Error('File fisik di karantina sudah tidak ada.');
  }

  const parentDir = path.dirname(item.originalPath);
  if (!fs.existsSync(parentDir)) {
    fs.mkdirSync(parentDir, { recursive: true });
  }

  await moveFileSafe(qPath, item.originalPath);
  if (item.originalMode) {
    try { await fs.promises.chmod(item.originalPath, item.originalMode); } catch (_) {}
  }

  manifest.splice(idx, 1);
  saveQuarantineManifest(manifest);
  sendLog(`[QUARANTINE] Dipulihkan: ${item.originalPath}\n`);
  return item;
});

ipcMain.handle('annakav:deleteQuarantine', async (_event, id) => {
  const manifest = loadQuarantineManifest();
  const idx = manifest.findIndex(x => x.id === id);
  if (idx === -1) throw new Error('Data karantina tidak ditemukan.');

  const item = manifest[idx];
  const qPath = path.join(QUARANTINE_DIR, item.quarantinedName);
  if (fs.existsSync(qPath)) {
    try { await fs.promises.chmod(qPath, 0o666); } catch (_) {}
    await fs.promises.unlink(qPath);
  }

  manifest.splice(idx, 1);
  saveQuarantineManifest(manifest);
  sendLog(`[QUARANTINE] Dihapus permanen: ${item.originalName}\n`);
  return item;
});

// IPC: readwritedb.c tool — Hash a file and save 32-byte binary signature into db/
ipcMain.handle('annakav:createDbSignature', async (_event, { sourceFilePath, outputDbName }) => {
  if (!fs.existsSync(sourceFilePath)) {
    throw new Error('File sumber tidak ditemukan.');
  }
  const cleanName = path.basename(String(outputDbName || '').trim());
  if (!cleanName || cleanName === '.' || cleanName === '..') {
    throw new Error('Nama file DB output tidak valid.');
  }

  const digest = await sha256File(sourceFilePath);
  const u32BE = sha256BufferToU32ArrayBE(digest);
  const outBuf = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) {
    outBuf.writeUInt32LE(u32BE[i], i * 4);
  }

  const destPath = path.join(DB_DIR, cleanName);
  fs.writeFileSync(destPath, outBuf);
  const hexOut = formatU32ArrayHex(u32BE);
  sendLog(`[readwritedb] ${cleanName} ditulis ke db/ -> ${hexOut}\n`);

  return {
    fileName: cleanName,
    destPath,
    hexHash: hexOut
  };
});

// IPC: WAFPrev() & Checkpoint() status
ipcMain.handle('annakav:getSecurityStatus', async () => {
  const checkpointTime = readCheckpointEpoch();

  const isLinux = process.platform === 'linux';
  let passwdMode = 'N/A (Khusus Linux — berjalan di ' + process.platform + ')';
  let shadowMode = 'N/A (Khusus Linux — berjalan di ' + process.platform + ')';
  if (isLinux) {
    try {
      const stP = fs.statSync('/etc/passwd');
      const mP = stP.mode & 0o777;
      passwdMode = `0${mP.toString(8)} (${(mP & 0o022) ? 'ALERT: Weak Permission!' : 'Compliant'})`;
    } catch (e) {
      passwdMode = `Error: ${e.code || e.message}`;
    }
    try {
      const stS = fs.statSync('/etc/shadow');
      const mS = stS.mode & 0o777;
      shadowMode = `0${mS.toString(8)} (${(mS & 0o077) ? 'ALERT: Weak Permission!' : 'Compliant'})`;
    } catch (e) {
      shadowMode = `Error: ${e.code || e.message}`;
    }
  }

  return {
    platform: process.platform,
    checkpointEpoch: checkpointTime,
    passwdMode,
    shadowMode
  };
});
