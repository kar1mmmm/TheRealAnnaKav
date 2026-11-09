const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

let mainWindow;
const PROJECT_ROOT = __dirname;
const DB_DIR = path.join(PROJECT_ROOT, 'db');
const LOG_BIN_PATH = path.join(PROJECT_ROOT, 'log.bin');
const SL = 10; // Hashmap size from sha.h (#define SL 10)

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1220,
    height: 800,
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
// EXACT C ENGINE IMPLEMENTATION (sha.c, hashmap.c, util.c, readwritedb.c, chprelated.c)
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

// Load Hashmap from db/ directory (exact replica of hmload() in hashmap.c)
function hmload() {
  const hashtable = new Array(SL).fill(null);
  const logs = [];

  if (!fs.existsSync(DB_DIR)) {
    logs.push('[ERROR] Folder db/ tidak ditemukan: ' + DB_DIR);
    return { hashtable, logs };
  }

  const entries = fs.readdirSync(DB_DIR);
  for (const name of entries) {
    if (name === '.' || name === '..') continue;
    const fullPath = path.join(DB_DIR, name);
    const stat = fs.statSync(fullPath);
    if (!stat.isFile()) continue;

    const rawBuf = fs.readFileSync(fullPath);
    if (rawBuf.length < 32) continue;

    const shafile = bufferToU32ArrayLE(rawBuf);
    const rawHexBE = rawBuf.subarray(0, 32).toString('hex');

    // insertToHm(shafile, entry->d_name)
    let index = Ihash(shafile) % SL;
    let counter = 0;
    let placed = false;

    while (counter < SL) {
      if (hashtable[index] === null) {
        hashtable[index] = {
          slot: index,
          name: name,
          shaU32: Array.from(shafile),
          shaFormatted: formatU32ArrayHex(shafile),
          rawHex: rawHexBE,
          initialIndex: Ihash(shafile) % SL,
          probes: counter,
          size: rawBuf.length
        };
        placed = true;
        break;
      }
      index = (index + 1) % SL;
      counter++;
    }

    if (!placed) {
      logs.push('ALERT:HASHMAP IS FULL (ketika memasukkan ' + name + ')');
    }
  }

  for (let j = 0; j < SL; j++) {
    if (hashtable[j] !== null) {
      logs.push(`${j} | sha of ${hashtable[j].name}  = ${hashtable[j].shaFormatted}`);
    } else {
      logs.push(`${j} | UNALLOCATED`);
    }
  }

  return { hashtable, logs };
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

// Kirim log ke renderer dengan aman (window bisa saja sudah ditutup saat scan masih jalan)
function sendLog(msg) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('annakav:log', msg);
  }
}

// Hash file secara streaming agar file besar (GB) tidak dimuat penuh ke RAM
function sha256File(fpath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(fpath);
    stream.on('error', reject);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest()));
  });
}

// Path relatif (mis. 'db' dari tombol "Test Scan Folder db/") di-resolve terhadap
// folder proyek, bukan terhadap process.cwd() yang bisa berbeda-beda.
function resolveTarget(p) {
  return path.isAbsolute(p) ? p : path.resolve(PROJECT_ROOT, p);
}

// IPC: Run dfsWalker + HashAfile + Hashmap get()
ipcMain.handle('annakav:scanTargets', async (_event, { targetPaths, onlyExecutable } = {}) => {
  if (!Array.isArray(targetPaths) || targetPaths.length === 0) {
    throw new Error('Tidak ada target scan.');
  }

  const { hashtable, logs: hmLogs } = hmload();
  hmLogs.forEach(l => sendLog(l + '\n'));

  const filesToScan = [];
  let skippedCount = 0;

  // dfsWalker async: error per entry (EACCES, EPERM, file hilang, dll) dicatat lalu dilewati,
  // symlink/junction tidak diikuti (mencegah loop tak berhingga).
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
      // In Windows, S_IEXEC or executable extensions (.exe, .bat, .cmd, .sh, .bin, .com)
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

      const digest = await sha256File(fpath);
      const shaBE = formatU32ArrayHex(sha256BufferToU32ArrayBE(digest));
      const shaLE = formatU32ArrayHex(bufferToU32ArrayLE(digest));
      // Check also if the file itself is an exact 32-byte raw hash signature file (like in db/)
      const rawFileLE = st.size === 32
        ? formatU32ArrayHex(bufferToU32ArrayLE(await fs.promises.readFile(fpath)))
        : null;

      let matchedEntry = null;
      for (let slot = 0; slot < SL; slot++) {
        const item = hashtable[slot];
        if (!item) continue;
        if (
          item.shaFormatted === shaBE ||
          item.shaFormatted === shaLE ||
          item.rawHex === shaBE ||
          (rawFileLE && item.shaFormatted === rawFileLE)
        ) {
          matchedEntry = item;
          break;
        }
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

  // Write Checkpoint (log.bin) after scanning, matching annakav.c -> Checkpoint()
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

// IPC: readwritedb.c tool — Hash a file and save 32-byte binary signature into db/
ipcMain.handle('annakav:createDbSignature', async (_event, { sourceFilePath, outputDbName }) => {
  if (!fs.existsSync(sourceFilePath)) {
    throw new Error('File sumber tidak ditemukan.');
  }
  const cleanName = path.basename(outputDbName.trim());
  if (!cleanName) {
    throw new Error('Nama file DB output tidak boleh kosong.');
  }

  const buf = fs.readFileSync(sourceFilePath);
  const digest = crypto.createHash('sha256').update(buf).digest();
  // In readwritedb.c: u32t * H = HashAfile(argv[1]); fwrite(HforDB, sizeof(u32t), 8, binWRITE);
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
  let checkpointTime = null;
  if (fs.existsSync(LOG_BIN_PATH)) {
    const b = fs.readFileSync(LOG_BIN_PATH);
    if (b.length >= 8) {
      checkpointTime = Number(b.readBigInt64LE(0));
    } else if (b.length >= 4) {
      checkpointTime = b.readUInt32LE(0);
    }
  }

  const isLinux = process.platform === 'linux';
  let passwdMode = '0644 (Simulated on Windows / Compliant)';
  let shadowMode = '0600 (Simulated on Windows / Compliant)';
  if (isLinux) {
    try {
      const stP = fs.statSync('/etc/passwd');
      passwdMode = '0' + (stP.mode & 0o777).toString(8);
      const stS = fs.statSync('/etc/shadow');
      shadowMode = '0' + (stS.mode & 0o777).toString(8);
    } catch (_) {}
  }

  return {
    platform: process.platform,
    checkpointEpoch: checkpointTime,
    passwdMode,
    shadowMode
  };
});
