/**
 * SideServer - enhanced
 *
 * Requirements:
 *   npm install selfsigned bonjour yauzl mime-types
 *
 * Notes:
 *   - Requires Node 18+ for global fetch (or install node-fetch and adapt).
 *   - If you have your own cert/key, set TLS_CERT_PATH and TLS_KEY_PATH env vars or update config below.
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { pipeline, PassThrough } = require('stream');
const { Transform } = require('stream');

// External deps (install via npm)
const selfsigned = require('selfsigned');
const bonjour = require('bonjour')();
const yauzl = require('yauzl');
const mime = require('mime-types');

// ==== CONFIG ====
const IPA_DIR = process.env.IPA_DIR || 'E:\\IPAs';
const DELETE_AFTER_DOWNLOAD = process.env.DELETE_AFTER_DOWNLOAD === 'true' || true;
const THROTTLE_BYTES_PER_SEC = process.env.THROTTLE_BYTES_PER_SEC ? Number(process.env.THROTTLE_BYTES_PER_SEC) : null;
const PORT = Number(process.env.PORT || 6969);
const TLS_CERT_PATH = process.env.TLS_CERT_PATH || null; // if provided, uses those files instead of generating
const TLS_KEY_PATH = process.env.TLS_KEY_PATH || null;
const MIRROR_BASE_URLS = process.env.MIRRORS ? process.env.MIRRORS.split(',').map(s => s.trim()).filter(Boolean) : []; // e.g. "https://mirror1.example,https://mirror2"
const MDNS_NAME = process.env.MDNS_NAME || 'sideserver';
const MAX_REPO_ENTRIES = 2000;
const REPO_SCAN_DEBOUNCE_MS = 300;

// ==== STATE/CACHES ====
const activeStreams = new Map(); // fileKey -> count
const shaCache = new Map(); // fileKey -> { mtimeMs, size, sha256 }
let repoCache = null;
let lastScan = 0;
let scanTimer = null;

// ==== UTILITIES ====

function isIpaFilename(name) {
    return typeof name === 'string' && name.toLowerCase().endsWith('.ipa');
}

function safeDecodeURIComponent(s) {
    try {
        return decodeURIComponent(s);
    } catch (err) {
        return null;
    }
}

function ensurePathInside(baseDir, targetPath) {
    const resolvedBase = path.resolve(baseDir);
    const resolvedTarget = path.resolve(targetPath);
    const rel = path.relative(resolvedBase, resolvedTarget);
    if (process.platform === 'win32') {
        return (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) &&
               resolvedTarget.toLowerCase().startsWith(resolvedBase.toLowerCase());
    }
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function incrementActive(fileKey) {
    activeStreams.set(fileKey, (activeStreams.get(fileKey) || 0) + 1);
}

function decrementActiveAndMaybeDelete(fileKey, filePath) {
    const current = Math.max(0, (activeStreams.get(fileKey) || 1) - 1);
    if (current === 0) {
        activeStreams.delete(fileKey);
        if (DELETE_AFTER_DOWNLOAD) {
            fsp.unlink(filePath).then(() => {
                console.log(`Deleted IPA: ${filePath}`);
                // When file removed, invalidate shaCache entry
                shaCache.delete(fileKey);
                // trigger rescan so repo.json reflects removal and redownload attempts can occur later
                scheduleRepoScan(50);
            }).catch(err => {
                console.warn(`Failed to delete IPA ${filePath}: ${err.message}`);
            });
        }
    } else {
        activeStreams.set(fileKey, current);
    }
}

// Throttle transform (token bucket style)
function throttleTransform(bytesPerSec) {
    if (!bytesPerSec || typeof bytesPerSec !== 'number' || bytesPerSec <= 0) return new PassThrough();

    let allowance = bytesPerSec;
    let last = Date.now();

    return new Transform({
        highWaterMark: 64 * 1024,
        transform(chunk, enc, cb) {
            const now = Date.now();
            const elapsed = now - last;
            last = now;
            allowance += (elapsed / 1000) * bytesPerSec;
            if (allowance > bytesPerSec) allowance = bytesPerSec;

            const buffer = Buffer.from(chunk);
            const tryPush = (buf) => {
                if (buf.length <= allowance) {
                    allowance -= buf.length;
                    this.push(buf);
                    cb();
                } else if (allowance >= 1) {
                    const take = Math.floor(allowance);
                    this.push(buf.slice(0, take));
                    const rest = buf.slice(take);
                    allowance = 0;
                    setTimeout(() => tryPush(rest), 100);
                } else {
                    setTimeout(() => tryPush(buf), 100);
                }
            };

            tryPush(buffer);
        }
    });
}

// SHA256 of a file (streaming). Caches result keyed by resolved path + mtime + size.
async function computeSha256(filePath) {
    const key = path.resolve(filePath);
    try {
        const st = await fsp.stat(filePath);
        const metaHashKey = `${st.mtimeMs}:${st.size}`;
        const cached = shaCache.get(key);
        if (cached && cached.meta === metaHashKey && cached.sha) {
            return cached.sha;
        }
        // Compute new hash
        const hash = crypto.createHash('sha256');
        await new Promise((resolve, reject) => {
            const rs = fs.createReadStream(filePath);
            rs.on('error', reject);
            rs.on('data', chunk => hash.update(chunk));
            rs.on('end', resolve);
        });
        const sha = hash.digest('hex');
        shaCache.set(key, { meta: metaHashKey, sha, mtimeMs: st.mtimeMs, size: st.size });
        return sha;
    } catch (err) {
        // missing file or other error
        shaCache.delete(key);
        throw err;
    }
}

// Attempt to download a missing IPA from configured MIRROR_BASE_URLS.
// Saves to IPA_DIR atomically (tmp then rename). Returns true on success.
async function downloadFromMirrors(filename) {
    if (!Array.isArray(MIRROR_BASE_URLS) || MIRROR_BASE_URLS.length === 0) return false;
    const encoded = encodeURIComponent(filename);
    const targetPath = path.join(IPA_DIR, filename);
    const tmpPath = `${targetPath}.download`;
    for (const base of MIRROR_BASE_URLS) {
        try {
            const url = base.endsWith('/') ? base + encoded : `${base}/${encoded}`;
            console.log(`Attempting to download ${filename} from ${url}`);
            const res = await fetch(url);
            if (!res.ok) {
                console.warn(`Mirror ${url} returned ${res.status}`);
                continue;
            }
            // Stream to tmp file
            await fsp.mkdir(path.dirname(tmpPath), { recursive: true });
            const fileStream = fs.createWriteStream(tmpPath, { flags: 'w' });
            await new Promise((resolve, reject) => {
                pipeline(res.body, fileStream, (err) => err ? reject(err) : resolve());
            });
            // atomic rename
            await fsp.rename(tmpPath, targetPath);
            console.log(`Downloaded ${filename} from ${base}`);
            // Invalidate sha cache
            shaCache.delete(path.resolve(targetPath));
            scheduleRepoScan(50);
            return true;
        } catch (err) {
            console.warn(`Failed to download from mirror ${base}: ${err && err.message ? err.message : err}`);
            try { await fsp.unlink(tmpPath); } catch (e) { /* ignore */ }
        }
    }
    return false;
}

// Parse Range header robustly
function parseRangeHeader(range, size) {
    if (!range) return null;
    const m = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
    if (!m) return null;
    const s = m[1], e = m[2];
    if (s === '' && e === '') return null;
    let start = s === '' ? undefined : parseInt(s, 10);
    let end = e === '' ? undefined : parseInt(e, 10);
    if (typeof start === 'number' && Number.isNaN(start)) start = undefined;
    if (typeof end === 'number' && Number.isNaN(end)) end = undefined;

    if (typeof start === 'undefined' && typeof end === 'number') {
        // suffix
        const suffix = end;
        if (suffix === 0) return null;
        start = Math.max(0, size - suffix);
        end = size - 1;
    } else {
        start = typeof start === 'number' ? start : 0;
        end = typeof end === 'number' ? Math.min(end, size - 1) : size - 1;
    }

    if (start > end || start >= size) return { error: true };
    return { start, end };
}

// Extract best icon from IPA (zip) and stream it to the response.
// Returns true if an icon was found and streamed; false if not found.
function streamIconFromIpa(ipaPath, res) {
    return new Promise((resolve) => {
        yauzl.open(ipaPath, { lazyEntries: true }, (err, zipfile) => {
            if (err) {
                res.writeHead(500);
                res.end();
                return resolve(false);
            }
            const iconCandidates = [];
            zipfile.readEntry();
            zipfile.on('entry', (entry) => {
                const name = entry.fileName;
                // Typical icons live in Payload/*.app/*.png or .jpg
                if (/\.(png|jpg|jpeg)$/i.test(name) && /\.app\//i.test(name)) {
                    // Exclude AppIcon60x60@2x~ipad etc? We'll prefer largest file length
                    iconCandidates.push({ name, size: entry.uncompressedSize });
                }
                zipfile.readEntry();
            });
            zipfile.on('end', () => {
                if (iconCandidates.length === 0) {
                    zipfile.close();
                    return resolve(false);
                }
                // pick largest
                iconCandidates.sort((a, b) => b.size - a.size);
                const chosen = iconCandidates[0].name;
                zipfile.openReadStream(iconCandidates[0].name ? { fileName: chosen } : null, (err2, rs) => {
                    // Note: yauzl doesn't have openReadStream by name directly. We'll reopen to find the correct entry.
                    // For compatibility, reopen and iterate
                    zipfile.close();
                    yauzl.open(ipaPath, { lazyEntries: true }, (err3, zip2) => {
                        if (err3) {
                            res.writeHead(500);
                            res.end();
                            return resolve(false);
                        }
                        let streamed = false;
                        zip2.readEntry();
                        zip2.on('entry', (entry2) => {
                            if (entry2.fileName === chosen) {
                                zip2.openReadStream(entry2, (err4, entryStream) => {
                                    if (err4) {
                                        zip2.close();
                                        res.writeHead(500);
                                        res.end();
                                        return resolve(false);
                                    }
                                    const type = mime.lookup(chosen) || 'application/octet-stream';
                                    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'public, max-age=86400' });
                                    pipeline(entryStream, res, (pErr) => {
                                        zip2.close();
                                        if (pErr) console.warn('icon stream pipeline err', pErr);
                                        resolve(true);
                                    });
                                });
                            } else {
                                zip2.readEntry();
                            }
                        });
                    });
                });
            });
        });
    });
}

// More robust icon extraction: iterate entries and stream chosen entry
function streamIconFromIpa_v2(ipaPath, res) {
    return new Promise((resolve) => {
        yauzl.open(ipaPath, { lazyEntries: true }, (err, zipfile) => {
            if (err) {
                res.writeHead(500);
                res.end();
                return resolve(false);
            }
            const candidates = [];
            zipfile.readEntry();
            zipfile.on('entry', (entry) => {
                const name = entry.fileName;
                if (/\.(png|jpg|jpeg)$/i.test(name) && /\.app\//i.test(name)) {
                    candidates.push({ entry, name, size: entry.uncompressedSize });
                }
                zipfile.readEntry();
            });
            zipfile.on('end', () => {
                if (candidates.length === 0) {
                    zipfile.close();
                    return resolve(false);
                }
                candidates.sort((a, b) => b.size - a.size);
                const chosen = candidates[0].entry;
                zipfile.openReadStream(chosen, (err2, readStream) => {
                    if (err2) {
                        zipfile.close();
                        res.writeHead(500);
                        res.end();
                        return resolve(false);
                    }
                    const type = mime.lookup(chosen.fileName) || 'application/octet-stream';
                    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'public, max-age=86400' });
                    pipeline(readStream, res, (pErr) => {
                        zipfile.close();
                        if (pErr) console.warn('icon pipeline err', pErr);
                        resolve(true);
                    });
                });
            });
        });
    });
}

// ==== REPO SCAN (repo.json) ====
async function buildRepoList() {
    const out = [];
    try {
        const files = await fsp.readdir(IPA_DIR);
        const ipaFiles = files.filter(isIpaFilename).slice(0, MAX_REPO_ENTRIES);
        for (const f of ipaFiles) {
            const fullPath = path.join(IPA_DIR, f);
            try {
                const stats = await fsp.stat(fullPath);
                if (!stats.isFile()) continue;
                // compute sha asynchronously but don't block listing; we'll compute concurrently and attach
                const item = {
                    name: f,
                    size: stats.size,
                    url: `/ipa/${encodeURIComponent(f)}`,
                    icon_url: `/icon/${encodeURIComponent(f)}`,
                    sha256: null
                };
                out.push(item);
            } catch (err) {
                console.warn(`Skipping ${f}: ${err.message}`);
            }
        }
    } catch (err) {
        console.error('Failed to read IPA dir for repo.json:', err.message);
    }

    // Compute sha256 concurrently but limit parallelism to avoid I/O overload
    const concurrency = 4;
    let idx = 0;
    const workers = new Array(concurrency).fill(0).map(async () => {
        while (true) {
            const i = idx++;
            if (i >= out.length) break;
            const it = out[i];
            try {
                it.sha256 = await computeSha256(path.join(IPA_DIR, it.name));
            } catch (e) {
                it.sha256 = null;
            }
        }
    });
    await Promise.all(workers);
    return out;
}

function scheduleRepoScan(ms = REPO_SCAN_DEBOUNCE_MS) {
    if (scanTimer) clearTimeout(scanTimer);
    scanTimer = setTimeout(async () => {
        try {
            repoCache = await buildRepoList();
            lastScan = Date.now();
            console.log(`repo.json refreshed (${repoCache.length} entries)`);
        } catch (err) {
            console.warn('repo scan failed', err);
        } finally {
            scanTimer = null;
        }
    }, ms);
}

// initial scan (sync)
(async () => {
    try {
        await fsp.mkdir(IPA_DIR, { recursive: true });
    } catch (e) { /* ignore */ }
    scheduleRepoScan(10);
})();

// fs.watch with resilient fallback to polling
try {
    fs.watch(IPA_DIR, { persistent: true }, (eventType, filename) => {
        if (filename && isIpaFilename(filename)) scheduleRepoScan();
    });
} catch (e) {
    // ignore; periodic rescan fallback
    setInterval(() => scheduleRepoScan(), 30_000);
}

// ==== STREAMING WITH ZERO-COPY WHEN POSSIBLE + RANGE support ====
async function streamFile(filePath, req, res, throttleBytesPerSec) {
    const fileKey = path.resolve(filePath);

    // If file missing, attempt automatic redownload from mirrors (if configured)
    try {
        await fsp.access(filePath, fs.constants.R_OK);
    } catch (err) {
        console.log(`File missing: ${filePath}. Attempting redownload from mirrors...`);
        const ok = await downloadFromMirrors(path.basename(filePath));
        if (!ok) {
            res.writeHead(404);
            res.end('IPA not found (and mirrors failed)');
            return;
        }
    }

    let stat;
    try {
        stat = await fsp.stat(filePath);
        if (!stat.isFile()) throw new Error('not a file');
    } catch (err) {
        res.writeHead(404);
        res.end('IPA not found');
        return;
    }

    const size = stat.size;
    const range = parseRangeHeader(req.headers.range, size);

    if (range && range.error) {
        res.writeHead(416, { 'Content-Range': `bytes */${size}` });
        res.end('Requested Range Not Satisfiable');
        return;
    }

    let start = 0, end = size - 1;
    let statusCode = 200;
    const headers = {
        'Content-Type': 'application/zip',
        'Cache-Control': 'public, max-age=86400',
        'Accept-Ranges': 'bytes',
        'Content-Disposition': `attachment; filename="${path.basename(filePath)}"`
    };

    if (range) {
        start = range.start;
        end = range.end;
        statusCode = 206;
        headers['Content-Range'] = `bytes ${start}-${end}/${size}`;
        headers['Content-Length'] = String(end - start + 1);
    } else {
        headers['Content-Length'] = String(size);
    }

    if (req.method === 'HEAD') {
        res.writeHead(statusCode, headers);
        res.end();
        return;
    }

    res.writeHead(statusCode, headers);

    incrementActive(fileKey);

    // Zero-copy when no throttling: pipe readStream directly to res (fast)
    const readStream = fs.createReadStream(filePath, { start, end, highWaterMark: 64 * 1024 });

    if (!throttleBytesPerSec) {
        pipeline(readStream, res, (err) => {
            if (err) console.warn('stream pipeline err', err && err.message ? err.message : err);
            decrementActiveAndMaybeDelete(fileKey, filePath);
        });
    } else {
        const throttle = throttleTransform(throttleBytesPerSec);
        pipeline(readStream, throttle, res, (err) => {
            if (err) console.warn('throttled pipeline err', err && err.message ? err.message : err);
            decrementActiveAndMaybeDelete(fileKey, filePath);
        });
    }

    req.on('close', () => {
        if (!readStream.destroyed) {
            try { readStream.destroy(); } catch (e) { /* ignore */ }
        }
    });
}

// ==== HTTP(S) SERVER ====
async function createTlsOptions() {
    // If paths provided, try to read them
    if (TLS_CERT_PATH && TLS_KEY_PATH) {
        try {
            const cert = await fsp.readFile(TLS_CERT_PATH);
            const key = await fsp.readFile(TLS_KEY_PATH);
            return { cert, key };
        } catch (err) {
            console.warn('Failed to read provided TLS cert/key:', err.message);
        }
    }
    // generate self-signed cert
    const attrs = [{ name: 'commonName', value: `${MDNS_NAME}.local` }];
    const pems = selfsigned.generate(attrs, { days: 365, keySize: 2048, algorithm: 'sha256' });
    return { cert: pems.cert, key: pems.private };
}

async function startServer() {
    const host = '0.0.0.0';
    const tls = await createTlsOptions();
    const httpsServer = https.createServer({ key: tls.key, cert: tls.cert }, requestHandler);
    const httpServer = http.createServer((req, res) => {
        // Redirect to https
        const hostHeader = req.headers.host ? req.headers.host.split(':')[0] : 'localhost';
        const redirect = `https://${hostHeader}:${PORT}${req.url}`;
        res.writeHead(301, { Location: redirect });
        res.end();
    });

    httpsServer.listen(PORT, host, () => {
        console.log(`SideServer (HTTPS) running on port ${PORT}`);
        // mDNS advertise service as https if using TLS
        bonjour.publish({ name: MDNS_NAME, type: 'https', port: PORT, txt: { path: '/' } });
        // also publish http for compatibility
        bonjour.publish({ name: `${MDNS_NAME}-http`, type: 'http', port: PORT, txt: { path: '/' } });
    });

    httpServer.listen( (PORT === 80) ? 8080 : (PORT + 1), host, () => {
        console.log(`HTTP redirector running on port ${ (PORT === 80) ? 8080 : (PORT + 1) } -> HTTPS:${PORT}`);
    });

    // Graceful shutdown handlers
    const stop = () => {
        try { bonjour.unpublishAll(); bonjour.destroy(); } catch (e) {}
        try { httpsServer.close(); } catch (e) {}
        try { httpServer.close(); } catch (e) {}
        process.exit(0);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
}

// Request handler used for HTTPS server
async function requestHandler(req, res) {
    try {
        const hostHeader = req.headers.host || `localhost:${PORT}`;
        const parsed = new URL(req.url, `https://${hostHeader}`);
        const pathname = parsed.pathname;

        if (pathname === '/repo.json') {
            // Ensure repoCache is reasonably fresh
            if (!repoCache || (Date.now() - lastScan) > 60_000) {
                try { repoCache = await buildRepoList(); lastScan = Date.now(); } catch (e) { /* ignore */ }
            }
            res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60' });
            res.end(JSON.stringify(repoCache || []));
            return;
        }

        if (pathname.startsWith('/ipa/')) {
            const encoded = pathname.slice('/ipa/'.length);
            const decoded = safeDecodeURIComponent(encoded);
            if (!decoded) {
                res.writeHead(400);
                res.end('Bad request: invalid filename encoding');
                return;
            }
            const ipaPath = path.join(IPA_DIR, decoded);
            if (!ensurePathInside(IPA_DIR, ipaPath)) {
                res.writeHead(403);
                res.end('Forbidden');
                return;
            }
            console.log(`Streaming IPA: ${decoded} from ${req.socket.remoteAddress}`);
            await streamFile(ipaPath, req, res, THROTTLE_BYTES_PER_SEC);
            return;
        }

        if (pathname.startsWith('/icon/')) {
            const encoded = pathname.slice('/icon/'.length);
            const decoded = safeDecodeURIComponent(encoded);
            if (!decoded) {
                res.writeHead(400);
                res.end('Bad request: invalid filename encoding');
                return;
            }
            const ipaPath = path.join(IPA_DIR, decoded);
            if (!ensurePathInside(IPA_DIR, ipaPath)) {
                res.writeHead(403);
                res.end('Forbidden');
                return;
            }
            try {
                await fsp.access(ipaPath, fs.constants.R_OK);
                const ok = await streamIconFromIpa_v2(ipaPath, res);
                if (!ok) {
                    res.writeHead(404);
                    res.end('Icon not found');
                }
            } catch (err) {
                // try mirrors before failing
                const downloaded = await downloadFromMirrors(decoded);
                if (downloaded) {
                    const ok = await streamIconFromIpa_v2(ipaPath, res);
                    if (!ok) {
                        res.writeHead(404);
                        res.end('Icon not found after redownload');
                    }
                } else {
                    res.writeHead(404);
                    res.end('IPA not found');
                }
            }
            return;
        }

        // health check
        if (pathname === '/.well-known/health' || pathname === '/health') {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('ok');
            return;
        }

        res.writeHead(404);
        res.end('Not found');
    } catch (err) {
        console.error('Server error handling request:', err && err.stack ? err.stack : err);
        if (!res.headersSent) res.writeHead(500);
        try { res.end('Server error'); } catch (e) { /* ignore */ }
    }
}

// Start everything
startServer().catch(err => {
    console.error('Failed to start server:', err && err.message ? err.message : err);
    process.exit(1);
});
