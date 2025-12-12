/**
 * SideServer - HTTP only (no TLS / no self-signed cert)
 *
 * Requirements:
 *   npm install bonjour yauzl mime-types
 *
 * Notes:
 *   - Node 18+ recommended (for global fetch). If using older Node, install node-fetch.
 *   - Configure via environment variables: IPA_DIR, PORT, DELETE_AFTER_DOWNLOAD, THROTTLE_BYTES_PER_SEC, MIRRORS, MDNS_NAME
 */

const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { pipeline, PassThrough, Transform } = require('stream');

// External deps (install via npm)
const bonjour = require('bonjour')();
const yauzl = require('yauzl');
const mime = require('mime-types');

// ==== CONFIG ====
const IPA_DIR = process.env.IPA_DIR || 'D:\\IPAs';
const DELETE_AFTER_DOWNLOAD = (process.env.DELETE_AFTER_DOWNLOAD || 'true') === 'true';
const THROTTLE_BYTES_PER_SEC = process.env.THROTTLE_BYTES_PER_SEC ? Number(process.env.THROTTLE_BYTES_PER_SEC) : null;
const PORT = Number(process.env.PORT || 6969);
const MIRROR_BASE_URLS = process.env.MIRRORS ? process.env.MIRRORS.split(',').map(s => s.trim()).filter(Boolean) : [];
const MDNS_NAME = process.env.MDNS_NAME || 'sideserver';
const MAX_REPO_ENTRIES = 2000;
const REPO_SCAN_DEBOUNCE_MS = 300;

// ==== STATE/CACHES ====
const activeStreams = new Map(); // fileKey -> count
const shaCache = new Map(); // fileKey -> { meta, sha, mtimeMs, size }
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
                shaCache.delete(fileKey);
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
            await fsp.mkdir(path.dirname(tmpPath), { recursive: true });
            const fileStream = fs.createWriteStream(tmpPath, { flags: 'w' });
            await new Promise((resolve, reject) => {
                pipeline(res.body, fileStream, (err) => err ? reject(err) : resolve());
            });
            await fsp.rename(tmpPath, targetPath);
            console.log(`Downloaded ${filename} from ${base}`);
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

// initial scan
(async () => {
    try { await fsp.mkdir(IPA_DIR, { recursive: true }); } catch (e) {}
    scheduleRepoScan(10);
})();

try {
    fs.watch(IPA_DIR, { persistent: true }, (eventType, filename) => {
        if (filename && isIpaFilename(filename)) scheduleRepoScan();
    });
} catch (e) {
    setInterval(() => scheduleRepoScan(), 30_000);
}

// ==== STREAMING WITH ZERO-COPY WHEN POSSIBLE + RANGE support ====
async function streamFile(filePath, req, res, throttleBytesPerSec) {
    const fileKey = path.resolve(filePath);

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

// ==== HTTP SERVER (NO TLS) ====
async function startServer() {
    const host = '0.0.0.0';
    const server = http.createServer(requestHandler);

    server.listen(PORT, host, () => {
        console.log(`SideServer (HTTP) running on port ${PORT}`);
        try {
            bonjour.publish({ name: MDNS_NAME, type: 'http', port: PORT, txt: { path: '/' } });
            console.log(`mDNS published as ${MDNS_NAME}.local:${PORT}`);
        } catch (e) {
            console.warn('mDNS publish failed', e && e.message ? e.message : e);
        }
    });

    const stop = () => {
        try { bonjour.unpublishAll(); bonjour.destroy(); } catch (e) {}
        try { server.close(); } catch (e) {}
        process.exit(0);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
}

// Request handler
async function requestHandler(req, res) {
    try {
        const hostHeader = req.headers.host || `localhost:${PORT}`;
        const parsed = new URL(req.url, `http://${hostHeader}`);
        const pathname = parsed.pathname;

        if (pathname === '/repo.json') {
            if (!repoCache || (Date.now() - lastScan) > 60_000) {
                try { repoCache = await buildRepoList(); lastScan = Date.now(); } catch (e) {}
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

// Start
startServer().catch(err => {
    console.error('Failed to start server:', err && err.message ? err.message : err);
    process.exit(1);
});
