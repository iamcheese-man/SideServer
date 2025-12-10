const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { pipeline, PassThrough } = require('stream');

// ==== CONFIG ====
const IPA_DIR = 'E:\\IPAs'; // external drive folder
const DELETE_AFTER_DOWNLOAD = true; // auto-delete after download
const THROTTLE_BYTES_PER_SEC = null; // set number for throttling, null = no throttling
const PORT = 6969;

// ==== UTILITIES ====

// Track active streams per file so we only delete when all streams finish
const activeStreams = new Map();

function isIpaFilename(name) {
    return typeof name === 'string' && name.toLowerCase().endsWith('.ipa');
}

async function getRepoJSON() {
    try {
        const files = await fsp.readdir(IPA_DIR);
        const ipaFiles = files.filter(isIpaFilename);
        const result = [];
        for (const f of ipaFiles) {
            try {
                const fullPath = path.join(IPA_DIR, f);
                const stats = await fsp.stat(fullPath);
                result.push({
                    name: f,
                    size: stats.size,
                    url: `/ipa/${encodeURIComponent(f)}`
                });
            } catch (err) {
                console.warn(`Skipping file ${f}: ${err.message}`);
            }
        }
        return result;
    } catch (err) {
        console.error('Failed to read IPA directory:', err);
        return [];
    }
}

function safeDecodeURIComponent(s) {
    try {
        return decodeURIComponent(s);
    } catch (err) {
        return null;
    }
}

function ensurePathInside(baseDir, targetPath) {
    const resolvedBase = path.resolve(baseDir) + path.sep;
    const resolvedTarget = path.resolve(targetPath) + (targetPath.endsWith(path.sep) ? path.sep : '');
    return resolvedTarget.startsWith(resolvedBase);
}

function throttleTransform(bytesPerSec) {
    // Simple transform-based throttle. It buffers each chunk and delays pushing to next stream.
    const transform = new PassThrough();
    let lastTime = Date.now();
    let leftover = 0;
    transform._transform = function (chunk, enc, cb) {
        // Not used by PassThrough; this is a conceptual placeholder.
        cb(null, chunk);
    };
    // We'll implement throttling by manually pausing/resuming using 'data' listeners where we create the stream.
    return transform;
}

function incrementActive(fileKey) {
    activeStreams.set(fileKey, (activeStreams.get(fileKey) || 0) + 1);
}

function decrementActiveAndMaybeDelete(fileKey, filePath) {
    const current = Math.max(0, (activeStreams.get(fileKey) || 1) - 1);
    if (current === 0) {
        activeStreams.delete(fileKey);
        if (DELETE_AFTER_DOWNLOAD) {
            // Attempt to delete; on Windows this may fail if file is still open.
            fsp.unlink(filePath).then(() => {
                console.log(`Deleted IPA: ${filePath}`);
            }).catch(err => {
                console.warn(`Failed to delete IPA ${filePath}: ${err.message}`);
            });
        }
    } else {
        activeStreams.set(fileKey, current);
    }
}

// Stream file with optional throttling and range support
function streamFile(filePath, res, throttleBytesPerSec, range) {
    const stat = fs.statSync(filePath); // statSync here is tiny and acceptable since we already checked existence
    let start = 0;
    let end = stat.size - 1;
    let statusCode = 200;
    const headers = {
        'Content-Type': 'application/zip',
        'Cache-Control': 'public, max-age=86400',
        'Accept-Ranges': 'bytes'
    };

    if (range) {
        // parse range header like "bytes=123-456"
        const m = range.match(/bytes=(\d*)-(\d*)/);
        if (m) {
            const rangeStart = m[1] ? parseInt(m[1], 10) : undefined;
            const rangeEnd = m[2] ? parseInt(m[2], 10) : undefined;
            if (typeof rangeStart !== 'undefined' || typeof rangeEnd !== 'undefined') {
                start = typeof rangeStart === 'number' ? rangeStart : start;
                end = typeof rangeEnd === 'number' ? Math.min(rangeEnd, end) : end;
                if (start <= end && start < stat.size) {
                    statusCode = 206;
                    headers['Content-Range'] = `bytes ${start}-${end}/${stat.size}`;
                    headers['Content-Length'] = end - start + 1;
                } else {
                    res.writeHead(416);
                    res.end('Requested Range Not Satisfiable');
                    return;
                }
            }
        }
    } else {
        headers['Content-Length'] = stat.size;
    }

    res.writeHead(statusCode, headers);

    let readStream = fs.createReadStream(filePath, { start, end });

    // Track active streams so we don't delete file prematurely
    const fileKey = path.resolve(filePath);
    incrementActive(fileKey);

    // If throttling is enabled, implement pause/resume per chunk
    if (!throttleBytesPerSec) {
        // pipe directly and handle events
        readStream.pipe(res);
    } else {
        // Simple per-chunk pause/resume throttle
        let bytesSent = 0;
        readStream.on('data', chunk => {
            readStream.pause();
            const ok = res.write(chunk, () => {
                bytesSent += chunk.length;
                // compute delay in ms to maintain average rate
                const delayMs = (chunk.length / throttleBytesPerSec) * 1000;
                setTimeout(() => {
                    // If response already closed, destroy stream
                    if (res.writableEnded || res.destroyed) {
                        readStream.destroy();
                        return;
                    }
                    readStream.resume();
                }, Math.max(0, delayMs));
            });
            // If res.write returns false, let 'drain' resume to avoid buffering too much
            if (!ok) {
                res.once('drain', () => {
                    // no-op; resume is handled in the write callback
                });
            }
        });
        readStream.on('end', () => {
            // ensure response ends
            try { res.end(); } catch (e) { /* ignore */ }
        });
    }

    const onFinishOrClose = () => {
        decrementActiveAndMaybeDelete(fileKey, filePath);
    };

    readStream.on('close', onFinishOrClose);
    readStream.on('end', onFinishOrClose);
    readStream.on('error', err => {
        console.error(`Read error for ${filePath}:`, err);
        try { res.end(); } catch (e) { /* ignore */ }
        onFinishOrClose();
    });

    // If client disconnects, destroy the read stream and decrement
    res.on('close', () => {
        if (!readStream.destroyed) {
            readStream.destroy();
        }
        onFinishOrClose();
    });
}

// ==== HTTP SERVER ====
const server = http.createServer(async (req, res) => {
    try {
        // parse URL using host header so query strings are handled properly
        const host = req.headers.host || `localhost:${PORT}`;
        const parsed = new URL(req.url, `http://${host}`);
        const pathname = parsed.pathname;

        if (pathname === '/repo.json') {
            const repo = await getRepoJSON();
            res.writeHead(200, {
                'Content-Type': 'application/json',
                'Cache-Control': 'public, max-age=60'
            });
            res.end(JSON.stringify(repo));
            return;
        }

        if (pathname.startsWith('/ipa/')) {
            const encodedName = pathname.slice('/ipa/'.length);
            const decoded = safeDecodeURIComponent(encodedName);
            if (!decoded) {
                res.writeHead(400);
                res.end('Bad request: invalid filename encoding');
                return;
            }

            // Prevent path traversal by resolving path and ensuring it's inside IPA_DIR
            const ipaPath = path.join(IPA_DIR, decoded);
            if (!ensurePathInside(IPA_DIR, ipaPath)) {
                res.writeHead(403);
                res.end('Forbidden');
                return;
            }

            if (!fs.existsSync(ipaPath)) {
                res.writeHead(404);
                res.end('IPA not found');
                return;
            }

            console.log(`Streaming IPA: ${decoded} to client [${req.socket.remoteAddress}]`);
            streamFile(ipaPath, res, THROTTLE_BYTES_PER_SEC, req.headers.range);
            return;
        }

        res.writeHead(404);
        res.end('Not found');
    } catch (err) {
        console.error('Server error handling request:', err);
        if (!res.headersSent) {
            res.writeHead(500);
        }
        try { res.end('Server error'); } catch (e) { /* ignore */ }
    }
});

// ==== AUTO-RELOAD repo.json WHEN FOLDER CHANGES ====
(async () => {
    try {
        await fsp.access(IPA_DIR);
        try {
            fs.watch(IPA_DIR, { persistent: true }, (eventType, filename) => {
                if (filename && isIpaFilename(filename)) {
                    console.log(`Detected change in IPA folder: ${filename}`);
                }
            });
        } catch (err) {
            console.warn('fs.watch failed:', err.message);
        }
    } catch (err) {
        console.warn(`IPA_DIR "${IPA_DIR}" does not exist or is not accessible: ${err.message}`);
    }

    server.listen(PORT, () => console.log(`SideServer running on port ${PORT}`));
})();
