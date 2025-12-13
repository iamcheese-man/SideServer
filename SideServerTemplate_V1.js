const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');

// ===== CONFIG =====
const IPA_DIR = 'D:\\SideServer\\IPAs'; // your external drive folder
const DELETE_AFTER_DOWNLOAD = false; // set true if you want auto-delete after download
const PORT = 6969;
const MAX_FILE_AGE_MS = 6 * 30 * 24 * 60 * 60 * 1000; // 6 months

// ===== UTILITIES =====
function isIpa(name) {
    return typeof name === 'string' && name.toLowerCase().endsWith('.ipa');
}

async function getRepoJSON() {
    try {
        const files = await fsp.readdir(IPA_DIR);
        const ipaFiles = files.filter(isIpa);
        const result = [];
        for (const f of ipaFiles) {
            const fullPath = path.join(IPA_DIR, f);
            try {
                const stats = await fsp.stat(fullPath);
                result.push({
                    name: f,
                    size: stats.size,
                    url: `/ipa/${encodeURIComponent(f)}`
                });
            } catch {}
        }
        return result;
    } catch {
        return [];
    }
}

function ensurePathInside(baseDir, targetPath) {
    return path.resolve(targetPath).startsWith(path.resolve(baseDir));
}

// Delete files older than 6 months
async function cleanupOldFiles() {
    try {
        const files = await fsp.readdir(IPA_DIR);
        const now = Date.now();
        for (const f of files.filter(isIpa)) {
            const fullPath = path.join(IPA_DIR, f);
            try {
                const stats = await fsp.stat(fullPath);
                if (now - stats.mtimeMs > MAX_FILE_AGE_MS) {
                    await fsp.unlink(fullPath);
                    console.log(`Deleted old IPA: ${f}`);
                }
            } catch {}
        }
    } catch {}
}

// Get LAN IP
function getLocalIP() {
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
        for (const iface of ifaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) return iface.address;
        }
    }
    return 'localhost';
}

// ===== SERVER =====
const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url, `http://${req.headers.host}`);
        const pathname = url.pathname;

        // Serve repo.json
        if (pathname === '/repo.json') {
            const repo = await getRepoJSON();
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(repo));
            return;
        }

        // Serve IPA files
        if (pathname.startsWith('/ipa/')) {
            const name = decodeURIComponent(pathname.slice(5));
            const filePath = path.join(IPA_DIR, name);

            if (!ensurePathInside(IPA_DIR, filePath) || !fs.existsSync(filePath)) {
                res.writeHead(404);
                res.end('Not found');
                return;
            }

            res.writeHead(200, {
                'Content-Type': 'application/zip',
                'Content-Disposition': `attachment; filename="${name}"`,
                'Cache-Control': 'public, max-age=86400'
            });

            const stream = fs.createReadStream(filePath);
            stream.pipe(res);

            stream.on('close', async () => {
                if (DELETE_AFTER_DOWNLOAD) {
                    try { await fsp.unlink(filePath); } catch {}
                }
            });

            return;
        }

        res.writeHead(404);
        res.end('Not found');
    } catch (err) {
        console.error(err);
        if (!res.headersSent) res.writeHead(500);
        res.end('Server error');
    }
});

// Run cleanup every 24h
setInterval(cleanupOldFiles, 24 * 60 * 60 * 1000);
cleanupOldFiles();

// Listen on all interfaces
server.listen(PORT, '0.0.0.0', () => {
    const lanIP = getLocalIP();
    console.log(`SideServer running on port ${PORT}`);
    console.log(`Access it on your LAN at http://${lanIP}:${PORT}`);
});
