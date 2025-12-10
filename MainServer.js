const http = require('http');
const fs = require('fs');
const path = require('path');

// ==== CONFIG ====
const IPA_DIR = 'E:\\IPAs'; // external drive folder
const DELETE_AFTER_DOWNLOAD = true; // auto-delete after download
const THROTTLE_BYTES_PER_SEC = null; // set number for throttling, null = no throttling
const PORT = 6969;

// ==== UTILITY FUNCTIONS ====

// Scan IPA folder and generate repo.json dynamically
function getRepoJSON() {
    const files = fs.readdirSync(IPA_DIR).filter(f => f.endsWith('.ipa'));
    return files.map(f => {
        const fullPath = path.join(IPA_DIR, f);
        const stats = fs.statSync(fullPath);
        return {
            name: f,
            size: stats.size,
            url: `/ipa/${encodeURIComponent(f)}`
        };
    });
}

// Stream file with optional throttling
function streamFile(filePath, res, throttle) {
    const stat = fs.statSync(filePath);
    res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': stat.size,
        'Cache-Control': 'public, max-age=86400'
    });

    const readStream = fs.createReadStream(filePath);

    if (!throttle) {
        readStream.pipe(res);
    } else {
        let bytesSent = 0;
        readStream.on('data', chunk => {
            readStream.pause();
            res.write(chunk, () => {
                bytesSent += chunk.length;
                setTimeout(() => readStream.resume(), (chunk.length / throttle) * 1000);
            });
        });
        readStream.on('end', () => res.end());
    }

    // Auto-delete after download
    if (DELETE_AFTER_DOWNLOAD) {
        readStream.on('end', () => {
            try {
                fs.unlinkSync(filePath);
                console.log(`Deleted IPA: ${filePath}`);
            } catch (err) {
                console.error(`Failed to delete IPA: ${err}`);
            }
        });
    }
}

// ==== HTTP SERVER ====
const server = http.createServer((req, res) => {
    try {
        if (req.url === '/repo.json') {
            const repo = getRepoJSON();
            res.writeHead(200, {
                'Content-Type': 'application/json',
                'Cache-Control': 'public, max-age=60'
            });
            res.end(JSON.stringify(repo));
            return;
        }

        if (req.url.startsWith('/ipa/')) {
            const ipaName = decodeURIComponent(req.url.replace('/ipa/', ''));
            const ipaPath = path.join(IPA_DIR, ipaName);

            if (!fs.existsSync(ipaPath)) {
                res.writeHead(404);
                res.end('IPA not found');
                return;
            }

            console.log(`Streaming IPA: ${ipaName} to client`);
            streamFile(ipaPath, res, THROTTLE_BYTES_PER_SEC);
            return;
        }

        res.writeHead(404);
        res.end('Not found');
    } catch (err) {
        console.error(err);
        res.writeHead(500);
        res.end('Server error');
    }
});

// ==== AUTO-RELOAD repo.json WHEN FOLDER CHANGES ====
fs.watch(IPA_DIR, { persistent: true }, (eventType, filename) => {
    if (filename && filename.endsWith('.ipa')) {
        console.log(`Detected change in IPA folder: ${filename}`);
    }
});

server.listen(PORT, () => console.log(`SideServer running on port ${PORT}`));
