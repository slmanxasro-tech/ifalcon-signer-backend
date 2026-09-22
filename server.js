const express = require('express');
const multer = require('multer');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const https = require('https');
const http = require('http');
const AdmZip = require('adm-zip');

// پاراستنی سێرვەر لە وەستان بە هۆی هەڵەی کاتییەوە
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection:', promise, 'reason:', reason);
});

const app = express();
app.use(cors());
app.use(express.json());

const uploadsDir = path.join(__dirname, 'uploads');
const publicDir = path.join(__dirname, 'public');
const plistDir = path.join(publicDir, 'plist');

[uploadsDir, publicDir, plistDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        try {
            fs.mkdirSync(dir, { recursive: true });
        } catch (e) {
            console.error(`Error creating directory ${dir}:`, e);
        }
    }
});

app.use(express.static(publicDir, {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.ipa')) {
            res.setHeader('Content-Type', 'application/octet-stream');
        } else if (filePath.endsWith('.plist')) {
            res.setHeader('Content-Type', 'text/xml');
        }
    }
}));

const upload = multer({
    dest: uploadsDir,
    limits: { fileSize: 500 * 1024 * 1024 }
});

const localZsign = path.join(__dirname, 'zsign');

const downloadIpaFromUrl = (url, destPath) => {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        client.get(url, (response) => {
            if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                return downloadIpaFromUrl(response.headers.location, destPath).then(resolve).catch(reject);
            }
            if (response.statusCode !== 200) {
                return reject(new Error(`Failed to download IPA. Status code: ${response.statusCode}`));
            }
            const fileStream = fs.createWriteStream(destPath);
            response.pipe(fileStream);
            fileStream.on('finish', () => {
                fileStream.close();
                resolve(destPath);
            });
            fileStream.on('error', (err) => {
                fs.unlink(destPath, () => {});
                reject(err);
            });
        }).on('error', (err) => {
            reject(err);
        });
    });
};

// ڕووکاری سەرەکی بۆ ڕێگریکردن لە کوژرانەوەی سێرვەر لەلایەن ڕەیلوەیەوە
app.get('/', (req, res) => {
    res.send('iFalcon Signer Backend is active and running successfully!');
});

app.get('/health', (req, res) => {
    res.json({ status: 'active', engine: 'zsign-pro', maxUpload: '500MB' });
});

app.post('/api/sign', upload.fields([
    { name: 'ipa', maxCount: 1 },
    { name: 'p12', maxCount: 1 },
    { name: 'provision', maxCount: 1 },
    { name: 'dylib', maxCount: 10 }
]), async (req, res) => {
    let ipaPath = null;
    try {
        const ipaFileUrl = req.body.ipaUrl;

        if (!req.files || !req.files['ipa']) {
            if (ipaFileUrl) {
                const tempIpaName = `downloaded_${Date.now()}.ipa`;
                ipaPath = path.join(uploadsDir, tempIpaName);
                try {
                    await downloadIpaFromUrl(ipaFileUrl, ipaPath);
                } catch (dlErr) {
                    return res.status(400).json({ success: false, error: `Failed to download IPA from URL: ${dlErr.message}` });
                }
            } else {
                return res.status(400).json({ success: false, error: 'IPA file or ipaUrl is required.' });
            }
        } else {
            ipaPath = req.files['ipa'][0].path;
        }

        const p12Path = req.files['p12'] ? req.files['p12'][0].path : null;
        const provPath = req.files['provision'] ? req.files['provision'][0].path : null;
        const password = req.body.password || '';

        const appName = req.body.appName || '';
        const bundleId = req.body.bundleId || '';
        const appVersion = req.body.appVersion || '';
        const noSignature = req.body.noSignature === 'true';
        const multiOpen = req.body.multiOpen === 'true';
        const removeProvision = req.body.removeProvision === 'true';

        const timestamp = Date.now();
        const signedIpaName = `signed_${timestamp}.ipa`;
        const signedIpaPath = path.join(publicDir, signedIpaName);
        const plistName = `manifest_${timestamp}.plist`;
        const plistPath = path.join(plistDir, plistName);

        let execCmd = 'zsign';
        if (fs.existsSync(localZsign)) {
            try { fs.chmodSync(localZsign, 0o755); } catch (_) {}
            execCmd = `"${localZsign}"`;
        }

        let cmdArgs = ['-f'];

        if (!noSignature && p12Path && provPath) {
            cmdArgs.push(`-k "${p12Path}"`);
            cmdArgs.push(`-p "${password}"`);
            cmdArgs.push(`-m "${provPath}"`);
        }

        if (appName) cmdArgs.push(`-n "${appName}"`);

        if (bundleId) {
            cmdArgs.push(`-b "${bundleId}"`);
        } else if (multiOpen) {
            cmdArgs.push(`-b "app.falcon.clone.${timestamp}"`);
        }

        if (appVersion) cmdArgs.push(`-r "${appVersion}"`);

        if (req.files['dylib']) {
            req.files['dylib'].forEach(file => {
                cmdArgs.push(`-l "${file.path}"`);
            });
        }

        cmdArgs.push(`-o "${signedIpaPath}"`);
        cmdArgs.push(`"${ipaPath}"`);

        const fullCmd = `${execCmd} ${cmdArgs.join(' ')}`;

        exec(fullCmd, (error, stdout, stderr) => {
            try {
                if (ipaPath && fs.existsSync(ipaPath)) fs.unlinkSync(ipaPath);
                if (p12Path && fs.existsSync(p12Path)) fs.unlinkSync(p12Path);
                if (provPath && fs.existsSync(provPath)) fs.unlinkSync(provPath);
                if (req.files && req.files['dylib']) {
                    req.files['dylib'].forEach(f => {
                        if (fs.existsSync(f.path)) fs.unlinkSync(f.path);
                    });
                }
            } catch (_) {}

            if (error) {
                console.error('zsign error:', stderr || stdout);
                return res.status(500).json({
                    success: false,
                    error: stderr || stdout || 'Signing failed.'
                });
            }

            if (removeProvision && fs.existsSync(signedIpaPath)) {
                try {
                    const zip = new AdmZip(signedIpaPath);
                    const zipEntries = zip.getEntries();
                    
                    zipEntries.forEach(entry => {
                        if (entry.entryName.endsWith('embedded.mobileprovision')) {
                            zip.deleteFile(entry.entryName);
                        }
                    });
                    
                    zip.writeZip(signedIpaPath);
                } catch (e) {
                    console.error('Error removing mobileprovision:', e);
                }
            }

            const host = req.get('host');
            const baseUrl = `https://${host}`;
            const ipaDownloadUrl = `${baseUrl}/${signedIpaName}`;
            const finalBundleId = bundleId || (multiOpen ? `app.falcon.clone.${timestamp}` : '*');

            const plistContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>items</key>
    <array>
        <dict>
            <key>assets</key>
            <array>
                <dict>
                    <key>kind</key>
                    <string>software-package</string>
                    <key>url</key>
                    <string>${ipaDownloadUrl}</string>
                </dict>
                <dict>
                    <key>kind</key>
                    <string>display-image</string>
                    <key>needs-shine</key>
                    <false/>
                    <key>url</key>
                    <string>https://ifalconapp.pages.dev/assets/images/icons/default.png</string>
                </dict>
                <dict>
                    <key>kind</key>
                    <string>full-size-image</string>
                    <key>needs-shine</key>
                    <false/>
                    <key>url</key>
                    <string>https://ifalconapp.pages.dev/assets/images/icons/default.png</string>
                </dict>
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>${finalBundleId}</string>
                <key>bundle-version</key>
                <string>${appVersion || '1.0.0'}</string>
                <key>kind</key>
                <string>software</string>
                <key>title</key>
                <string>${appName || 'iFalcon Signed App'}</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>`;

            fs.writeFileSync(plistPath, plistContent);

            const manifestUrl = `${baseUrl}/plist/${plistName}`;
            const itmsUrl = `itms-services://?action=download-manifest&url=${manifestUrl}`;

            return res.json({
                success: true,
                downloadUrl: ipaDownloadUrl,
                manifestUrl: manifestUrl,
                installUrl: itmsUrl
            });
        });

    } catch (err) {
        if (ipaPath && fs.existsSync(ipaPath)) {
            try { fs.unlinkSync(ipaPath); } catch (_) {}
        }
        return res.status(500).json({ success: false, error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Backend server successfully running on port ${PORT}`);
});
