import express from 'express';
import multer from 'multer';
import { exec } from 'child_process';
import fs from 'fs';
import path from 'path';
import cors from 'cors';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

const uploadsDir = path.join(__dirname, 'uploads');
const publicDir = path.join(__dirname, 'public');
const plistDir = path.join(publicDir, 'plist');

[uploadsDir, publicDir, plistDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// ستانداردی MIME Type بۆ دامەزراندنی OTA
app.use(express.static(publicDir, {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.ipa')) {
            res.setHeader('Content-Type', 'application/octet-stream');
        } else if (filePath.endsWith('.plist')) {
            res.setHeader('Content-Type', 'text/xml');
        }
    }
}));

// بەرزکردنەوەی سنوور بۆ 500MB
const upload = multer({
    dest: uploadsDir,
    limits: { fileSize: 500 * 1024 * 1024 }
});

const localZsign = path.join(__dirname, 'zsign');

app.post('/api/sign', upload.fields([
    { name: 'ipa', maxCount: 1 },
    { name: 'p12', maxCount: 1 },
    { name: 'provision', maxCount: 1 },
    { name: 'dylib', maxCount: 10 }
]), (req, res) => {
    try {
        if (!req.files || !req.files['ipa']) {
            return res.status(400).json({ success: false, error: 'IPA file is required.' });
        }

        const ipaPath = req.files['ipa'][0].path;
        const p12Path = req.files['p12'] ? req.files['p12'][0].path : null;
        const provPath = req.files['provision'] ? req.files['provision'][0].path : null;
        const password = req.body.password || '';

        const appName = req.body.appName || '';
        const bundleId = req.body.bundleId || '';
        const appVersion = req.body.appVersion || '';
        const noSignature = req.body.noSignature === 'true';
        const multiOpen = req.body.multiOpen === 'true';

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

        // بەکارهێنانی تەنیا ئەو فەرمانانەی کە بە فەرمی لە zsign بوونیان هەیە
        let cmdArgs = ['-f']; // -f بۆ force sign و تێپەڕاندنی واژۆی پێشوو

        if (!noSignature && p12Path && provPath) {
            cmdArgs.push(`-k "${p12Path}"`);
            cmdArgs.push(`-p "${password}"`);
            cmdArgs.push(`-m "${provPath}"`);
        }

        if (appName) cmdArgs.push(`-n "${appName}"`);

        // ڕێکخستنی شوناس (Bundle ID)
        if (bundleId) {
            cmdArgs.push(`-b "${bundleId}"`);
        } else if (multiOpen) {
            cmdArgs.push(`-b "app.falcon.clone.${timestamp}"`);
        }

        // گۆڕینی وەشان
        if (appVersion) cmdArgs.push(`-r "${appVersion}"`);

        // زیادکردن و دەرزیلێدانی تویکەکان (Dylib / Deb)
        if (req.files['dylib']) {
            req.files['dylib'].forEach(file => {
                cmdArgs.push(`-l "${file.path}"`);
            });
        }

        cmdArgs.push(`-o "${signedIpaPath}"`);
        cmdArgs.push(`"${ipaPath}"`);

        const fullCmd = `${execCmd} ${cmdArgs.join(' ')}`;

        exec(fullCmd, (error, stdout, stderr) => {
            // سڕینەوەی فایلە خاوەکان
            try {
                if (fs.existsSync(ipaPath)) fs.unlinkSync(ipaPath);
                if (p12Path && fs.existsSync(p12Path)) fs.unlinkSync(p12Path);
                if (provPath && fs.existsSync(provPath)) fs.unlinkSync(provPath);
                if (req.files['dylib']) {
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
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'active', engine: 'zsign-pro', maxUpload: '500MB' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
