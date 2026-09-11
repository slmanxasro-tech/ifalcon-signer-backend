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

// دروستکردنی فۆڵدەرە پێویستەکان ئەگەر بوونیان نەبێت
const uploadsDir = path.join(__dirname, 'uploads');
const publicDir = path.join(__dirname, 'public');
const plistDir = path.join(publicDir, 'plist');

[uploadsDir, publicDir, plistDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// ڕێگەپێدان بە دەستگەیشتن بە فایلەکانی ناو public (IPA و Plist)
app.use(express.static(publicDir));

// ڕێکخستنی سنووری بارکردن (200MB)
const upload = multer({
    dest: uploadsDir,
    limits: { fileSize: 200 * 1024 * 1024 }
});

// ئەگەر zsign لە ناو فۆڵدەرەکە بوو ئەوە بەکاردێنێت، دەنا ناوی فەرمانە گشتییەکە (Nixpacks / System)
const localZsign = path.join(__dirname, 'zsign');
const zsignCmd = fs.existsSync(localZsign) ? `"${localZsign}"` : 'zsign';

app.post('/api/sign', upload.fields([
    { name: 'ipa', maxCount: 1 },
    { name: 'p12', maxCount: 1 },
    { name: 'provision', maxCount: 1 }
]), (req, res) => {
    try {
        if (!req.files || !req.files['ipa'] || !req.files['p12'] || !req.files['provision']) {
            return res.status(400).json({ success: false, error: 'All files (IPA, P12, Provision) are required.' });
        }

        const ipaPath = req.files['ipa'][0].path;
        const p12Path = req.files['p12'][0].path;
        const provPath = req.files['provision'][0].path;
        const password = req.body.password || '';

        const timestamp = Date.now();
        const signedIpaName = `signed_${timestamp}.ipa`;
        const signedIpaPath = path.join(publicDir, signedIpaName);
        const plistName = `manifest_${timestamp}.plist`;
        const plistPath = path.join(plistDir, plistName);

        // دڵنیابوونەوە لە مۆڵەتی کارکردنی باینەری ئەگەر لە ناوخۆ بوو
        if (fs.existsSync(localZsign)) {
            try { fs.chmodSync(localZsign, 0o755); } catch (_) {}
        }

        // فەرمانی واژۆکردنی IPA
        const cmd = `${zsignCmd} -k "${p12Path}" -p "${password}" -m "${provPath}" -o "${signedIpaPath}" "${ipaPath}"`;

        exec(cmd, (error, stdout, stderr) => {
            // سڕینەوەی فایلە خاوەکان
            try {
                if (fs.existsSync(ipaPath)) fs.unlinkSync(ipaPath);
                if (fs.existsSync(p12Path)) fs.unlinkSync(p12Path);
                if (fs.existsSync(provPath)) fs.unlinkSync(provPath);
            } catch (cleanupErr) {
                console.warn('Cleanup warning:', cleanupErr.message);
            }

            if (error) {
                console.error('zsign execution error:', stderr || stdout);
                return res.status(500).json({
                    success: false,
                    error: stderr || stdout || 'Codesigning failed. Check password or provisioning profile.'
                });
            }

            // بەستەری تەواو بە پرۆتۆکۆڵی پارێزراو
            const protocol = req.headers['x-forwarded-proto'] || req.protocol;
            const host = req.get('host');
            const baseUrl = `${protocol}://${host}`;

            const ipaDownloadUrl = `${baseUrl}/${signedIpaName}`;

            // دروستکردنی فایلی فەرمی manifest.plist بۆ ئەپڵ
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
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>app.ifalcon.signed.${timestamp}</string>
                <key>bundle-version</key>
                <string>1.0.0</string>
                <key>kind</key>
                <string>software</string>
                <key>title</key>
                <string>iFalcon Signed App</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>`;

            fs.writeFileSync(plistPath, plistContent);

            const manifestUrl = `${baseUrl}/plist/${plistName}`;
            const itmsUrl = `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`;

            return res.json({
                success: true,
                downloadUrl: ipaDownloadUrl,
                manifestUrl: manifestUrl,
                installUrl: itmsUrl
            });
        });

    } catch (err) {
        console.error('Server request exception:', err);
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'active', engine: 'zsign', maxUpload: '200MB' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`iFalcon Signer Backend running on port ${PORT}`);
});
