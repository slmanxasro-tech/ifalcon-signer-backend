import express from 'express';
import multer from 'multer';
import { exec } from 'child_process';
import fs from 'fs';
import path from 'path';
import cors from 'cors';

const app = express();
app.use(cors());

// دانانی سنووری تەواوی 200 مێگابایت بۆ سێرڤەر
const upload = multer({
    dest: 'uploads/',
    limits: { fileSize: 200 * 1024 * 1024 } 
});

app.post('/api/sign', upload.fields([
    { name: 'ipa', maxCount: 1 },
    { name: 'p12', maxCount: 1 },
    { name: 'provision', maxCount: 1 }
]), (req, res) => {
    const ipa = req.files['ipa'][0].path;
    const p12 = req.files['p12'][0].path;
    const prov = req.files['provision'][0].path;
    const pass = req.body.password || '';

    const signedName = `signed_${Date.now()}.ipa`;
    const outputPath = path.join('public', signedName);

    // فەرمانی واژۆکردنی zsign
    const cmd = `zsign -k "${p12}" -p "${pass}" -m "${prov}" -o "${outputPath}" "${ipa}"`;

    exec(cmd, (err, stdout, stderr) => {
        // سڕینەوەی فایلە هەڵبژێردراوەکانی بەکارهێنەر بۆ ئەوەی جێگا نەگرێت
        fs.unlinkSync(ipa);
        fs.unlinkSync(p12);
        fs.unlinkSync(prov);

        if (err) {
            return res.status(500).json({ success: false, error: stderr });
        }

        const domain = `https://${req.get('host')}`;
        const plistUrl = `${domain}/plist/${signedName}.plist`;

        res.json({
            success: true,
            installUrl: `itms-services://?action=download-manifest&url=${encodeURIComponent(plistUrl)}`
        });
    });
});

app.listen(process.env.PORT || 3000);
