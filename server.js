const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3001;
const upload = multer({ dest: 'uploads/' });

// Initialize databases
const filesDB = [];
const accessLogs = {};

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('encrypted_files')) fs.mkdirSync('encrypted_files');

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const getClientIp = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() || 
         req.headers['x-real-ip'] || 
         req.connection.remoteAddress;
};

const encryptFile = (buffer, key) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.padEnd(32, '0')), iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return { iv: iv.toString('hex'), content: encrypted.toString('hex') };
};

const decryptFile = (encrypted, key) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key.padEnd(32, '0')), Buffer.from(encrypted.iv, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(encrypted.content, 'hex')), decipher.final()]);
};

// File upload endpoint
app.post('/api/upload', upload.single('file'), (req, res) => {
  try {
    if (!req.file || !req.body.key) {
      return res.status(400).json({ error: 'File and encryption key are required' });
    }

    const fileBuffer = fs.readFileSync(req.file.path);
    const encrypted = encryptFile(fileBuffer, req.body.key);
    const fileId = crypto.randomBytes(8).toString('hex');
    
    // Save encrypted file
    fs.writeFileSync(`encrypted_files/${fileId}.enc`, JSON.stringify(encrypted));
    fs.unlinkSync(req.file.path);

    // Add to database
    filesDB.push({
      id: fileId,
      name: req.file.originalname,
      type: req.file.mimetype,
      uploadDate: new Date().toISOString(),
      accessCount: 0
    });

    // Initialize access logs
    accessLogs[fileId] = [];

    res.json({ 
      success: true, 
      id: fileId,
      name: req.file.originalname
    });
  } catch (err) {
    res.status(500).json({ error: 'File upload failed' });
  }
});

// File download endpoint
app.post('/api/download', (req, res) => {
  try {
    const { id, key } = req.body;
    if (!id || !key) {
      return res.status(400).json({ error: 'File ID and key are required' });
    }

    const file = filesDB.find(f => f.id === id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    // Get client IP
    const clientIp = getClientIp(req);
    console.log(`Download attempt from IP: ${clientIp}`);

    try {
      const encrypted = JSON.parse(fs.readFileSync(`encrypted_files/${id}.enc`));
      const decrypted = decryptFile(encrypted, key);

      // Log successful download
      file.accessCount++;
      accessLogs[id].push({
        timestamp: new Date().toISOString(),
        ip: clientIp,
        action: 'download'
      });

      res.set({
        'Content-Type': file.type,
        'Content-Disposition': `attachment; filename="${encodeURIComponent(file.name)}"`,
        'Content-Length': decrypted.length
      });
      return res.send(decrypted);
    } catch (decryptError) {
      // Log failed attempt
      accessLogs[id].push({
        timestamp: new Date().toISOString(),
        ip: clientIp,
        action: 'failed_attempt',
        error: decryptError.message.includes('bad decrypt') ? 'invalid_key' : 'decryption_error'
      });

      if (decryptError.message.includes('bad decrypt')) {
        return res.status(403).json({ error: 'Invalid encryption key' });
      }
      throw decryptError;
    }
  } catch (err) {
    res.status(500).json({ error: 'File download failed' });
  }
});

// Get all files
app.get('/api/files', (req, res) => {
  res.json(filesDB.map(f => ({
    id: f.id,
    name: f.name,
    uploadDate: f.uploadDate,
    accessCount: f.accessCount
  })));
});

// Get file details
app.get('/api/file/:id', (req, res) => {
  const file = filesDB.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  res.json({
    ...file,
    accessLogs: accessLogs[req.params.id] || []
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://localhost:${PORT}`);
});