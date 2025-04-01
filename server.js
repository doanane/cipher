const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;
const upload = multer({ storage: multer.memoryStorage() });

// Initialize databases (in-memory storage)
const filesDB = [];
const accessLogs = {};

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Helper functions
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

// Routes
app.post('/api/upload', upload.single('file'), (req, res) => {
  try {
    console.log('Upload request received');
    if (!req.file || !req.body.key) {
      console.log('Missing file or key');
      return res.status(400).json({ error: 'File and encryption key are required' });
    }

    const encrypted = encryptFile(req.file.buffer, req.body.key);
    const fileId = crypto.randomBytes(8).toString('hex');
    
    filesDB.push({
      id: fileId,
      name: req.file.originalname,
      type: req.file.mimetype,
      uploadDate: new Date().toISOString(),
      accessCount: 0,
      encryptedData: encrypted
    });

    accessLogs[fileId] = [];

    console.log(`File uploaded successfully: ${fileId}`);
    res.json({ 
      success: true, 
      id: fileId,
      name: req.file.originalname
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'File upload failed' });
  }
});

app.post('/api/download', (req, res) => {
  try {
    console.log('Download request received');
    const { id, key } = req.body;
    if (!id || !key) {
      console.log('Missing ID or key');
      return res.status(400).json({ error: 'File ID and key are required' });
    }

    const file = filesDB.find(f => f.id === id);
    if (!file) {
      console.log('File not found:', id);
      return res.status(404).json({ error: 'File not found' });
    }

    const clientIp = getClientIp(req);
    console.log(`Download attempt from IP: ${clientIp}`);

    try {
      const decrypted = decryptFile(file.encryptedData, key);

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
      console.log('File download successful:', id);
      return res.send(decrypted);
    } catch (decryptError) {
      console.error('Decryption error:', decryptError);
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
    console.error('Download error:', err);
    res.status(500).json({ error: 'File download failed' });
  }
});

app.get('/api/files', (req, res) => {
  console.log('Files list requested');
  res.json(filesDB.map(f => ({
    id: f.id,
    name: f.name,
    uploadDate: f.uploadDate,
    accessCount: f.accessCount
  })));
});

app.get('/api/file/:id', (req, res) => {
  console.log('File details requested:', req.params.id);
  const file = filesDB.find(f => f.id === req.params.id);
  if (!file) {
    console.log('File not found:', req.params.id);
    return res.status(404).json({ error: 'File not found' });
  }

  res.json({
    ...file,
    accessLogs: accessLogs[req.params.id] || []
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});