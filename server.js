const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// Initialize databases (in-memory storage)
const filesDB = [];
const accessLogs = {};

// Enhanced middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Improved IP detection
const getClientIp = (req) => {
  const headers = [
    req.headers['x-forwarded-for'],
    req.headers['x-real-ip'],
    req.connection?.remoteAddress,
    req.socket?.remoteAddress
  ].filter(Boolean);

  const ipList = headers.flatMap(header => 
    header.includes(',') ? header.split(',').map(ip => ip.trim()) : [header]
  );

  return ipList[0] || 'unknown';
};

// File encryption/decryption
const encryptFile = (buffer, key) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.padEnd(32, '0')), iv);
  return {
    iv: iv.toString('hex'),
    content: Buffer.concat([cipher.update(buffer), cipher.final()]).toString('hex')
  };
};

const decryptFile = (encrypted, key) => {
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    Buffer.from(key.padEnd(32, '0')),
    Buffer.from(encrypted.iv, 'hex')
  );
  return Buffer.concat([
    decipher.update(Buffer.from(encrypted.content, 'hex')),
    decipher.final()
  ]);
};

// API Routes
app.post('/api/upload', upload.single('file'), (req, res) => {
  try {
    if (!req.file || !req.body.key) {
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

    accessLogs[fileId] = [{
      timestamp: new Date().toISOString(),
      ip: getClientIp(req),
      action: 'upload'
    }];

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
    const { id, key } = req.body;
    if (!id || !key) {
      return res.status(400).json({ error: 'File ID and key are required' });
    }

    const file = filesDB.find(f => f.id === id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    try {
      const decrypted = decryptFile(file.encryptedData, key);
      file.accessCount++;
      
      accessLogs[id].push({
        timestamp: new Date().toISOString(),
        ip: getClientIp(req),
        action: 'download'
      });

      res.set({
        'Content-Type': file.type,
        'Content-Disposition': `attachment; filename="${encodeURIComponent(file.name)}"`,
        'Content-Length': decrypted.length
      });
      return res.send(decrypted);
    } catch (decryptError) {
      accessLogs[id].push({
        timestamp: new Date().toISOString(),
        ip: getClientIp(req),
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
  res.json(filesDB.map(f => ({
    id: f.id,
    name: f.name,
    uploadDate: f.uploadDate,
    accessCount: f.accessCount
  })));
});

app.get('/api/file/:id', (req, res) => {
  const file = filesDB.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  res.json({
    ...file,
    accessLogs: accessLogs[req.params.id] || []
  });
});

// Client-side routing fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Export for Vercel
module.exports = app;

// Local development
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}