const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
const upload = multer({ storage: multer.memoryStorage() }); // Using memory storage for Vercel

const filesDB = [];
const accessLogs = {};

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const getClientIp = (req) => {
  const ipChain = req.headers['x-forwarded-for'] || 
                 req.headers['x-real-ip'] || 
                 req.connection.remoteAddress;
  return ipChain.split(',')[0].trim();
};

const encryptFile = (buffer, key) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.padEnd(32, '0')), iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return { iv: iv.toString('hex'), content: encrypted.toString('hex') };
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

// File upload endpoint
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
      size: req.file.size,
      uploadDate: new Date().toISOString(),
      accessCount: 0,
      encryptedData: encrypted // Storing encrypted data directly
    });

    accessLogs[fileId] = [{
      timestamp: new Date().toISOString(),
      ip: getClientIp(req),
      action: 'upload'
    }];

    res.json({ 
      success: true, 
      id: fileId,
      name: req.file.originalname,
      size: req.file.size
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ 
      error: 'File upload failed',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
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

    const clientIp = getClientIp(req);

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
        'Content-Length': decrypted.length,
        'X-File-ID': file.id
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
    console.error('Download error:', err);
    res.status(500).json({ 
      error: 'File download failed',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

app.get('/api/files', (req, res) => {
  res.json(filesDB.map(f => ({
    id: f.id,
    name: f.name,
    size: f.size,
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

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}