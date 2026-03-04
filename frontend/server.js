const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Inject runtime config so the frontend JS knows where the API is
// without hardcoding localhost — required for Docker / production deploys
app.get('/config.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.send(`
    window.CYBERLAB_API = "${process.env.API_URL || 'http://localhost:4000'}";
    window.CYBERLAB_IDOR = "${process.env.IDOR_URL || 'http://localhost:5000'}";
  `);
});

app.use(express.static(path.join(__dirname, 'pages')));

// SPA fallback — serve index.html for unknown routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🌐 CyberLab Frontend running on http://localhost:${PORT}`);
  console.log(`   API_URL: ${process.env.API_URL || 'http://localhost:4000'}`);
  console.log(`   IDOR_URL: ${process.env.IDOR_URL || 'http://localhost:5000'}`);
});
