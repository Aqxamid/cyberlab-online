const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/config.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.send(`
    window.CYBERLAB_API  = "${process.env.API_URL  || 'http://localhost:4000'}";
    window.CYBERLAB_LABS = {
      'idor-basics':      "${process.env.IDOR_URL  || 'http://localhost:5001'}",
      'sql-injection-101':"${process.env.SQLI_URL  || 'http://localhost:5002'}",
      'xss-reflected':    "${process.env.XSS_URL   || 'http://localhost:5003'}",
      'jwt-forgery':      "${process.env.JWT_URL    || 'http://localhost:5004'}",
      'path-traversal':   "${process.env.PATH_URL   || 'http://localhost:5005'}"
    };
  `);
});

app.use(express.static(path.join(__dirname, 'pages')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'pages', 'index.html')));

app.listen(PORT, () => {
  console.log(`🌐 CyberLab Frontend on http://localhost:${PORT}`);
});
