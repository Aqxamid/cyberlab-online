const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/config.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.send(`
    window.CYBERLAB_API  = "${process.env.API_URL  || 'http://localhost:4000'}";
    window.CYBERLAB_LABS = {
      'idor-basics':      "${process.env.IDOR_URL  || 'https://cyberlab-idor.onrender.com'}",
      'sql-injection-101':"${process.env.SQLI_URL  || 'https://cyberlab-sqli.onrender.com'}",
      'xss-reflected':    "${process.env.XSS_URL   || 'https://cyberlab-xss.onrender.com'}",
      'jwt-forgery':      "${process.env.JWT_URL    || 'https://cyberlab-jwt.onrender.com'}",
      'path-traversal':   "${process.env.PATH_URL   || 'https://cyberlab-path-traversal.onrender.com'}"
    };
  `);
});

app.use(express.static(path.join(__dirname, 'pages')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'pages', 'index.html')));

app.listen(PORT, () => {
  console.log(`🌐 CyberLab Frontend on http://localhost:${PORT}`);
});
