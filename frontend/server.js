/* -- this is the working version of the server, which serves the React app and provides the config.js endpoint -- */
/*
const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/config.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.send(`
    window.CYBERLAB_API  = "${process.env.API_URL  || 'https://cyberlab-backend-to2l.onrender.com'}";
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
*/ 

const express    = require('express');
const path       = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');
const app        = express();
const PORT       = process.env.PORT || 3000;

// ── Lab URL map ───────────────────────────────────────────────────────────────
const LAB_TARGETS = {
  'idor-basics':       process.env.IDOR_URL || 'http://idor-lab:5001',
  'sql-injection-101': process.env.SQLI_URL || 'http://sqli-lab:5002',
  'xss-reflected':     process.env.XSS_URL  || 'http://xss-lab:5003',
  'jwt-forgery':       process.env.JWT_URL  || 'http://jwt-lab:5004',
  'path-traversal':    process.env.PATH_URL || 'http://path-traversal-lab:5005',
};

function isInternal(url) {
  return !url.startsWith('https://') && !url.match(/^http:\/\/localhost/);
}

// ── Config.js ─────────────────────────────────────────────────────────────────
app.get('/config.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');

  // For internal Docker URLs → use /proxy/:slug so browser hits localhost:3000
  // For real public URLs (Render) → send the URL directly to the browser
  const labEntries = Object.entries(LAB_TARGETS)
    .map(([slug, url]) => `'${slug}': "${isInternal(url) ? `/proxy/${slug}` : url}"`)
    .join(',\n      ');

  res.send(`
    window.CYBERLAB_API = "${process.env.API_URL || 'http://localhost:4000'}";
    window.CYBERLAB_LABS = {
      ${labEntries}
    };
  `);
});

// ── Proxy — only active for internal Docker URLs ──────────────────────────────
Object.entries(LAB_TARGETS).forEach(([slug, target]) => {
  if (isInternal(target)) {
    app.use(
      `/proxy/${slug}`,
      createProxyMiddleware({
        target,
        changeOrigin: true,
        pathRewrite: { [`^/proxy/${slug}`]: '' },
        ws: true, // support websockets if any lab uses them
      })
    );
  }
});

app.use(express.static(path.join(__dirname, 'pages')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'pages', 'index.html')));

app.listen(PORT, () => {
  console.log(`🌐 CyberLab Frontend on http://localhost:${PORT}`);
});