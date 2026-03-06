#!/usr/bin/env node
/**
 * generate-flag-hashes.js
 *
 * Run with: node db/generate-flag-hashes.js
 *
 * To customise: change the FLAG_VALUES below, or pass them in via env vars.
 */
require('dotenv').config();
const crypto = require('crypto');

function hashFlag(rawFlag) {
  return crypto.createHash('sha256').update(rawFlag.trim().toLowerCase()).digest('hex');
}

// ── Define your flags here (or pull from env vars) ───────────────────────────
const flags = {
  'idor-basics':      process.env.FLAG_IDOR     || 'FLAG{idor_is_dangerous_123}',
  'sql-injection-101':process.env.FLAG_SQLI     || 'FLAG{sql_injected_success}',
  'xss-reflected':    process.env.FLAG_XSS      || 'FLAG{xss_reflected_pwned}',
  'jwt-forgery':      process.env.FLAG_JWT      || 'FLAG{jwt_none_algorithm_bypass}',
  'path-traversal':   process.env.FLAG_PATH     || 'FLAG{traversed_the_path}',
};

console.log('\n🔑 Flag hashes for schema.sql:\n');
console.log('-- Copy these into schema.sql, replacing REPLACE_WITH_... placeholders\n');

for (const [slug, rawFlag] of Object.entries(flags)) {
  const hash = hashFlag(rawFlag);
  console.log(`-- ${slug}`);
  console.log(`-- Raw flag (DO NOT COMMIT): ${rawFlag}`);
  console.log(`'${hash}',\n`);
}

console.log('✅ Done. Paste the hashes above into schema.sql.');
console.log('⚠️  Never commit raw flag values to source control.\n');