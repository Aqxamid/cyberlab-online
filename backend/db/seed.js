/**
 * CyberLab Seed Script
 * Run AFTER npm install: node db/seed.js
 * This inserts demo users with proper bcrypt hashes.
 */
require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

async function seed() {
  console.log('🌱 Seeding demo users...');
  const hash = await bcrypt.hash('password123', 10);
  console.log('   Generated hash:', hash);

  const users = [
    { username: 'alice',       email: 'alice@cyberlab.io',      password_hash: hash, role: 'student' },
    { username: 'bob',         email: 'bob@cyberlab.io',        password_hash: hash, role: 'student' },
    { username: 'instructor1', email: 'instructor@cyberlab.io', password_hash: hash, role: 'instructor' },
    { username: 'admin',       email: 'admin@cyberlab.io',      password_hash: hash, role: 'admin' },
  ];

  for (const user of users) {
    const { error } = await supabase.from('users').upsert(user, { onConflict: 'username' });
    if (error) console.error(`   ✗ ${user.username}:`, error.message);
    else console.log(`   ✓ ${user.username} (${user.role})`);
  }

  console.log('✅ Seed complete.');
  process.exit(0);
}

seed().catch(err => { console.error('Seed failed:', err); process.exit(1); });
