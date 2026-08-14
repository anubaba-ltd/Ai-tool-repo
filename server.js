require('dotenv').config();
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const expressLayouts = require('express-ejs-layouts');
const mysql = require('mysql2/promise');
const { v4: uuid } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_NAME = process.env.APP_NAME || 'Safe Tool Portal';
const UPLOAD_DIR = path.join(__dirname, 'storage', 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const dbConfig = {
  host: process.env.MYSQL_HOST || 'localhost',
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'tool_portal',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4'
};
let pool;

async function initDatabase() {
  const adminConn = await mysql.createConnection({
    host: dbConfig.host,
    port: dbConfig.port,
    user: dbConfig.user,
    password: dbConfig.password,
    charset: 'utf8mb4'
  });
  await adminConn.query(`CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  await adminConn.end();

  pool = mysql.createPool(dbConfig);
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    email VARCHAR(190) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin','editor','user') NOT NULL DEFAULT 'user',
    active TINYINT(1) NOT NULL DEFAULT 1,
    current_session_id VARCHAR(100) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await pool.query("ALTER TABLE users ADD COLUMN current_session_id VARCHAR(100) NULL").catch(err => { if (err.code !== 'ER_DUP_FIELDNAME') throw err; });
  await pool.query("ALTER TABLE users MODIFY COLUMN role ENUM('admin','editor','user') NOT NULL DEFAULT 'user'");

  await pool.query(`CREATE TABLE IF NOT EXISTS tools (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(160) NOT NULL,
    url TEXT NOT NULL,
    description TEXT NULL,
    instructions LONGTEXT NULL,
    access_notes LONGTEXT NULL,
    expiry_hours INT NOT NULL DEFAULT 2,
    active TINYINT(1) NOT NULL DEFAULT 1,
    extension_file VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await pool.query(`CREATE TABLE IF NOT EXISTS logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NULL,
    action VARCHAR(100) NOT NULL,
    meta JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_logs_created_at (created_at),
    INDEX idx_logs_user_id (user_id),
    CONSTRAINT fk_logs_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  const [[userCount]] = await pool.query('SELECT COUNT(*) AS total FROM users');
  if (userCount.total === 0) {
    await pool.query(
      'INSERT INTO users (id, name, email, password_hash, role, active) VALUES (?, ?, ?, ?, ?, ?), (?, ?, ?, ?, ?, ?)',
      [
        uuid(), 'Admin', 'admin@example.com', bcrypt.hashSync('ChangeMe123!', 10), 'admin', 1,
        uuid(), 'Demo User', 'user@example.com', bcrypt.hashSync('User123!', 10), 'user', 1
      ]
    );
  }

  const [[toolCount]] = await pool.query('SELECT COUNT(*) AS total FROM tools');
  if (toolCount.total === 0) {
    await pool.query(
      'INSERT INTO tools (id, name, url, description, instructions, access_notes, expiry_hours, active, extension_file) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [uuid(), 'Google Flow', 'https://labs.google/fx/tools/flow', 'Prompt-builder assisted access workflow for Google Flow.', 'Install the approved extension if needed, open the tool, and follow your organization access instructions.', 'Use your assigned login/access method only.', 2, 1, null]
    );
  }
}

function mapUser(row) {
  return row && {
    id: row.id,
    name: row.name,
    email: row.email,
    passwordHash: row.password_hash,
    role: row.role,
    active: !!row.active,
    createdAt: row.created_at
  };
}
function mapTool(row) {
  return row && {
    id: row.id,
    name: row.name,
    url: row.url,
    description: row.description,
    instructions: row.instructions,
    accessNotes: row.access_notes,
    expiryHours: row.expiry_hours,
    active: !!row.active,
    extensionFile: row.extension_file,
    createdAt: row.created_at
  };
}
function mapLog(row) {
  return row && {
    id: row.id,
    userId: row.user_id,
    action: row.action,
    meta: typeof row.meta === 'string' ? JSON.parse(row.meta || '{}') : (row.meta || {}),
    createdAt: row.created_at
  };
}
async function getUsers() { const [rows] = await pool.query('SELECT * FROM users ORDER BY created_at DESC'); return rows.map(mapUser); }
async function getTools(includeInactive = true) {
  const [rows] = await pool.query(`SELECT * FROM tools ${includeInactive ? '' : 'WHERE active = 1'} ORDER BY created_at DESC`);
  return rows.map(mapTool);
}
async function getLogs(limit = 1000) { const [rows] = await pool.query('SELECT * FROM logs ORDER BY created_at DESC LIMIT ?', [limit]); return rows.map(mapLog); }
async function audit(userId, action, meta = {}) { await pool.query('INSERT INTO logs (id, user_id, action, meta) VALUES (?, ?, ?, ?)', [uuid(), userId || null, action, JSON.stringify(meta || {})]); }
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

async function validateSingleSession(req, res, next) {
  if (!req.session.user) return next();
  try {
    const [rows] = await pool.query('SELECT current_session_id, active, role FROM users WHERE id = ? LIMIT 1', [req.session.user.id]);
    const dbUser = rows[0];
    if (!dbUser || !dbUser.active || !req.session.loginToken || dbUser.current_session_id !== req.session.loginToken) {
      return req.session.destroy(() => res.redirect('/login?session=expired'));
    }
    req.session.user.role = dbUser.role;
    res.locals.currentUser = req.session.user;
    next();
  } catch (err) {
    next(err);
  }
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, UPLOAD_DIR),
    filename: (_, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'))
  }),
  limits: { fileSize: 25 * 1024 * 1024 }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(session({ secret: process.env.SESSION_SECRET || 'dev-change-this-secret', resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 8 } }));
app.use(flash());
app.use(expressLayouts);
app.set('layout', 'layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use((req, res, next) => {
  res.locals.appName = APP_NAME;
  res.locals.currentUser = req.session.user || null;
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  next();
});

function requireLogin(req, res, next) { if (!req.session.user) return res.redirect('/login'); next(); }
function requireAdmin(req, res, next) { if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).render('error', { message: 'Admin access required' }); next(); }
function requireToolManager(req, res, next) { if (!req.session.user || !['admin', 'editor'].includes(req.session.user.role)) return res.status(403).render('error', { message: 'Tool management access required' }); next(); }
function requireUser(req, res, next) { if (!req.session.user || req.session.user.role !== 'user') return res.status(403).render('error', { message: 'User access required' }); next(); }
function homeFor(user) {
  if (!user) return '/login';
  if (user.role === 'admin') return '/admin';
  if (user.role === 'editor') return '/admin/tools';
  return '/dashboard';
}
function normalizeRole(role) { return ['admin', 'editor', 'user'].includes(role) ? role : 'user'; }

app.get('/', (req, res) => res.redirect(homeFor(req.session.user)));
app.get('/login', (req, res) => {
  if (req.query.session === 'expired') req.flash('error', 'Your account was logged in on another device, so this session was logged out.');
  res.render('auth/login', { title: 'Login' });
});
app.post('/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await pool.query('SELECT * FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1', [String(email || '')]);
  const user = mapUser(rows[0]);
  if (!user || !user.active || !bcrypt.compareSync(password || '', user.passwordHash)) { req.flash('error', 'Invalid email or password'); return res.redirect('/login'); }
  const loginToken = uuid();
  req.session.loginToken = loginToken;
  req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
  await pool.query('UPDATE users SET current_session_id = ? WHERE id = ?', [loginToken, user.id]);
  await audit(user.id, 'login', { singleSession: true });
  res.redirect(homeFor(user));
}));
app.post('/logout', requireLogin, asyncHandler(async (req, res) => {
  const id = req.session.user.id;
  if (req.session.loginToken) {
    await pool.query('UPDATE users SET current_session_id = NULL WHERE id = ? AND current_session_id = ?', [id, req.session.loginToken]);
  }
  await audit(id, 'logout');
  req.session.destroy(() => res.redirect('/login'));
}));

app.use(validateSingleSession);

app.get('/admin', requireLogin, requireAdmin, asyncHandler(async (req, res) => {
  res.render('admin/dashboard', { title: 'Admin Dashboard', users: await getUsers(), tools: await getTools(), logs: await getLogs(8) });
}));
app.get('/admin/users', requireLogin, requireAdmin, asyncHandler(async (req, res) => res.render('admin/users', { title: 'Users', users: await getUsers() })));
app.post('/admin/users', requireLogin, requireAdmin, asyncHandler(async (req, res) => {
  const { name, email, password, role, active } = req.body;
  const [existing] = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1', [email]);
  if (existing.length) { req.flash('error', 'Email already exists'); return res.redirect('/admin/users'); }
  await pool.query('INSERT INTO users (id, name, email, password_hash, role, active) VALUES (?, ?, ?, ?, ?, ?)', [uuid(), name, email, bcrypt.hashSync(password, 10), normalizeRole(role), active === 'on' ? 1 : 0]);
  await audit(req.session.user.id, 'created_user', { email }); req.flash('success', 'User created'); res.redirect('/admin/users');
}));
app.post('/admin/users/:id/update', requireLogin, requireAdmin, asyncHandler(async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM users WHERE id = ? LIMIT 1', [req.params.id]);
  if (!rows.length) return res.status(404).render('error', { message: 'User not found' });
  const fields = [req.body.name, req.body.email, normalizeRole(req.body.role), req.body.active === 'on' ? 1 : 0];
  let sql = 'UPDATE users SET name = ?, email = ?, role = ?, active = ?';
  if (req.body.password) { sql += ', password_hash = ?'; fields.push(bcrypt.hashSync(req.body.password, 10)); }
  sql += ' WHERE id = ?'; fields.push(req.params.id);
  await pool.query(sql, fields);
  if (req.body.active !== 'on') await pool.query('UPDATE users SET current_session_id = NULL WHERE id = ?', [req.params.id]);
  await audit(req.session.user.id, 'updated_user', { userId: req.params.id }); req.flash('success', 'User updated'); res.redirect('/admin/users');
}));
app.post('/admin/users/:id/delete', requireLogin, requireAdmin, asyncHandler(async (req, res) => {
  if (req.params.id === req.session.user.id) { req.flash('error', 'You cannot delete your own account'); return res.redirect('/admin/users'); }
  await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  await audit(req.session.user.id, 'deleted_user', { userId: req.params.id }); req.flash('success', 'User deleted'); res.redirect('/admin/users');
}));

app.get('/admin/tools', requireLogin, requireToolManager, asyncHandler(async (req, res) => res.render('admin/tools', { title: 'Tools', tools: await getTools() })));
app.post('/admin/tools', requireLogin, requireToolManager, upload.single('extension'), asyncHandler(async (req, res) => {
  const { name, url, description, instructions, accessNotes, expiryHours, active } = req.body;
  await pool.query('INSERT INTO tools (id, name, url, description, instructions, access_notes, expiry_hours, active, extension_file) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [uuid(), name, url, description, instructions, accessNotes, Number(expiryHours || 2), active === 'on' ? 1 : 0, req.file ? req.file.filename : null]);
  await audit(req.session.user.id, 'created_tool', { name }); req.flash('success', 'Tool created'); res.redirect('/admin/tools');
}));
app.post('/admin/tools/:id/update', requireLogin, requireToolManager, upload.single('extension'), asyncHandler(async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM tools WHERE id = ? LIMIT 1', [req.params.id]);
  if (!rows.length) return res.status(404).render('error', { message: 'Tool not found' });
  const extensionFile = req.file ? req.file.filename : rows[0].extension_file;
  await pool.query('UPDATE tools SET name = ?, url = ?, description = ?, instructions = ?, access_notes = ?, expiry_hours = ?, active = ?, extension_file = ? WHERE id = ?', [req.body.name, req.body.url, req.body.description, req.body.instructions, req.body.accessNotes, Number(req.body.expiryHours || 2), req.body.active === 'on' ? 1 : 0, extensionFile, req.params.id]);
  await audit(req.session.user.id, 'updated_tool', { toolId: req.params.id }); req.flash('success', 'Tool updated'); res.redirect('/admin/tools');
}));
app.post('/admin/tools/:id/delete', requireLogin, requireToolManager, asyncHandler(async (req, res) => { await pool.query('DELETE FROM tools WHERE id = ?', [req.params.id]); await audit(req.session.user.id, 'deleted_tool', { toolId: req.params.id }); req.flash('success', 'Tool deleted'); res.redirect('/admin/tools'); }));
app.get('/admin/logs', requireLogin, requireAdmin, asyncHandler(async (req, res) => { res.render('admin/logs', { title: 'Usage Logs', logs: await getLogs(), users: await getUsers(), tools: await getTools() }); }));

app.get('/dashboard', requireLogin, requireUser, asyncHandler(async (req, res) => {
  res.render('user/dashboard', { title: 'Dashboard', tools: await getTools(false) });
}));
app.post('/tools/:id/track', requireLogin, requireUser, asyncHandler(async (req, res) => { await audit(req.session.user.id, 'used_tool', { toolId: req.params.id }); res.json({ ok: true }); }));

app.use((req, res) => res.status(404).render('error', { message: 'Page not found' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', { message: 'Server error: ' + err.message });
});

initDatabase()
  .then(() => app.listen(PORT, () => console.log(`${APP_NAME} running on http://localhost:${PORT}`)))
  .catch(err => {
    console.error('Database startup failed:', err.message);
    console.error('Check .env MySQL settings and make sure MySQL is running.');
    process.exit(1);
  });
