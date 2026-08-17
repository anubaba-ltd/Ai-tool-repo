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
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_NAME = process.env.APP_NAME || 'Safe Tool Portal';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-change-this-secret';
const EXTENSION_SESSION_HOURS = Math.max(1, Number(process.env.EXTENSION_SESSION_HOURS || 2));
const EXTENSION_ACTIVATION_TTL_SECONDS = 60;
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

async function ignoreDuplicateColumn(sql) {
  try { await pool.query(sql); }
  catch (err) { if (err.code !== 'ER_DUP_FIELDNAME') throw err; }
}

async function initDatabase() {
  // On shared hosting the database usually already exists and the DB user may not
  // have CREATE DATABASE permission. Try it, but continue with the configured DB.
  try {
    const adminConn = await mysql.createConnection({
      host: dbConfig.host, port: dbConfig.port, user: dbConfig.user,
      password: dbConfig.password, charset: 'utf8mb4'
    });
    try {
      await adminConn.query(`CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    } catch (err) {
      if (!['ER_DBACCESS_DENIED_ERROR','ER_ACCESS_DENIED_ERROR'].includes(err.code)) throw err;
    }
    await adminConn.end();
  } catch (err) {
    if (!['ER_DBACCESS_DENIED_ERROR','ER_ACCESS_DENIED_ERROR'].includes(err.code)) throw err;
  }

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
  await ignoreDuplicateColumn('ALTER TABLE users ADD COLUMN current_session_id VARCHAR(100) NULL');
  await pool.query("ALTER TABLE users MODIFY COLUMN role ENUM('admin','editor','user') NOT NULL DEFAULT 'user'");

  await pool.query(`CREATE TABLE IF NOT EXISTS extension_sessions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id VARCHAR(36) NOT NULL,
    device_id VARCHAR(255) NOT NULL,
    session_token_hash VARCHAR(255) NOT NULL,
    uninstall_token_hash VARCHAR(255) NULL,
    portal_session_id VARCHAR(100) NULL,
    browser_name VARCHAR(100) DEFAULT NULL,
    extension_version VARCHAR(50) DEFAULT NULL,
    last_heartbeat TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL DEFAULT NULL,
    active TINYINT(1) NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY unique_user_session (user_id),
    KEY idx_device_id (device_id),
    KEY idx_session_token (session_token_hash),
    KEY idx_last_heartbeat (last_heartbeat)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  await pool.query('ALTER TABLE extension_sessions MODIFY COLUMN user_id VARCHAR(36) NOT NULL');
  await ignoreDuplicateColumn('ALTER TABLE extension_sessions ADD COLUMN uninstall_token_hash VARCHAR(255) NULL AFTER session_token_hash');
  await ignoreDuplicateColumn('ALTER TABLE extension_sessions ADD COLUMN portal_session_id VARCHAR(100) NULL AFTER uninstall_token_hash');

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
      [uuid(), 'Admin', 'admin@example.com', bcrypt.hashSync('ChangeMe123!', 10), 'admin', 1,
       uuid(), 'Demo User', 'user@example.com', bcrypt.hashSync('User123!', 10), 'user', 1]
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

function mapUser(row) { return row && { id: row.id, name: row.name, email: row.email, passwordHash: row.password_hash, role: row.role, active: !!row.active, createdAt: row.created_at }; }
function mapTool(row) { return row && { id: row.id, name: row.name, url: row.url, description: row.description, instructions: row.instructions, accessNotes: row.access_notes, expiryHours: row.expiry_hours, active: !!row.active, extensionFile: row.extension_file, createdAt: row.created_at }; }
function mapLog(row) { return row && { id: row.id, userId: row.user_id, action: row.action, meta: typeof row.meta === 'string' ? JSON.parse(row.meta || '{}') : (row.meta || {}), createdAt: row.created_at }; }
async function getUsers() { const [rows] = await pool.query('SELECT * FROM users ORDER BY created_at DESC'); return rows.map(mapUser); }
async function getTools(includeInactive = true) { const [rows] = await pool.query(`SELECT * FROM tools ${includeInactive ? '' : 'WHERE active = 1'} ORDER BY created_at DESC`); return rows.map(mapTool); }
async function getLogs(limit = 1000) { const [rows] = await pool.query('SELECT * FROM logs ORDER BY created_at DESC LIMIT ?', [limit]); return rows.map(mapLog); }
async function audit(userId, action, meta = {}) { await pool.query('INSERT INTO logs (id, user_id, action, meta) VALUES (?, ?, ?, ?)', [uuid(), userId || null, action, JSON.stringify(meta || {})]); }
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function hashToken(token) { return crypto.createHash('sha256').update(String(token || '')).digest('hex'); }
function getBearer(req) { const auth = req.get('authorization') || ''; return auth.startsWith('Bearer ') ? auth.slice(7).trim() : null; }
function signActivation(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyActivation(token) {
  try {
    const [body, sig] = String(token || '').split('.');
    if (!body || !sig) return null;
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
    const a = Buffer.from(sig); const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.uid || !payload.sid || !payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch (_) { return null; }
}

async function validateSingleSession(req, res, next) {
  if (!req.session.user) return next();
  try {
    const [rows] = await pool.query('SELECT current_session_id, active, role FROM users WHERE id = ? LIMIT 1', [req.session.user.id]);
    const dbUser = rows[0];
    if (!dbUser || !dbUser.active || !req.session.loginToken || dbUser.current_session_id !== req.session.loginToken) {
      if (req.session.loginToken) await pool.query('UPDATE extension_sessions SET active = 0 WHERE user_id = ? AND portal_session_id = ?', [req.session.user.id, req.session.loginToken]).catch(()=>{});
      return req.session.destroy(() => res.redirect('/login?session=expired'));
    }
    req.session.user.role = dbUser.role;
    res.locals.currentUser = req.session.user;
    next();
  } catch (err) { next(err); }
}

const upload = multer({
  storage: multer.diskStorage({ destination: (_, __, cb) => cb(null, UPLOAD_DIR), filename: (_, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')) }),
  limits: { fileSize: 25 * 1024 * 1024 }
});

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(session({
  secret: SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 8 }
}));
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
function requireToolManager(req, res, next) { if (!req.session.user || !['admin','editor'].includes(req.session.user.role)) return res.status(403).render('error', { message: 'Tool management access required' }); next(); }
function requireUser(req, res, next) { if (!req.session.user || req.session.user.role !== 'user') return res.status(403).render('error', { message: 'User access required' }); next(); }
function homeFor(user) { if (!user) return '/login'; if (user.role === 'admin') return '/admin'; if (user.role === 'editor') return '/admin/tools'; return '/dashboard'; }
function normalizeRole(role) { return ['admin','editor','user'].includes(role) ? role : 'user'; }

app.get('/', (req, res) => res.redirect(homeFor(req.session.user)));
app.get('/login', (req, res) => {
  if (req.query.session === 'expired') res.locals.error = ['Your account was logged in on another device, so this session was logged out.'];
  if (req.query.extension === 'missing' || req.query.extension === 'required') res.locals.error = ['The AIANUBABA extension is required. Install/enable it, then log in again.'];
  if (req.query.extension === 'removed') res.locals.error = ['The AIANUBABA extension was removed, so the protected session was signed out.'];
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
  await pool.query('UPDATE extension_sessions SET active = 0 WHERE user_id = ?', [user.id]);
  await audit(user.id, 'login', { singleSession: true });
  res.redirect(homeFor(user));
}));
app.post('/logout', requireLogin, asyncHandler(async (req, res) => {
  const id = req.session.user.id;
  await pool.query('UPDATE extension_sessions SET active = 0 WHERE user_id = ?', [id]);
  if (req.session.loginToken) await pool.query('UPDATE users SET current_session_id = NULL WHERE id = ? AND current_session_id = ?', [id, req.session.loginToken]);
  await audit(id, 'logout');
  req.session.destroy(() => res.redirect('/login'));
}));

// ----- Chrome extension CORS -----
app.use('/api/extension', (req, res, next) => {
  const origin = req.get('origin');
  const configured = process.env.EXTENSION_ORIGIN;
  if (origin) {
    const allowed = configured ? origin === configured : origin.startsWith('chrome-extension://');
    if (allowed) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Vary', 'Origin'); }
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Extension activates only from a short-lived token created by an already logged-in portal session.
app.post('/api/extension/activate', asyncHandler(async (req, res) => {
  const { activationToken, deviceId, browserName, extensionVersion } = req.body || {};
  const activation = verifyActivation(activationToken);
  if (!activation || !deviceId) return res.status(401).json({ ok: false, code: 'INVALID_ACTIVATION', error: 'Portal activation expired. Refresh the dashboard.' });

  const [rows] = await pool.query('SELECT id, name, email, active, current_session_id FROM users WHERE id = ? LIMIT 1', [activation.uid]);
  const user = rows[0];
  if (!user || !user.active || user.current_session_id !== activation.sid) return res.status(401).json({ ok: false, code: 'PORTAL_SESSION_REPLACED', error: 'Portal session is no longer active.' });

  const rawToken = crypto.randomBytes(32).toString('hex');
  const uninstallToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + EXTENSION_SESSION_HOURS * 60 * 60 * 1000);
  await pool.query(`
    INSERT INTO extension_sessions (user_id, device_id, session_token_hash, uninstall_token_hash, portal_session_id, browser_name, extension_version, last_heartbeat, created_at, expires_at, active)
    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, 1)
    ON DUPLICATE KEY UPDATE device_id=VALUES(device_id), session_token_hash=VALUES(session_token_hash), uninstall_token_hash=VALUES(uninstall_token_hash), portal_session_id=VALUES(portal_session_id), browser_name=VALUES(browser_name), extension_version=VALUES(extension_version), last_heartbeat=CURRENT_TIMESTAMP, created_at=CURRENT_TIMESTAMP, expires_at=VALUES(expires_at), active=1
  `, [user.id, String(deviceId), hashToken(rawToken), hashToken(uninstallToken), activation.sid, browserName || null, extensionVersion || null, expiresAt]);
  await audit(user.id, 'extension_activated', { deviceId: String(deviceId), browserName: browserName || null, extensionVersion: extensionVersion || null });
  res.json({ ok: true, token: rawToken, uninstallToken, expiresAt, user: { id: user.id, name: user.name, email: user.email } });
}));

app.post('/api/extension/heartbeat', asyncHandler(async (req, res) => {
  const token = getBearer(req); const { deviceId, browserName, extensionVersion, reason } = req.body || {};
  if (!token || !deviceId) return res.status(401).json({ ok: false, code: 'AUTH_REQUIRED' });
  const [rows] = await pool.query(`
    SELECT es.*, u.active AS user_active, u.current_session_id, u.name, u.email
    FROM extension_sessions es INNER JOIN users u ON u.id = es.user_id
    WHERE es.session_token_hash = ? LIMIT 1
  `, [hashToken(token)]);
  const s = rows[0];
  if (!s) return res.status(401).json({ ok: false, code: 'SESSION_REPLACED', error: 'This extension session was replaced.' });
  if (!s.user_active) { await pool.query('UPDATE extension_sessions SET active=0 WHERE id=?', [s.id]); return res.status(401).json({ ok: false, code: 'USER_DISABLED' }); }
  if (!s.active) return res.status(401).json({ ok: false, code: 'SESSION_DISABLED' });
  if (String(s.device_id) !== String(deviceId)) return res.status(401).json({ ok: false, code: 'DEVICE_MISMATCH' });
  if (!s.portal_session_id || s.current_session_id !== s.portal_session_id) { await pool.query('UPDATE extension_sessions SET active=0 WHERE id=?', [s.id]); return res.status(401).json({ ok: false, code: 'PORTAL_SESSION_REPLACED', error: 'The portal account is active on another browser/device.' }); }
  if (s.expires_at && new Date(s.expires_at).getTime() <= Date.now()) { await pool.query('UPDATE extension_sessions SET active=0 WHERE id=?', [s.id]); return res.status(401).json({ ok: false, code: 'SESSION_EXPIRED' }); }
  await pool.query('UPDATE extension_sessions SET last_heartbeat=CURRENT_TIMESTAMP, browser_name=?, extension_version=? WHERE id=?', [browserName || s.browser_name, extensionVersion || s.extension_version, s.id]);
  res.json({ ok: true, active: true, expiresAt: s.expires_at, serverTime: new Date().toISOString(), user: { id: s.user_id, name: s.name, email: s.email }, reason: reason || null });
}));

app.post('/api/extension/logout', asyncHandler(async (req, res) => {
  const token = getBearer(req); const { deviceId } = req.body || {};
  if (token) await pool.query('UPDATE extension_sessions SET active=0 WHERE session_token_hash=? AND device_id=?', [hashToken(token), String(deviceId || '')]);
  res.json({ ok: true });
}));

// Chrome opens this URL after uninstall. It revokes the server extension session and, when the same portal cookie is present, signs out the portal session too.
app.get('/api/extension/uninstalled', asyncHandler(async (req, res) => {
  const { token, device } = req.query;
  if (!token || !device) return res.redirect('/login?extension=removed');
  const [rows] = await pool.query('SELECT user_id, portal_session_id FROM extension_sessions WHERE uninstall_token_hash=? AND device_id=? LIMIT 1', [hashToken(token), String(device)]);
  const s = rows[0];
  if (s) {
    await pool.query('UPDATE extension_sessions SET active=0 WHERE uninstall_token_hash=? AND device_id=?', [hashToken(token), String(device)]);
    await audit(s.user_id, 'extension_uninstalled', { deviceId: String(device) }).catch(()=>{});
    if (req.session?.user?.id === s.user_id && req.session.loginToken === s.portal_session_id) {
      await pool.query('UPDATE users SET current_session_id=NULL WHERE id=? AND current_session_id=?', [s.user_id, s.portal_session_id]);
      return req.session.destroy(() => res.redirect('/login?extension=removed'));
    }
  }
  res.redirect('/login?extension=removed');
}));

// All website routes below this point verify the one-browser portal session.
app.use(validateSingleSession);

app.get('/api/extension/bootstrap', requireLogin, requireUser, (req, res) => {
  const payload = { uid: req.session.user.id, sid: req.session.loginToken, exp: Date.now() + EXTENSION_ACTIVATION_TTL_SECONDS * 1000, nonce: crypto.randomBytes(12).toString('hex') };
  res.json({ ok: true, activationToken: signActivation(payload), expiresInSeconds: EXTENSION_ACTIVATION_TTL_SECONDS });
});

app.get('/api/extension/web-status', requireLogin, asyncHandler(async (req, res) => {
  const [rows] = await pool.query('SELECT device_id,browser_name,extension_version,last_heartbeat,expires_at,active,portal_session_id FROM extension_sessions WHERE user_id=? LIMIT 1', [req.session.user.id]);
  const s = rows[0];
  if (!s) return res.json({ ok: true, active: false });
  const age = s.last_heartbeat ? Date.now() - new Date(s.last_heartbeat).getTime() : Infinity;
  const notExpired = !s.expires_at || new Date(s.expires_at).getTime() > Date.now();
  res.json({ ok: true, active: !!s.active && s.portal_session_id === req.session.loginToken && notExpired && age <= 15000, browserName: s.browser_name || null, extensionVersion: s.extension_version || null, lastHeartbeat: s.last_heartbeat || null, expiresAt: s.expires_at || null });
}));

app.post('/api/session/extension-missing', requireLogin, asyncHandler(async (req, res) => {
  const id = req.session.user.id; const loginToken = req.session.loginToken;
  await pool.query('UPDATE extension_sessions SET active=0 WHERE user_id=?', [id]);
  await pool.query('UPDATE users SET current_session_id=NULL WHERE id=? AND current_session_id=?', [id, loginToken]);
  await audit(id, 'extension_missing_forced_logout', { reason: req.body?.reason || 'missing' });
  req.session.destroy(() => res.json({ ok: true }));
}));

app.get('/admin', requireLogin, requireAdmin, asyncHandler(async (req, res) => res.render('admin/dashboard', { title: 'Admin Dashboard', users: await getUsers(), tools: await getTools(), logs: await getLogs(8) })));
app.get('/admin/users', requireLogin, requireAdmin, asyncHandler(async (req, res) => res.render('admin/users', { title: 'Users', users: await getUsers() })));
app.post('/admin/users', requireLogin, requireAdmin, asyncHandler(async (req, res) => {
  const { name, email, password, role, active } = req.body;
  const [existing] = await pool.query('SELECT id FROM users WHERE LOWER(email)=LOWER(?) LIMIT 1', [email]);
  if (existing.length) { req.flash('error','Email already exists'); return res.redirect('/admin/users'); }
  await pool.query('INSERT INTO users (id,name,email,password_hash,role,active) VALUES (?,?,?,?,?,?)', [uuid(),name,email,bcrypt.hashSync(password,10),normalizeRole(role),active==='on'?1:0]);
  await audit(req.session.user.id,'created_user',{email}); req.flash('success','User created'); res.redirect('/admin/users');
}));
app.post('/admin/users/:id/update', requireLogin, requireAdmin, asyncHandler(async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM users WHERE id=? LIMIT 1',[req.params.id]); if (!rows.length) return res.status(404).render('error',{message:'User not found'});
  const fields=[req.body.name,req.body.email,normalizeRole(req.body.role),req.body.active==='on'?1:0]; let sql='UPDATE users SET name=?, email=?, role=?, active=?';
  if(req.body.password){sql+=', password_hash=?';fields.push(bcrypt.hashSync(req.body.password,10));} sql+=' WHERE id=?';fields.push(req.params.id); await pool.query(sql,fields);
  if(req.body.active!=='on'){await pool.query('UPDATE users SET current_session_id=NULL WHERE id=?',[req.params.id]);await pool.query('UPDATE extension_sessions SET active=0 WHERE user_id=?',[req.params.id]);}
  await audit(req.session.user.id,'updated_user',{userId:req.params.id}); req.flash('success','User updated'); res.redirect('/admin/users');
}));
app.post('/admin/users/:id/delete', requireLogin, requireAdmin, asyncHandler(async (req, res) => {
  if(req.params.id===req.session.user.id){req.flash('error','You cannot delete your own account');return res.redirect('/admin/users');}
  await pool.query('DELETE FROM extension_sessions WHERE user_id=?',[req.params.id]); await pool.query('DELETE FROM users WHERE id=?',[req.params.id]); await audit(req.session.user.id,'deleted_user',{userId:req.params.id}); req.flash('success','User deleted'); res.redirect('/admin/users');
}));

app.get('/admin/tools', requireLogin, requireToolManager, asyncHandler(async (req,res)=>res.render('admin/tools',{title:'Tools',tools:await getTools()})));
app.post('/admin/tools', requireLogin, requireToolManager, upload.single('extension'), asyncHandler(async (req,res)=>{const{name,url,description,instructions,accessNotes,expiryHours,active}=req.body;await pool.query('INSERT INTO tools (id,name,url,description,instructions,access_notes,expiry_hours,active,extension_file) VALUES (?,?,?,?,?,?,?,?,?)',[uuid(),name,url,description,instructions,accessNotes,Number(expiryHours||2),active==='on'?1:0,req.file?req.file.filename:null]);await audit(req.session.user.id,'created_tool',{name});req.flash('success','Tool created');res.redirect('/admin/tools');}));
app.post('/admin/tools/:id/update', requireLogin, requireToolManager, upload.single('extension'), asyncHandler(async (req,res)=>{const[rows]=await pool.query('SELECT * FROM tools WHERE id=? LIMIT 1',[req.params.id]);if(!rows.length)return res.status(404).render('error',{message:'Tool not found'});const extensionFile=req.file?req.file.filename:rows[0].extension_file;await pool.query('UPDATE tools SET name=?,url=?,description=?,instructions=?,access_notes=?,expiry_hours=?,active=?,extension_file=? WHERE id=?',[req.body.name,req.body.url,req.body.description,req.body.instructions,req.body.accessNotes,Number(req.body.expiryHours||2),req.body.active==='on'?1:0,extensionFile,req.params.id]);await audit(req.session.user.id,'updated_tool',{toolId:req.params.id});req.flash('success','Tool updated');res.redirect('/admin/tools');}));
app.post('/admin/tools/:id/delete', requireLogin, requireToolManager, asyncHandler(async (req,res)=>{await pool.query('DELETE FROM tools WHERE id=?',[req.params.id]);await audit(req.session.user.id,'deleted_tool',{toolId:req.params.id});req.flash('success','Tool deleted');res.redirect('/admin/tools');}));
app.get('/admin/logs', requireLogin, requireAdmin, asyncHandler(async (req,res)=>res.render('admin/logs',{title:'Usage Logs',logs:await getLogs(),users:await getUsers(),tools:await getTools()})));

app.get('/dashboard', requireLogin, requireUser, asyncHandler(async (req,res)=>res.render('user/dashboard',{title:'Dashboard',tools:await getTools(false)})));
app.post('/tools/:id/track', requireLogin, requireUser, asyncHandler(async (req,res)=>{await audit(req.session.user.id,'used_tool',{toolId:req.params.id});res.json({ok:true});}));

app.use((req,res)=>res.status(404).render('error',{message:'Page not found'}));
app.use((err,req,res,next)=>{console.error(err);res.status(500).render('error',{message:'Server error: '+err.message});});

initDatabase().then(()=>app.listen(PORT,()=>console.log(`${APP_NAME} running on port ${PORT}`))).catch(err=>{console.error('Database startup failed:',err);process.exit(1);});
