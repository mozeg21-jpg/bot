// ============================================================
// 𝗗𝗢𝗖𝗧𝗢𝗥 𝗖𝗢𝗗𝗘 𝗘𝗟 𝗬𝗢𝗨𝗧𝗨𝗕𝗘𝗥 - Advanced Bot Hosting System
// الخادم الرئيسي مع جميع الوظائف: Auth, Bots, Admin, Multi-Device
// ============================================================

require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs-extra');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const AdmZip = require('adm-zip');
const { v4: uuidv4 } = require('uuid');
const { spawn, exec } = require('child_process');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' }, pingTimeout: 60000 });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'doctorcode_super_secret_key_2025';
const USERS_DIR = path.join(__dirname, 'users');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const DATABASE_DIR = path.join(__dirname, 'database');
const USERS_DB = path.join(DATABASE_DIR, 'users.json');
const REFRESH_DB = path.join(DATABASE_DIR, 'refreshTokens.json');
const LOGS_DB = path.join(DATABASE_DIR, 'logs.json');

fs.ensureDirSync(USERS_DIR);
fs.ensureDirSync(UPLOADS_DIR);
fs.ensureDirSync(DATABASE_DIR);

// تحميل قواعد البيانات
let users = {};
let refreshTokens = {};   // مفتاح: refreshToken, قيمة: { userId, deviceId, deviceName, ip, lastActive }
let logs = [];

function loadDB() {
  if (fs.existsSync(USERS_DB)) users = fs.readJsonSync(USERS_DB);
  if (fs.existsSync(REFRESH_DB)) refreshTokens = fs.readJsonSync(REFRESH_DB);
  if (fs.existsSync(LOGS_DB)) logs = fs.readJsonSync(LOGS_DB);
}
function saveUsers() { fs.writeJsonSync(USERS_DB, users, { spaces: 2 }); }
function saveRefreshTokens() { fs.writeJsonSync(REFRESH_DB, refreshTokens, { spaces: 2 }); }
function saveLogs() { fs.writeJsonSync(LOGS_DB, logs.slice(-2000), { spaces: 2 }); }
loadDB();

// إضافة سجل
function addLog(type, userId, username, action, details = '') {
  const log = { id: uuidv4(), timestamp: new Date().toISOString(), type, userId, username, action, details };
  logs.unshift(log);
  saveLogs();
  io.emit('new_log', log);
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// استخراج IP حقيقي (يدعم الـ proxy)
app.set('trust proxy', true);
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
}

// إعداد multer للـ ZIP
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}_${file.originalname}`)
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/zip' || file.originalname.endsWith('.zip')) cb(null, true);
    else cb(new Error('Only ZIP files allowed'), false);
  }
});

// دوال مساعدة
function getUserDataPath(userId) { return path.join(USERS_DIR, userId); }
async function getUserById(userId) { return users[userId] || null; }

function generateTokens(userId, deviceId, deviceName, ip) {
  const accessToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' });
  const refreshToken = jwt.sign({ userId, deviceId }, JWT_SECRET, { expiresIn: '30d' });
  // تخزين الـ refresh token مع بيانات الجهاز
  refreshTokens[refreshToken] = {
    userId,
    deviceId,
    deviceName: deviceName || 'جهاز غير معروف',
    ip,
    lastActive: Date.now(),
    createdAt: Date.now()
  };
  saveRefreshTokens();
  return { accessToken, refreshToken };
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

// Auth Middleware
function authMiddleware(req, res, next) {
  const token = req.cookies.accessToken;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const decoded = verifyToken(token);
  if (!decoded) return res.status(401).json({ error: 'Invalid token' });
  req.userId = decoded.userId;
  next();
}

async function adminMiddleware(req, res, next) {
  const user = await getUserById(req.userId);
  if (!user || (user.role !== 'admin' && user.role !== 'super_admin')) 
    return res.status(403).json({ error: 'Admin only' });
  next();
}

// إنشاء السوبر أدمن الأول تلقائياً
async function initAdmin() {
  const adminUsername = process.env.ADMIN_USERNAME || 'Ahmed047';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Ahmed047';
  const existing = Object.values(users).find(u => u.username === adminUsername);
  if (!existing) {
    const userId = uuidv4();
    const hashed = await bcrypt.hash(adminPassword, 10);
    users[userId] = {
      userId, username: adminUsername, password: hashed,
      role: 'super_admin', plan: 'premium', status: 'active',
      bots: [], createdAt: new Date().toISOString(), createdBy: 'system'
    };
    await fs.ensureDir(path.join(USERS_DIR, userId, 'bots'));
    saveUsers();
    addLog('system', userId, adminUsername, 'admin_created', 'Super admin created');
    console.log(`✅ Super admin created: ${adminUsername}`);
  }
}
initAdmin();

// ==================== AUTH ROUTES ====================
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (Object.values(users).some(u => u.username === username)) 
    return res.status(400).json({ error: 'Username exists' });
  const userId = uuidv4();
  const hashed = await bcrypt.hash(password, 10);
  users[userId] = {
    userId, username, password: hashed,
    role: 'user', plan: 'free', status: 'active',
    bots: [], createdAt: new Date().toISOString(), createdBy: 'self'
  };
  await fs.ensureDir(path.join(USERS_DIR, userId, 'bots'));
  saveUsers();
  addLog('auth', userId, username, 'register', 'User registered');
  res.json({ success: true, userId });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = Object.values(users).find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.status !== 'active') {
    return res.status(403).json({ error: 'Account banned' });
  }
  // معلومات الجهاز
  const userAgent = req.headers['user-agent'] || 'unknown';
  const ip = getClientIp(req);
  const deviceId = uuidv4();
  const deviceName = `${userAgent.substring(0, 50)}`;
  const { accessToken, refreshToken } = generateTokens(user.userId, deviceId, deviceName, ip);
  res.cookie('accessToken', accessToken, { httpOnly: true, maxAge: 3600000 });
  res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 30*24*3600000 });
  addLog('auth', user.userId, user.username, 'login', `Device: ${deviceName} | IP: ${ip}`);
  res.json({ success: true, role: user.role });
});

app.post('/api/logout', authMiddleware, async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken && refreshTokens[refreshToken]) {
    delete refreshTokens[refreshToken];
    saveRefreshTokens();
  }
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  addLog('auth', req.userId, users[req.userId]?.username, 'logout', '');
  res.json({ success: true });
});

app.post('/api/refresh', (req, res) => {
  const oldRefreshToken = req.cookies.refreshToken;
  if (!oldRefreshToken || !refreshTokens[oldRefreshToken]) 
    return res.status(401).json({ error: 'Invalid refresh' });
  const decoded = verifyToken(oldRefreshToken);
  if (!decoded) return res.status(401).json({ error: 'Invalid token' });
  // تجديد access token فقط
  const newAccessToken = jwt.sign({ userId: decoded.userId }, JWT_SECRET, { expiresIn: '1h' });
  // تحديث lastActive للجهاز
  refreshTokens[oldRefreshToken].lastActive = Date.now();
  saveRefreshTokens();
  res.cookie('accessToken', newAccessToken, { httpOnly: true, maxAge: 3600000 });
  res.json({ success: true });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const user = await getUserById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    userId: user.userId, username: user.username, role: user.role,
    plan: user.plan, status: user.status, bots: user.bots
  });
});

// ==================== DEVICES MANAGEMENT (MULTI-DEVICE) ====================
app.get('/api/devices', authMiddleware, (req, res) => {
  const userId = req.userId;
  const userDevices = Object.entries(refreshTokens)
    .filter(([_, data]) => data.userId === userId)
    .map(([token, data]) => ({
      deviceId: data.deviceId,
      deviceName: data.deviceName,
      ip: data.ip,
      lastActive: data.lastActive,
      createdAt: data.createdAt
    }));
  res.json({ devices: userDevices });
});

app.post('/api/devices/revoke', authMiddleware, (req, res) => {
  const { deviceId } = req.body;
  const userId = req.userId;
  let found = false;
  for (const [token, data] of Object.entries(refreshTokens)) {
    if (data.userId === userId && data.deviceId === deviceId) {
      delete refreshTokens[token];
      found = true;
      break;
    }
  }
  if (found) {
    saveRefreshTokens();
    addLog('auth', userId, users[userId]?.username, 'revoke_device', `Device ${deviceId}`);
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Device not found' });
  }
});

// ==================== BOT MANAGEMENT ====================
const activeProcesses = new Map(); // botId -> { process, userId, botPath, type, entryFile }

app.post('/api/upload', authMiddleware, upload.single('botFile'), async (req, res) => {
  const user = await getUserById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.plan === 'free' && user.bots.length >= 3) 
    return res.status(403).json({ error: 'Free plan max 3 bots' });
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const botId = uuidv4();
  const botPath = path.join(USERS_DIR, req.userId, 'bots', botId);
  await fs.ensureDir(botPath);
  const zip = new AdmZip(req.file.path);
  zip.extractAllTo(botPath, true);
  await fs.remove(req.file.path);

  // كشف النوع وملف الدخول
  let botType = null, entryFile = null;
  const packageJsonPath = path.join(botPath, 'package.json');
  if (await fs.pathExists(packageJsonPath)) {
    try {
      const pkg = await fs.readJson(packageJsonPath);
      if (pkg.main && await fs.pathExists(path.join(botPath, pkg.main))) {
        entryFile = pkg.main; botType = 'node';
      } else {
        const jsFiles = await fs.readdir(botPath);
        const firstJs = jsFiles.find(f => f.endsWith('.js'));
        if (firstJs) { entryFile = firstJs; botType = 'node'; }
      }
    } catch(e) {}
  }
  if (!botType) {
    const ahmedPy = path.join(botPath, 'ahmed.py');
    if (await fs.pathExists(ahmedPy)) {
      botType = 'python'; entryFile = 'ahmed.py';
    } else {
      await fs.remove(botPath);
      return res.status(400).json({ error: 'Invalid Python bot: ahmed.py is required' });
    }
  }
  const botInfo = {
    botId, name: req.file.originalname.replace('.zip', ''), type: botType,
    entryFile, status: 'stopped', pid: null, createdAt: new Date().toISOString()
  };
  user.bots.push(botInfo);
  saveUsers();
  addLog('bot', req.userId, user.username, 'upload', `${botInfo.name} (${botType})`);
  // التثبيت التلقائي
  if (botType === 'node') {
    exec('npm install', { cwd: botPath }, (err) => {
      if (err) addLog('error', req.userId, user.username, 'npm_fail', botInfo.name);
    });
  } else if (botType === 'python') {
    const reqPath = path.join(botPath, 'requirements.txt');
    if (await fs.pathExists(reqPath)) {
      exec('pip3 install -r requirements.txt', { cwd: botPath }, (err) => {
        if (err) addLog('error', req.userId, user.username, 'pip_fail', botInfo.name);
      });
    }
  }
  res.json({ success: true, botId });
});

app.get('/api/bots', authMiddleware, async (req, res) => {
  const user = await getUserById(req.userId);
  res.json({ bots: user.bots || [] });
});

app.post('/api/bot/start', authMiddleware, async (req, res) => {
  const { botId } = req.body;
  const user = await getUserById(req.userId);
  const bot = user.bots.find(b => b.botId === botId);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  if (activeProcesses.has(botId)) return res.status(409).json({ error: 'Already running' });
  const botPath = path.join(USERS_DIR, req.userId, 'bots', botId);
  let child;
  if (bot.type === 'node') child = spawn('node', [bot.entryFile], { cwd: botPath });
  else child = spawn('python3', [bot.entryFile], { cwd: botPath });
  bot.status = 'running'; bot.pid = child.pid;
  saveUsers();
  activeProcesses.set(botId, { process: child, userId: req.userId, botPath, type: bot.type, entryFile: bot.entryFile, botName: bot.name });
  child.stdout.on('data', (data) => io.to(`bot_${botId}`).emit('console_output', { type: 'stdout', data: data.toString(), timestamp: Date.now() }));
  child.stderr.on('data', (data) => io.to(`bot_${botId}`).emit('console_output', { type: 'stderr', data: data.toString(), timestamp: Date.now() }));
  child.on('exit', (code) => {
    activeProcesses.delete(botId);
    bot.status = 'stopped'; bot.pid = null;
    saveUsers();
    io.to(`bot_${botId}`).emit('console_output', { type: 'system', data: `Process exited with code ${code}`, timestamp: Date.now() });
  });
  addLog('bot', req.userId, user.username, 'start_bot', bot.name);
  res.json({ success: true, pid: child.pid });
});

app.post('/api/bot/stop', authMiddleware, async (req, res) => {
  const { botId } = req.body;
  const proc = activeProcesses.get(botId);
  if (proc) { proc.process.kill(); activeProcesses.delete(botId); }
  const user = await getUserById(req.userId);
  const bot = user.bots.find(b => b.botId === botId);
  if (bot) { bot.status = 'stopped'; bot.pid = null; saveUsers(); }
  res.json({ success: true });
});

app.post('/api/bot/restart', authMiddleware, async (req, res) => {
  await fetch(`http://localhost:${PORT}/api/bot/stop`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(req.body) });
  setTimeout(async () => {
    await fetch(`http://localhost:${PORT}/api/bot/start`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(req.body) });
  }, 500);
  res.json({ success: true });
});

app.post('/api/bot/delete', authMiddleware, async (req, res) => {
  const { botId } = req.body;
  const user = await getUserById(req.userId);
  const idx = user.bots.findIndex(b => b.botId === botId);
  if (idx === -1) return res.status(404).json({ error: 'Bot not found' });
  if (activeProcesses.has(botId)) activeProcesses.get(botId).process.kill();
  activeProcesses.delete(botId);
  await fs.remove(path.join(USERS_DIR, req.userId, 'bots', botId));
  user.bots.splice(idx, 1);
  saveUsers();
  res.json({ success: true });
});

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const usersList = Object.values(users).map(u => ({
    userId: u.userId, username: u.username, role: u.role, plan: u.plan,
    status: u.status, botsCount: u.bots.length, createdAt: u.createdAt, createdBy: u.createdBy
  }));
  res.json({ users: usersList });
});

app.post('/api/admin/ban', authMiddleware, adminMiddleware, async (req, res) => {
  const { userId, durationHours } = req.body;
  const target = users[userId];
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.role === 'super_admin') return res.status(403).json({ error: 'Cannot ban super admin' });
  target.status = 'banned';
  target.banExpiry = durationHours ? Date.now() + durationHours * 3600000 : null;
  saveUsers();
  for (const bot of target.bots) {
    if (activeProcesses.has(bot.botId)) activeProcesses.get(bot.botId).process.kill();
    activeProcesses.delete(bot.botId);
  }
  addLog('admin', req.userId, users[req.userId]?.username, 'ban_user', `${target.username} for ${durationHours || 'permanent'}`);
  res.json({ success: true });
});

app.post('/api/admin/unban', authMiddleware, adminMiddleware, async (req, res) => {
  const { userId } = req.body;
  const target = users[userId];
  if (!target) return res.status(404).json({ error: 'User not found' });
  target.status = 'active';
  target.banExpiry = null;
  saveUsers();
  addLog('admin', req.userId, users[req.userId]?.username, 'unban_user', target.username);
  res.json({ success: true });
});

app.post('/api/admin/set-role', authMiddleware, adminMiddleware, async (req, res) => {
  const { userId, role } = req.body;
  const target = users[userId];
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.role === 'super_admin') return res.status(403).json({ error: 'Cannot change super admin' });
  target.role = role;
  saveUsers();
  addLog('admin', req.userId, users[req.userId]?.username, 'change_role', `${target.username} -> ${role}`);
  res.json({ success: true });
});

app.post('/api/admin/create-user', authMiddleware, adminMiddleware, async (req, res) => {
  const { username, password, plan } = req.body;
  if (Object.values(users).some(u => u.username === username)) 
    return res.status(400).json({ error: 'Username exists' });
  const userId = uuidv4();
  const hashed = await bcrypt.hash(password, 10);
  users[userId] = {
    userId, username, password: hashed, role: 'user', plan: plan || 'free',
    status: 'active', bots: [], createdAt: new Date().toISOString(), createdBy: users[req.userId].username
  };
  await fs.ensureDir(path.join(USERS_DIR, userId, 'bots'));
  saveUsers();
  addLog('admin', req.userId, users[req.userId]?.username, 'create_user', username);
  res.json({ success: true, userId });
});

app.get('/api/admin/user-files/:userId', authMiddleware, adminMiddleware, async (req, res) => {
  const { userId } = req.params;
  const botsDir = path.join(USERS_DIR, userId, 'bots');
  if (!await fs.pathExists(botsDir)) return res.json({ files: [] });
  const folders = await fs.readdir(botsDir);
  const filesList = [];
  for (const botId of folders) {
    const stat = await fs.stat(path.join(botsDir, botId));
    filesList.push({ name: botId, path: path.join(botsDir, botId), type: 'folder', size: stat.size, modified: stat.mtime });
  }
  res.json({ files: filesList });
});

app.get('/api/admin/logs', authMiddleware, adminMiddleware, (req, res) => {
  res.json({ logs: logs.slice(0, 300) });
});

// ==================== SOCKET.IO ====================
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));
  const decoded = verifyToken(token);
  if (!decoded) return next(new Error('Invalid token'));
  socket.userId = decoded.userId;
  next();
}).on('connection', (socket) => {
  socket.on('join_bot', (botId) => socket.join(`bot_${botId}`));
  socket.on('leave_bot', (botId) => socket.leave(`bot_${botId}`));
});

// ==================== SERVE HTML PAGES ====================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/upload', (req, res) => res.sendFile(path.join(__dirname, 'public', 'upload.html')));
app.get('/bots', (req, res) => res.sendFile(path.join(__dirname, 'public', 'bots.html')));
app.get('/console', (req, res) => res.sendFile(path.join(__dirname, 'public', 'console.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/devices', (req, res) => res.sendFile(path.join(__dirname, 'public', 'devices.html')));

server.listen(PORT, () => {
  console.log(`🚀 Doctor Code Bot Hosting running on http://localhost:${PORT}`);
});