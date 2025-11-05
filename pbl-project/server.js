require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const { v4: uuidv4 } = require('uuid');
const client = require('prom-client');
const { z } = require('zod');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();

// Correlation ID
app.use((req, res, next) => {
  const id = req.headers['x-request-id'] || uuidv4();
  req.id = id;
  res.setHeader('X-Request-Id', id);
  next();
});

// Logs & security & performance
app.use(morgan('combined'));
app.use(helmet());
app.use(compression());

// CORS tightened via env; allow '*' to keep local file usage
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN }));
app.use(express.json());

// Basic rate limit
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: Number(process.env.RATE_LIMIT_MAX || 300) });
app.use(limiter);

const dbPath = path.join(__dirname, 'db.sqlite');
const db = new Database(dbPath);

// Prometheus metrics
client.collectDefaultMetrics();
// SQLite pragmas & safety
try { db.pragma('foreign_keys = ON'); } catch(_) {}

// Create tables if they don't exist
db.prepare(`
CREATE TABLE IF NOT EXISTS teams (
  team_id TEXT PRIMARY KEY,
  team_name TEXT,
  country_name TEXT,
  team_rank INTEGER,
  no_of_wins INTEGER DEFAULT 0,
  no_of_loses INTEGER DEFAULT 0,
  no_of_draws INTEGER DEFAULT 0,
  deleted_at TEXT
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS players (
  player_id TEXT PRIMARY KEY,
  player_name TEXT,
  team_id TEXT,
  batting_average REAL,
  no_of_totalruns INTEGER DEFAULT 0,
  no_of_wickets INTEGER DEFAULT 0,
  type_of_bowler TEXT,
  no_of_sixes INTEGER DEFAULT 0,
  economy REAL DEFAULT NULL,
  deleted_at TEXT
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS matches (
  match_id TEXT PRIMARY KEY,
  match_date TEXT,
  match_time TEXT,
  team_1_name TEXT,
  team_2_name TEXT,
  winner TEXT,
  stadium TEXT,
  deleted_at TEXT
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS umpires (
  umpire_id TEXT PRIMARY KEY,
  umpire_name TEXT,
  country TEXT,
  no_of_matches INTEGER DEFAULT 0,
  deleted_at TEXT
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password_salt TEXT,
  password_hash TEXT,
  role TEXT DEFAULT 'viewer'
)`).run();

// Migration: ensure 'role' column exists for existing databases created before RBAC
try {
  const cols = db.prepare("PRAGMA table_info(users)").all();
  const hasRole = cols.some(c => c.name === 'role');
  if (!hasRole) {
    db.prepare("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'viewer'").run();
  }

  // Backfill any NULL roles to 'viewer'
  db.prepare("UPDATE users SET role='viewer' WHERE role IS NULL").run();
} catch (_) {
  // ignore migration errors; app will surface if something is wrong
}

// Zod schemas for stricter validation (with coercion for numeric form values)
const zodSchemas = {
  teams: z.object({
    team_id: z.string().min(1).nullable().optional(),
    team_name: z.string().min(1).nullable().optional(),
    country_name: z.string().min(1).nullable().optional(),
    team_rank: z.coerce.number().int().nonnegative().nullable().optional(),
    no_of_wins: z.coerce.number().int().nonnegative().nullable().optional(),
    no_of_loses: z.coerce.number().int().nonnegative().nullable().optional(),
    no_of_draws: z.coerce.number().int().nonnegative().nullable().optional()
  }),
  players: z.object({
    player_id: z.string().min(1).nullable().optional(),
    player_name: z.string().min(1).nullable().optional(),
    team_id: z.string().min(1).nullable().optional(),
    batting_average: z.coerce.number().nullable().optional(),
    no_of_totalruns: z.coerce.number().int().nonnegative().nullable().optional(),
    no_of_wickets: z.coerce.number().int().nonnegative().nullable().optional(),
    type_of_bowler: z.string().nullable().optional(),
    no_of_sixes: z.coerce.number().int().nonnegative().nullable().optional(),
    economy: z.coerce.number().nullable().optional()
  }),
  matches: z.object({
    match_id: z.string().min(1).nullable().optional(),
    match_date: z.string().min(1).nullable().optional(),
    match_time: z.string().min(1).nullable().optional(),
    team_1_name: z.string().min(1).nullable().optional(),
    team_2_name: z.string().min(1).nullable().optional(),
    winner: z.string().nullable().optional(),
    stadium: z.string().nullable().optional()
  }),
  umpires: z.object({
    umpire_id: z.string().min(1).nullable().optional(),
    umpire_name: z.string().min(1).nullable().optional(),
    country: z.string().min(1).nullable().optional(),
    no_of_matches: z.coerce.number().int().nonnegative().nullable().optional()
  })
};
// Migrations: add deleted_at columns if missing
['teams','players','matches','umpires'].forEach(tbl => {
  try {
    const cols = db.prepare(`PRAGMA table_info(${tbl})`).all();
    if (!cols.some(c=>c.name==='deleted_at')) {
      db.prepare(`ALTER TABLE ${tbl} ADD COLUMN deleted_at TEXT`).run();
    }
  } catch(_) {}
});

// Audit logs table
db.prepare(`
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor TEXT,
  action TEXT,
  entity TEXT,
  entity_id TEXT,
  at TEXT,
  payload TEXT
)`).run();

// Indexes
db.prepare('CREATE INDEX IF NOT EXISTS idx_players_team ON players(team_id)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_players_runs ON players(no_of_totalruns)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_players_wkts ON players(no_of_wickets)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_players_name ON players(player_name)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_teams_name ON teams(team_name)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_teams_country ON teams(country_name)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_matches_t1 ON matches(team_1_name)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_matches_t2 ON matches(team_2_name)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_matches_winner ON matches(winner)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_matches_date ON matches(match_date)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_umpires_country ON umpires(country)').run();

// Integrity triggers: ensure players.team_id references an existing, non-deleted team
try {
  db.prepare(`
  CREATE TRIGGER IF NOT EXISTS trg_players_team_fk_ins
  BEFORE INSERT ON players
  WHEN NEW.team_id IS NOT NULL AND (SELECT COUNT(1) FROM teams t WHERE t.team_id = NEW.team_id AND t.deleted_at IS NULL) = 0
  BEGIN
    SELECT RAISE(ABORT, 'Invalid team_id');
  END;`).run();
  db.prepare(`
  CREATE TRIGGER IF NOT EXISTS trg_players_team_fk_upd
  BEFORE UPDATE OF team_id ON players
  WHEN NEW.team_id IS NOT NULL AND (SELECT COUNT(1) FROM teams t WHERE t.team_id = NEW.team_id AND t.deleted_at IS NULL) = 0
  BEGIN
    SELECT RAISE(ABORT, 'Invalid team_id');
  END;`).run();
} catch(_) {}

// Full-text search for players (name, type, team)
try {
  db.prepare(`CREATE VIRTUAL TABLE IF NOT EXISTS players_fts USING fts5(player_name, type_of_bowler, team_id, content='players', content_rowid='rowid')`).run();
  // Sync triggers for FTS
  db.prepare(`
  CREATE TRIGGER IF NOT EXISTS trg_players_ai AFTER INSERT ON players BEGIN
    INSERT INTO players_fts(rowid, player_name, type_of_bowler, team_id)
    VALUES (new.rowid, new.player_name, new.type_of_bowler, new.team_id);
  END;`).run();
  db.prepare(`
  CREATE TRIGGER IF NOT EXISTS trg_players_ad AFTER DELETE ON players BEGIN
    INSERT INTO players_fts(players_fts, rowid, player_name, type_of_bowler, team_id)
    VALUES ('delete', old.rowid, old.player_name, old.type_of_bowler, old.team_id);
  END;`).run();
  db.prepare(`
  CREATE TRIGGER IF NOT EXISTS trg_players_au AFTER UPDATE ON players BEGIN
    INSERT INTO players_fts(players_fts, rowid, player_name, type_of_bowler, team_id)
    VALUES ('delete', old.rowid, old.player_name, old.type_of_bowler, old.team_id);
    INSERT INTO players_fts(rowid, player_name, type_of_bowler, team_id)
    VALUES (new.rowid, new.player_name, new.type_of_bowler, new.team_id);
  END;`).run();
} catch(_) {}

// helper responses
function ok(res, data, code = 200) { res.status(code).json({ success: true, data }); }
function err(res, message, code = 400) { res.status(code).json({ success: false, error: message }); }

// JWT helpers
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
function signAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '1h' });
}

// Auth middlewares
function requireAuth(req, res, next) {
  try {
    const auth = req.headers['authorization'] || '';
    if (!auth.startsWith('Bearer ')) return err(res, 'Unauthorized', 401);
    const token = auth.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { username: decoded.username, role: decoded.role };
    next();
  } catch (e) {
    return err(res, 'Unauthorized', 401);
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return err(res, 'Unauthorized', 401);
    if (req.user.role !== role) return err(res, 'Forbidden', 403);
    next();
  };
}

function hashPassword(password, salt) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  return hash.toString('hex');
}

const resetTokens = new Map(); // username -> { token, expiresAt } (dev only)

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return err(res, 'Missing credentials');
    const existing = db.prepare('SELECT username FROM users WHERE username = ?').get(username);
    if (existing) return err(res, 'User already exists');
    // argon2 for new users
    const pwdHash = await argon2.hash(String(password));
    const userCount = db.prepare('SELECT COUNT(*) as c FROM users').pluck().get();
    const role = userCount === 0 ? 'admin' : 'viewer';
    db.prepare('INSERT INTO users (username, password_salt, password_hash, role) VALUES (?, ?, ?, ?)').run(username, null, pwdHash, role);
    ok(res, null, 201);
  } catch (e) { err(res, e.message); }
});

// New: leaderboards analytics (top performers)
app.get('/api/analytics/leaderboards', (req, res) => {
  try {
    const topRuns = db.prepare('SELECT player_id, player_name, no_of_totalruns FROM players WHERE deleted_at IS NULL ORDER BY no_of_totalruns DESC NULLS LAST LIMIT 5').all();
    const topWickets = db.prepare('SELECT player_id, player_name, no_of_wickets FROM players WHERE deleted_at IS NULL ORDER BY no_of_wickets DESC NULLS LAST LIMIT 5').all();
    const topTeamsByWins = db.prepare('SELECT team_id, team_name, no_of_wins FROM teams WHERE deleted_at IS NULL ORDER BY no_of_wins DESC NULLS LAST LIMIT 5').all();
    ok(res, { topRuns, topWickets, topTeamsByWins });
  } catch (e) { err(res, e.message); }
});

// New: FTS search endpoint for players
app.get('/api/search/players', (req, res) => {
  try {
    const { q = '', limit = 10, offset = 0 } = req.query || {};
    const lim = Math.max(0, Math.min(parseInt(limit, 10) || 0, 100));
    const off = Math.max(0, parseInt(offset, 10) || 0);
    const like = String(q || '').trim();
    if (!like) return ok(res, { items: [], total: 0 });
    const items = db.prepare(`
      SELECT p.*
      FROM players p
      JOIN players_fts f ON f.rowid = p.rowid
      WHERE players_fts MATCH @term AND p.deleted_at IS NULL
      LIMIT ${lim} OFFSET ${off}
    `).all({ term: like });
    const total = db.prepare(`
      SELECT COUNT(*) as c
      FROM players p
      JOIN players_fts f ON f.rowid = p.rowid
      WHERE players_fts MATCH @term AND p.deleted_at IS NULL
    `).pluck().get({ term: like });
    try { res.set('X-Total-Count', String(total)); } catch(_) {}
    ok(res, { items, total });
  } catch (e) { err(res, e.message); }
});

// Health check endpoint for smoother ops
app.get('/health', (req, res) => {
  try {
    const now = new Date().toISOString();
    const okDb = db.prepare('SELECT 1').pluck().get() === 1;
    res.json({ status: 'ok', db: okDb, time: now });
  } catch (e) {
    res.status(500).json({ status: 'error', error: e.message });
  }
});

// DEV-only password reset flow
app.post('/api/auth/request-reset', (req, res) => {
  try {
    const { username } = req.body || {};
    if (!username) return err(res, 'Username required');
    const user = db.prepare('SELECT username FROM users WHERE username = ?').get(username);
    if (!user) return err(res, 'User not found');
    const token = crypto.randomBytes(12).toString('hex');
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    resetTokens.set(username, { token, expiresAt });
    if (process.env.NODE_ENV === 'production') {
      ok(res, { message: 'If the account exists, a reset link has been sent.' });
    } else {
      ok(res, { token, expiresAt }); // dev convenience
    }
  } catch (e) { err(res, e.message); }
});

app.post('/api/auth/reset', async (req, res) => {
  try {
    const { username, token, newPassword } = req.body || {};
    if (!username || !token || !newPassword) return err(res, 'Missing fields');
    const rec = resetTokens.get(username);
    if (!rec || rec.token !== token || Date.now() > rec.expiresAt) return err(res, 'Invalid or expired token');
    const pwdHash = await argon2.hash(String(newPassword));
    db.prepare('UPDATE users SET password_salt = ?, password_hash = ? WHERE username = ?').run(null, pwdHash, username);
    resetTokens.delete(username);
    ok(res, null);
  } catch (e) { err(res, e.message); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return err(res, 'Missing credentials');
    const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!row) return err(res, 'Invalid username or password');
    let valid = false;
    if (row.password_salt) {
      // legacy PBKDF2
      const legacy = hashPassword(password, row.password_salt);
      valid = legacy === row.password_hash;
      if (valid) {
        // auto-upgrade to argon2
        const newHash = await argon2.hash(String(password));
        db.prepare('UPDATE users SET password_salt = NULL, password_hash = ? WHERE username = ?').run(newHash, username);
      }
    } else {
      valid = await argon2.verify(String(row.password_hash), String(password));
    }
    if (!valid) return err(res, 'Invalid username or password', 401);
    const token = signAccessToken({ username, role: row.role });
    ok(res, { token, user: { username, role: row.role } });
  } catch (e) { err(res, e.message); }
});

app.post('/api/auth/logout', (req, res) => {
  try {
    // JWT is stateless; client should discard token
    ok(res, null);
  } catch (e) { err(res, e.message); }
});

app.use('/api', (req, res, next) => {
  const openAuthPaths = new Set(['/auth/login','/auth/register','/auth/logout','/auth/request-reset','/auth/reset']);
  if (openAuthPaths.has(req.path)) return next();

  // Allow unauthenticated GETs for public resources
  if (req.method === 'GET') {
    const publicGetPatterns = [
      /^\/teams\b/,
      /^\/players\b/,
      /^\/matches\b/,
      /^\/umpires\b/,
      /^\/analytics\/stats\b/
    ];
    if (publicGetPatterns.some(rx => rx.test(req.path))) return next();
  }

  return requireAuth(req, res, next);
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  try {
    const row = db.prepare('SELECT username, role FROM users WHERE username = ?').get(req.user.username);
    if (!row) return err(res, 'Unauthorized');
    ok(res, row);
  } catch (e) { err(res, e.message); }
});

// Admin-only user management
app.get('/api/users', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const rows = db.prepare('SELECT username, role FROM users ORDER BY username').all();
    ok(res, rows);
  } catch (e) { err(res, e.message); }
});

app.put('/api/users/:username/role', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const { role } = req.body || {};
    if (!['admin','viewer'].includes(role)) return err(res, 'Invalid role');
    const target = req.params.username;
    const exists = db.prepare('SELECT username FROM users WHERE username = ?').get(target);
    if (!exists) return err(res, 'User not found');
    db.prepare('UPDATE users SET role = ? WHERE username = ?').run(role, target);
    ok(res, null);
  } catch (e) { err(res, e.message); }
});

// Admin: delete user (cannot delete self)
app.delete('/api/users/:username', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const target = req.params.username;
    if (target === req.user.username) return err(res, 'Cannot delete your own account', 422);
    const exists = db.prepare('SELECT username FROM users WHERE username = ?').get(target);
    if (!exists) return err(res, 'User not found', 404);
    db.prepare('DELETE FROM users WHERE username = ?').run(target);
    try { db.prepare('INSERT INTO audit_logs (id,actor,action,entity,entity_id,at,payload) VALUES (?,?,?,?,?,?,?)').run(uuidv4(), req.user.username, 'delete', 'users', target, new Date().toISOString(), null); } catch(_) {}
    ok(res, null);
  } catch (e) { err(res, e.message); }
});

// Debug: list registered routes (methods + paths)
app.get('/_routes', (req, res) => {
  try {
    const routes = [];
    const stack = (app._router && app._router.stack) || [];
    stack.forEach((layer) => {
      if (layer.route && layer.route.path) {
        const methods = Object.keys(layer.route.methods).map(m=>m.toUpperCase());
        routes.push({ methods, path: layer.route.path });
      } else if (layer.name === 'router' && layer.handle && Array.isArray(layer.handle.stack)) {
        layer.handle.stack.forEach((h) => {
          if (h.route && h.route.path) {
            const methods = Object.keys(h.route.methods).map(m=>m.toUpperCase());
            routes.push({ methods, path: h.route.path });
          }
        });
      }
    });
    res.json({ success: true, data: routes });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// (moved below): API 404 JSON handler should be registered after all routes

// validation helpers per entity (minimal)
function validate(entity, obj, isUpdate = false) {
  function req(field) { return !(obj[field] === undefined || obj[field] === null || obj[field] === ''); }
  function isNum(field) { return obj[field] === undefined || obj[field] === null || obj[field] === '' || typeof obj[field] === 'number'; }
  switch(entity) {
    case 'teams':
      if (!isUpdate && !req('team_id')) return 'team_id required';
      if (!isUpdate && !req('team_name')) return 'team_name required';
      if (!isNum('team_rank') || !isNum('no_of_wins') || !isNum('no_of_loses') || !isNum('no_of_draws')) return 'numeric fields invalid';
      return null;
    case 'players':
      if (!isUpdate && !req('player_id')) return 'player_id required';
      if (!isUpdate && !req('player_name')) return 'player_name required';
      if (!isNum('batting_average') || !isNum('no_of_totalruns') || !isNum('no_of_wickets') || !isNum('no_of_sixes') || !isNum('economy')) return 'numeric fields invalid';
      return null;
    case 'matches':
      if (!isUpdate && !req('match_id')) return 'match_id required';
      if (!isUpdate && !req('match_date')) return 'match_date required';
      return null;
    case 'umpires':
      if (!isUpdate && !req('umpire_id')) return 'umpire_id required';
      if (!isUpdate && !req('umpire_name')) return 'umpire_name required';
      if (!isNum('no_of_matches')) return 'numeric fields invalid';
      return null;
    default:
      return null;
  }
}

// generic CRUD with optional pagination/sorting and filtering
function createCrudRoutes(entity, table, fields) {
  // normalize helper: convert empty strings to null for numeric fields
  const numericFields = {
    teams: ['team_rank','no_of_wins','no_of_loses','no_of_draws'],
    players: ['batting_average','no_of_totalruns','no_of_wickets','no_of_sixes','economy'],
    matches: [],
    umpires: ['no_of_matches']
  };
  function normalize(tableName, obj){
    const out = { ...obj };
    // convert all empty strings to null so nullable fields pass schema
    Object.keys(out).forEach(k=>{ if (out[k] === '') out[k] = null; });
    // numeric-specific cleanup (kept for clarity)
    const nums = numericFields[tableName] || [];
    nums.forEach(f=>{ if (out[f] === '') out[f] = null; });
    return out;
  }
  app.get(`/api/${entity}`, (req, res) => {
    try {
      const { limit, offset, sort, order, q, ...rawFilters } = req.query || {};
      const sortCol = sort && fields.includes(sort) ? sort : null;
      const ord = (order || 'asc').toLowerCase() === 'desc' ? 'DESC' : 'ASC';

      // Build WHERE conditions
      const where = [];
      const params = {};

      // Full-text-ish search across selected columns per table
      const searchable = {
        teams: ['team_id','team_name','country_name'],
        players: ['player_id','player_name','team_id','type_of_bowler'],
        matches: ['match_id','team_1_name','team_2_name','winner','stadium'],
        umpires: ['umpire_id','umpire_name','country']
      };
      if (q && String(q).trim().length) {
        const cols = searchable[table] || [];
        if (cols.length) {
          const like = `%${String(q).trim()}%`;
          where.push('(' + cols.map((c,i)=>{ params[`q${i}`]=like; return `${c} LIKE @q${i}`; }).join(' OR ') + ')');
        }
      }

      // Field-specific filters: equality for exact matches
      Object.keys(rawFilters).forEach(k => {
        // special handling for matches team_name filter (maps to team_1_name OR team_2_name)
        if (table === 'matches' && k === 'team_name' && rawFilters[k] !== undefined) {
          const like = `%${String(rawFilters[k]).trim()}%`;
          params[`tm1`] = like; params[`tm2`] = like;
          where.push('(team_1_name LIKE @tm1 OR team_2_name LIKE @tm2)');
          return;
        }
        // numeric range filters: *_min / *_max
        if (k.endsWith('_min')) {
          const base = k.slice(0, -4);
          if (fields.includes(base)) {
            const num = Number(rawFilters[k]);
            if (!Number.isNaN(num)) { params[`min_${base}`] = num; where.push(`${base} >= @min_${base}`); }
          }
          return;
        }
        if (k.endsWith('_max')) {
          const base = k.slice(0, -4);
          if (fields.includes(base)) {
            const num = Number(rawFilters[k]);
            if (!Number.isNaN(num)) { params[`max_${base}`] = num; where.push(`${base} <= @max_${base}`); }
          }
          return;
        }
        // exact match for known fields
        if (fields.includes(k)) {
          params[k] = rawFilters[k];
          where.push(`${k} = @${k}`);
        }
      });

      const parts = [`SELECT * FROM ${table}`];
      const countParts = [`SELECT COUNT(*) as c FROM ${table}`];
      if (where.length) {
        const clause = ' WHERE ' + where.join(' AND ');
        parts.push(clause);
        countParts.push(clause);
      }
      // exclude soft-deleted
      if (!where.length) {
        parts.push(' WHERE deleted_at IS NULL');
        countParts.push(' WHERE deleted_at IS NULL');
      } else {
        parts.push(' AND deleted_at IS NULL');
        countParts.push(' AND deleted_at IS NULL');
      }
      if (sortCol) parts.push(` ORDER BY ${sortCol} ${ord}`);

      if (limit !== undefined) {
        const lim = Math.max(0, Math.min(parseInt(limit, 10) || 0, 100));
        const off = Math.max(0, parseInt(offset, 10) || 0);
        parts.push(` LIMIT ${lim} OFFSET ${off}`);
        const items = db.prepare(parts.join('')).all(params);
        const total = db.prepare(countParts.join('')).pluck().get(params);
        try { res.set('X-Total-Count', String(total)); } catch(_) {}
        ok(res, { items, total });
      } else {
        ok(res, db.prepare(parts.join('')).all(params));
      }
    } catch (e) { err(res, e.message); }
  });

  app.post(`/api/${entity}`, requireAuth, (req, res) => {
    try {
      if (req.user && ['viewer'].includes(db.prepare('SELECT role FROM users WHERE username = ?').pluck().get(req.user.username))) {
        return err(res, 'Forbidden');
      }
      const obj = normalize(table, req.body || {});
      try { zodSchemas[table]?.parse(obj); } catch(e) {
        const msg = (e && e.errors && Array.isArray(e.errors)) ? e.errors.map(x=>x.message).join('; ') : (e && e.message) || 'Invalid payload';
        return err(res, msg, 422);
      }
      const v = validate(table, obj, false);
      if (v) return err(res, v);
      const cols = fields.join(', ');
      const placeholders = fields.map(f => `@${f}`).join(', ');
      const tx = db.transaction(() => {
        db.prepare(`INSERT OR REPLACE INTO ${table} (${cols}) VALUES (${placeholders})`).run(obj);
        try { db.prepare('INSERT INTO audit_logs (id,actor,action,entity,entity_id,at,payload) VALUES (?,?,?,?,?,?,?)').run(uuidv4(), req.user.username, 'create', table, obj[fields[0]], new Date().toISOString(), JSON.stringify(obj)); } catch(_) {}
      });
      tx();
      ok(res, null);
    } catch (e) { err(res, e.message); }
  });

  app.put(`/api/${entity}/:id`, requireAuth, (req, res) => {
    try {
      if (req.user && ['viewer'].includes(db.prepare('SELECT role FROM users WHERE username = ?').pluck().get(req.user.username))) {
        return err(res, 'Forbidden');
      }
      const obj = normalize(table, req.body || {});
      try { zodSchemas[table]?.parse(obj); } catch(e) {
        const msg = (e && e.errors && Array.isArray(e.errors)) ? e.errors.map(x=>x.message).join('; ') : (e && e.message) || 'Invalid payload';
        return err(res, msg, 422);
      }
      const v = validate(table, obj, true);
      if (v) return err(res, v);
      const set = Object.keys(obj).map(k => `${k} = @${k}`).join(', ');
      const tx = db.transaction(() => {
        db.prepare(`UPDATE ${table} SET ${set} WHERE ${fields[0]} = @id`).run({ ...obj, id: req.params.id });
        try { db.prepare('INSERT INTO audit_logs (id,actor,action,entity,entity_id,at,payload) VALUES (?,?,?,?,?,?,?)').run(uuidv4(), req.user.username, 'update', table, req.params.id, new Date().toISOString(), JSON.stringify(obj)); } catch(_) {}
      });
      tx();
      ok(res, null);
    } catch (e) { err(res, e.message); }
  });

  app.delete(`/api/${entity}/:id`, requireAuth, (req, res) => {
    try {
      if (req.user && ['viewer'].includes(db.prepare('SELECT role FROM users WHERE username = ?').pluck().get(req.user.username))) {
        return err(res, 'Forbidden');
      }
      // soft delete
      const tx = db.transaction(() => {
        db.prepare(`UPDATE ${table} SET deleted_at = ? WHERE ${fields[0]} = ?`).run(new Date().toISOString(), req.params.id);
        try { db.prepare('INSERT INTO audit_logs (id,actor,action,entity,entity_id,at,payload) VALUES (?,?,?,?,?,?,?)').run(uuidv4(), req.user.username, 'delete', table, req.params.id, new Date().toISOString(), null); } catch(_) {}
      });
      tx();
      ok(res, null);
    } catch (e) { err(res, e.message); }
  });
}

createCrudRoutes('teams','teams',['team_id', 'team_name', 'country_name', 'team_rank', 'no_of_wins', 'no_of_loses', 'no_of_draws']);
createCrudRoutes('players','players',['player_id', 'player_name', 'team_id', 'batting_average', 'no_of_totalruns', 'no_of_wickets', 'type_of_bowler', 'no_of_sixes', 'economy']);
createCrudRoutes('matches','matches',['match_id', 'match_date', 'match_time', 'team_1_name', 'team_2_name', 'winner', 'stadium']);
createCrudRoutes('umpires','umpires',['umpire_id', 'umpire_name', 'country', 'no_of_matches']);

app.get('/api/analytics/stats', requireAuth, (req, res) => {
  try {
    const totalTeams = db.prepare('SELECT COUNT(*) as c FROM teams').pluck().get();
    const totalPlayers = db.prepare('SELECT COUNT(*) as c FROM players').pluck().get();
    const totalMatches = db.prepare('SELECT COUNT(*) as c FROM matches').pluck().get();
    const totalUmpires = db.prepare('SELECT COUNT(*) as c FROM umpires').pluck().get();
    const avgBattingAvg = db.prepare('SELECT AVG(batting_average) as a FROM players WHERE batting_average IS NOT NULL').get();
    const totalRuns = db.prepare('SELECT SUM(no_of_totalruns) as s FROM players').pluck().get();
    const totalWickets = db.prepare('SELECT SUM(no_of_wickets) as s FROM players').pluck().get();

    // new: average economy (nulls ignored)
    const avgEconomyRow = db.prepare('SELECT AVG(economy) as e FROM players WHERE economy IS NOT NULL').get();

    ok(res, {
      totalTeams,
      totalPlayers,
      totalMatches,
      totalUmpires,
      avgBattingAvg: avgBattingAvg && avgBattingAvg.a ? Number(avgBattingAvg.a.toFixed(2)) : 0,
      totalRuns: totalRuns || 0,
      totalWickets: totalWickets || 0,
      avgEconomy: avgEconomyRow && avgEconomyRow.e ? Number(avgEconomyRow.e.toFixed(2)) : 0
    });
  } catch (e) { err(res, e.message); }
});

// Central error handler
// eslint-disable-next-line no-unused-vars
// Final API 404 handler (must be after all /api routes)
app.use('/api', (req, res) => {
  res.status(404).json({ success: false, error: `Not found: ${req.method} ${req.originalUrl}` });
});

app.use((error, req, res, next) => {
  const status = error.status || 500;
  const msg = error.message || 'Server error';
  res.status(status).json({ success: false, error: msg, requestId: req.id });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API listening on http://localhost:${PORT}`));