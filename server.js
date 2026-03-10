const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { Pool }   = require('pg');

const app  = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'fieldmapper_secret_key_2026';

// ─── DATABASE ─────────────────────────────────────────────────
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : new Pool({
      host:     'localhost',
      port:     5432,
      database: 'fieldmapper_db',
      user:     'postgres',
      password: 'postgres',
    });
// ─── MIDDLEWARE ───────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// Auth middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const organiserOnly = (req, res, next) => {
  if (req.user.role !== 'organiser')
    return res.status(403).json({ error: 'Organiser access only' });
  next();
};

// ─── SETUP DATABASE TABLES ────────────────────────────────────
async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      name       VARCHAR(100) NOT NULL,
      email      VARCHAR(150) UNIQUE NOT NULL,
      password   VARCHAR(255) NOT NULL,
      role       VARCHAR(20)  NOT NULL DEFAULT 'worker',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS surveys (
      id          SERIAL PRIMARY KEY,
      title       VARCHAR(200) NOT NULL,
      description TEXT,
      category    VARCHAR(100),
      fields      JSONB        NOT NULL DEFAULT '[]',
      created_by  INTEGER      REFERENCES users(id),
      status      VARCHAR(20)  NOT NULL DEFAULT 'draft',
      created_at  TIMESTAMP    DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS responses (
      id          SERIAL PRIMARY KEY,
      survey_id   INTEGER   REFERENCES surveys(id) ON DELETE CASCADE,
      worker_id   INTEGER   REFERENCES users(id),
      answers     JSONB     NOT NULL DEFAULT '{}',
      latitude    DOUBLE PRECISION,
      longitude   DOUBLE PRECISION,
      photo_url   TEXT,
      submitted_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS survey_assignments (
      id         SERIAL PRIMARY KEY,
      survey_id  INTEGER REFERENCES surveys(id) ON DELETE CASCADE,
      worker_id  INTEGER REFERENCES users(id)   ON DELETE CASCADE,
      assigned_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(survey_id, worker_id)
    );
  `);

  // Create default organiser account if not exists
  const existing = await pool.query(`SELECT id FROM users WHERE email = 'admin@fieldmapper.com'`);
  if (existing.rows.length === 0) {
    const hashed = await bcrypt.hash('admin1234', 10);
    await pool.query(
      `INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)`,
      ['Admin Organiser', 'admin@fieldmapper.com', hashed, 'organiser']
    );
    console.log('✅ Default organiser created: admin@fieldmapper.com / admin1234');
  }

  console.log('✅ Database tables ready');
}

// ─── AUTH ROUTES ──────────────────────────────────────────────

// Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'All fields required' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, password, role) VALUES ($1,$2,$3,$4) RETURNING id, name, email, role`,
      [name, email, hashed, role || 'worker']
    );
    const user  = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user, token });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Email already exists' });
    res.status(500).json({ error: e.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required' });
  try {
    const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
    const user   = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role }, token });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get current user
app.get('/api/auth/me', auth, async (req, res) => {
  const result = await pool.query(`SELECT id, name, email, role, created_at FROM users WHERE id = $1`, [req.user.id]);
  res.json(result.rows[0]);
});

// ─── USER ROUTES ──────────────────────────────────────────────

// Get all workers (organiser only)
app.get('/api/users/workers', auth, organiserOnly, async (req, res) => {
  const result = await pool.query(
    `SELECT u.id, u.name, u.email, u.created_at,
       COUNT(DISTINCT sa.survey_id) as surveys,
       COUNT(DISTINCT r.id) as responses
     FROM users u
     LEFT JOIN survey_assignments sa ON sa.worker_id = u.id
     LEFT JOIN responses r ON r.worker_id = u.id
     WHERE u.role = 'worker'
     GROUP BY u.id ORDER BY u.created_at DESC`
  );
  res.json(result.rows);
});

// Invite (create) a worker
app.post('/api/users/invite', auth, organiserOnly, async (req, res) => {
  const { name, email } = req.body;
  const tempPassword = 'worker1234';
  try {
    const hashed = await bcrypt.hash(tempPassword, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, password, role) VALUES ($1,$2,$3,'worker') RETURNING id, name, email, role`,
      [name, email, hashed]
    );
    res.json({ user: result.rows[0], tempPassword });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Email already exists' });
    res.status(500).json({ error: e.message });
  }
});

// ─── SURVEY ROUTES ────────────────────────────────────────────

// Get all surveys (organiser sees all, worker sees assigned only)
app.get('/api/surveys', auth, async (req, res) => {
  try {
    let result;
    if (req.user.role === 'organiser') {
      result = await pool.query(
        `SELECT s.*, u.name as creator_name,
           COUNT(DISTINCT r.id) as responses,
           COUNT(DISTINCT sa.worker_id) as workers
         FROM surveys s
         LEFT JOIN users u ON u.id = s.created_by
         LEFT JOIN responses r ON r.survey_id = s.id
         LEFT JOIN survey_assignments sa ON sa.survey_id = s.id
         WHERE s.created_by = $1
         GROUP BY s.id, u.name
         ORDER BY s.created_at DESC`,
        [req.user.id]
      );
    } else {
      result = await pool.query(
        `SELECT s.* FROM surveys s
         JOIN survey_assignments sa ON sa.survey_id = s.id
         WHERE sa.worker_id = $1 AND s.status = 'active'
         ORDER BY s.created_at DESC`,
        [req.user.id]
      );
    }
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get single survey
app.get('/api/surveys/:id', auth, async (req, res) => {
  const result = await pool.query(`SELECT * FROM surveys WHERE id = $1`, [req.params.id]);
  if (!result.rows[0]) return res.status(404).json({ error: 'Survey not found' });
  res.json(result.rows[0]);
});

// Create survey
app.post('/api/surveys', auth, organiserOnly, async (req, res) => {
  const { title, description, category, fields } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  try {
    const result = await pool.query(
      `INSERT INTO surveys (title, description, category, fields, created_by, status)
       VALUES ($1,$2,$3,$4,$5,'draft') RETURNING *`,
      [title, description, category, JSON.stringify(fields || []), req.user.id]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Update survey
app.put('/api/surveys/:id', auth, organiserOnly, async (req, res) => {
  const { title, description, category, fields, status } = req.body;
  try {
    const result = await pool.query(
      `UPDATE surveys SET title=$1, description=$2, category=$3, fields=$4, status=$5
       WHERE id=$6 AND created_by=$7 RETURNING *`,
      [title, description, category, JSON.stringify(fields || []), status, req.params.id, req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Survey not found' });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Delete survey
app.delete('/api/surveys/:id', auth, organiserOnly, async (req, res) => {
  await pool.query(`DELETE FROM surveys WHERE id=$1 AND created_by=$2`, [req.params.id, req.user.id]);
  res.json({ success: true });
});

// Assign worker to survey
app.post('/api/surveys/:id/assign', auth, organiserOnly, async (req, res) => {
  const { worker_id } = req.body;
  try {
    await pool.query(
      `INSERT INTO survey_assignments (survey_id, worker_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
      [req.params.id, worker_id]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── RESPONSE ROUTES ──────────────────────────────────────────

// Get all responses for a survey
app.get('/api/surveys/:id/responses', auth, async (req, res) => {
  const result = await pool.query(
    `SELECT r.*, u.name as worker_name, u.email as worker_email
     FROM responses r
     JOIN users u ON u.id = r.worker_id
     WHERE r.survey_id = $1
     ORDER BY r.submitted_at DESC`,
    [req.params.id]
  );
  res.json(result.rows);
});

// Get ALL responses (organiser dashboard)
app.get('/api/responses', auth, organiserOnly, async (req, res) => {
  const result = await pool.query(
    `SELECT r.*, u.name as worker_name, s.title as survey_title
     FROM responses r
     JOIN users u ON u.id = r.worker_id
     JOIN surveys s ON s.id = r.survey_id
     WHERE s.created_by = $1
     ORDER BY r.submitted_at DESC
     LIMIT 100`,
    [req.user.id]
  );
  res.json(result.rows);
});

// Submit a response (worker)
app.post('/api/surveys/:id/respond', auth, async (req, res) => {
  const { answers, latitude, longitude, photo_url } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO responses (survey_id, worker_id, answers, latitude, longitude, photo_url)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [req.params.id, req.user.id, JSON.stringify(answers || {}), latitude, longitude, photo_url]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── STATS ROUTE ──────────────────────────────────────────────
app.get('/api/stats', auth, organiserOnly, async (req, res) => {
  const surveys   = await pool.query(`SELECT COUNT(*) FROM surveys WHERE created_by=$1`, [req.user.id]);
  const active    = await pool.query(`SELECT COUNT(*) FROM surveys WHERE created_by=$1 AND status='active'`, [req.user.id]);
  const responses = await pool.query(
    `SELECT COUNT(*) FROM responses r JOIN surveys s ON s.id=r.survey_id WHERE s.created_by=$1`, [req.user.id]
  );
  const workers   = await pool.query(`SELECT COUNT(*) FROM users WHERE role='worker'`);

  res.json({
    total_surveys:   parseInt(surveys.rows[0].count),
    active_surveys:  parseInt(active.rows[0].count),
    total_responses: parseInt(responses.rows[0].count),
    total_workers:   parseInt(workers.rows[0].count),
  });
});

// ─── START ────────────────────────────────────────────────────
setupDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🚀 FieldMapper API running on http://localhost:${PORT}`);
    console.log(`📋 Endpoints:`);
    console.log(`   POST /api/auth/login`);
    console.log(`   POST /api/auth/register`);
    console.log(`   GET  /api/surveys`);
    console.log(`   POST /api/surveys`);
    console.log(`   GET  /api/responses`);
    console.log(`   GET  /api/stats\n`);
  });
}).catch(err => {
  console.error('❌ Database connection failed:', err.message);
  console.error('Make sure PostgreSQL is running and credentials are correct');
});