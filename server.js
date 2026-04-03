const express = require('express');
const multer  = require('multer');
const AdmZip  = require('adm-zip');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 8080;

// ── Dossiers ──────────────────────────────────────────────
const SITES_DIR = path.join(__dirname, 'sites');
const TMP_DIR   = path.join(__dirname, 'tmp');
if (!fs.existsSync(SITES_DIR)) fs.mkdirSync(SITES_DIR);
if (!fs.existsSync(TMP_DIR))   fs.mkdirSync(TMP_DIR);

// ── Chiffrement AES-256-CBC ───────────────────────────────
const ENC_ALGO = 'aes-256-cbc';
const ENC_KEY  = process.env.SITES_ENCRYPTION_KEY
  ? Buffer.from(process.env.SITES_ENCRYPTION_KEY, 'hex')
  : null;

const ENCRYPTION_ENABLED = ENC_KEY && ENC_KEY.length === 32;

if (!ENCRYPTION_ENABLED) {
  console.warn('[WARN] SITES_ENCRYPTION_KEY non défini ou invalide — chiffrement désactivé.');
}

function encryptBuffer(buf) {
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ENC_ALGO, ENC_KEY, iv);
  const enc    = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, enc]);
}

function decryptBuffer(buf) {
  const iv         = buf.slice(0, 16);
  const ciphertext = buf.slice(16);
  const decipher   = crypto.createDecipheriv(ENC_ALGO, ENC_KEY, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ── MIME types ────────────────────────────────────────────
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.json': 'application/json',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
  '.ttf':  'font/ttf',
  '.mp4':  'video/mp4',
  '.webm': 'video/webm',
  '.pdf':  'application/pdf',
  '.xml':  'application/xml',
  '.txt':  'text/plain',
  '.map':  'application/json',
  '.mjs':  'application/javascript',
  '.jsx':  'application/javascript',
  '.ts':   'application/javascript',
  '.tsx':  'application/javascript',
  '.wasm': 'application/wasm',
  '.avif': 'image/avif',
  '.mp3':  'audio/mpeg',
  '.ogg':  'audio/ogg',
  '.wav':  'audio/wav',
};

function serveFile(filePath, res) {
  if (!fs.existsSync(filePath)) return res.status(404).send('Not found');
  try {
    const raw  = fs.readFileSync(filePath);
    const data = ENCRYPTION_ENABLED ? decryptBuffer(raw) : raw;
    const ext  = path.extname(filePath).toLowerCase();
    res.setHeader('Content-Type', MIME_TYPES[ext] || 'application/octet-stream');
    res.send(data);
  } catch (e) {
    console.error('[SERVE ERROR]', e.message);
    res.status(500).send('Erreur serveur');
  }
}

function writeFile(destPath, buf) {
  fs.writeFileSync(destPath, ENCRYPTION_ENABLED ? encryptBuffer(buf) : buf);
}

// ── Middleware ────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

// ─────────────────────────────────────────────────────────
// 🛡️ ShieldWall — Protection dynamique par sous-domaine
// ─────────────────────────────────────────────────────────

const shieldCache = new Map();
const CACHE_TTL = 5 * 60 * 1000;

async function getShieldSiteId(slug) {
  const cached = shieldCache.get(slug);
  if (cached && cached.expires > Date.now()) {
    return cached.site_id;
  }

  const metaPath = path.join(SITES_DIR, slug, '.meta.json');
  if (fs.existsSync(metaPath)) {
    try {
      const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
      if (meta.shield_site_id) {
        shieldCache.set(slug, { site_id: meta.shield_site_id, expires: Date.now() + CACHE_TTL });
        return meta.shield_site_id;
      }
    } catch {}
  }

  return null;
}

app.use(async (req, res, next) => {
  const host  = req.hostname;
  const match = host.match(/^([a-z0-9-]+)\.allpredictor\.com$/);

  if (!match) return next();

  const slug = match[1];
  const reserved = ['www', 'api', 'app', 'admin', 'dashboard', 'docs', 'mail', 'bot', 'builder'];
  if (reserved.includes(slug)) return next();

  const siteId = await getShieldSiteId(slug);

  if (!siteId) return next();

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    const response = await fetch(
      'https://shield-net-core.base44.app/api/functions/validateRequest',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site_id: siteId,
          ip: req.headers['x-forwarded-for'] || req.ip,
          user_agent: req.headers['user-agent'] || '',
          path: req.path,
          method: req.method,
          api_key: req.headers['x-api-key'] || null,
          jwt_token: req.headers['authorization']?.replace('Bearer ', '') || null,
          query_params: req.query ? new URLSearchParams(req.query).toString() : '',
          request_body: typeof req.body === 'string' ? req.body : JSON.stringify(req.body || ''),
        }),
        signal: controller.signal,
      }
    );
    clearTimeout(timeout);
    const data = await response.json();

    if (!data.allowed) {
      return res.status(403).json({
        error: 'Blocked by ShieldWall',
        reason: data.reason,
      });
    }
    next();
  } catch (err) {
    next();
  }
});

// ── Upload temporaire ─────────────────────────────────────
const upload = multer({
  dest: TMP_DIR,
  limits: { fileSize: 50 * 1024 * 1024 },
});

// ── Helpers ───────────────────────────────────────────────
function cleanSlug(raw) {
  return (raw || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 32);
}
function readMeta(slug) {
  const p = path.join(SITES_DIR, slug, '.meta.json');
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}
function writeMeta(slug, data) {
  fs.writeFileSync(
    path.join(SITES_DIR, slug, '.meta.json'),
    JSON.stringify(data, null, 2)
  );
}

// ─────────────────────────────────────────────────────────
// SOUS-DOMAINES — Sert les sites statiques + SPA fallback
// ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const host  = req.hostname;
  const match = host.match(/^([a-z0-9-]+)\.allpredictor\.com$/);
  if (!match) return next();

  const slug     = match[1];
  const reserved = ['www','api','app','admin','dashboard','docs','mail','bot','builder'];
  if (reserved.includes(slug)) return next();

  const siteDir = path.join(SITES_DIR, slug);
  if (!fs.existsSync(siteDir)) {
    return res.status(404).send(`
      <!DOCTYPE html>
      <html lang="fr">
      <head>
        <meta charset="UTF-8"/>
        <meta name="viewport" content="width=device-width,initial-scale=1"/>
        <title>Site introuvable — AllPredictor</title>
        <style>
          body{font-family:sans-serif;background:#080d1a;color:#e8edf5;
               display:flex;flex-direction:column;align-items:center;
               justify-content:center;height:100vh;margin:0;text-align:center;}
          h2{font-size:1.4rem;margin-bottom:8px;}
          p{color:#8fa3c0;font-size:.9rem;margin-bottom:24px;}
          a{color:#6391fa;text-decoration:none;font-weight:600;}
        </style>
      </head>
      <body>
        <div style="font-size:2.5rem;margin-bottom:16px;">🌐</div>
        <h2>${slug}.allpredictor.com</h2>
        <p>Ce site n'existe pas encore.</p>
        <a href__="https://allpredictor.com">← Retour à AllPredictor</a>
      </body>
      </html>
    `);
  }

  // Bloquer les fichiers cachés (.meta.json, .env, etc.)
  if (path.basename(req.path).startsWith('.')) return res.status(404).send('Not found');

  // Sécurité : empêcher la traversée de répertoire
  const filePath = path.join(siteDir, req.path);
  if (!filePath.startsWith(siteDir + path.sep) && filePath !== siteDir) {
    return res.status(403).send('Interdit');
  }

  // ── Racine du site ──
  if (req.path === '/' || req.path === '') {
    const indexPath = path.join(siteDir, 'index.html');
    if (fs.existsSync(indexPath)) return serveFile(indexPath, res);
    const htmlFiles = fs.readdirSync(siteDir)
      .filter(f => f.endsWith('.html') && !f.startsWith('.'));
    if (htmlFiles.length > 0) return serveFile(path.join(siteDir, htmlFiles[0]), res);
    return next();
  }

  // ── Fichier existant → le servir directement ──
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    return serveFile(filePath, res);
  }

  // ── Sous-dossier avec index.html ──
  const subIndex = path.join(filePath, 'index.html');
  if (fs.existsSync(subIndex)) return serveFile(subIndex, res);

  // ── SPA FALLBACK ──────────────────────────────────────
  // Si aucun fichier trouvé ET qu'un index.html existe à la racine,
  // on le sert → React, Vue, Angular, Svelte gèrent le routing côté client
  const spaIndex = path.join(siteDir, 'index.html');
  if (fs.existsSync(spaIndex)) {
    return serveFile(spaIndex, res);
  }

  return res.status(404).send('Not found');
});

// ─────────────────────────────────────────────────────────
// ROUTES API
// ─────────────────────────────────────────────────────────

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'AllPredictor Sites Manager', encryption: ENCRYPTION_ENABLED });
});

app.get('/api/sites/check/:slug', (req, res) => {
  const slug = cleanSlug(req.params.slug);
  if (!slug) return res.status(400).json({ error: 'Slug invalide' });
  const exists = fs.existsSync(path.join(SITES_DIR, slug));
  res.json({ available: !exists, slug });
});

app.get('/api/sites/list/:userId', (req, res) => {
  const { userId } = req.params;
  const sites = [];
  if (!fs.existsSync(SITES_DIR)) return res.json({ sites: [] });
  for (const slug of fs.readdirSync(SITES_DIR)) {
    const meta = readMeta(slug);
    if (meta && meta.userId === userId) sites.push(meta);
  }
  sites.sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));
  res.json({ sites });
});

// ─────────────────────────────────────────────────────────
// DEPLOY
// ─────────────────────────────────────────────────────────
app.post('/api/sites/deploy', upload.single('file'), async (req, res) => {
  try {
    const { slug: rawSlug, userId, shield_site_id } = req.body;
    if (!rawSlug || !userId)
      return res.status(400).json({ error: 'slug et userId requis' });

    const slug = cleanSlug(rawSlug);
    if (!slug) return res.status(400).json({ error: 'Slug invalide' });

    const existing = readMeta(slug);
    if (existing && existing.userId !== userId)
      return res.status(403).json({ error: 'Ce nom est déjà pris' });

    const siteDir = path.join(SITES_DIR, slug);
    if (!fs.existsSync(siteDir)) fs.mkdirSync(siteDir, { recursive: true });

    const file = req.file;
    if (!file) return res.status(400).json({ error: 'Aucun fichier reçu' });

    const ext = path.extname(file.originalname).toLowerCase();
    let files = [];

    if (ext === '.zip') {
      const zip = new AdmZip(file.path);
      const entries = zip.getEntries().filter(e =>
        !e.entryName.includes('__MACOSX') &&
        !e.entryName.startsWith('.') &&
        !e.isDirectory
      );
      for (const entry of entries) {
        const destPath = path.join(siteDir, entry.entryName);
        const destDir  = path.dirname(destPath);
        if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
        writeFile(destPath, entry.getData());
        files.push(entry.entryName);
      }
      fs.unlinkSync(file.path);
    } else {
      const dest = path.join(siteDir, file.originalname);
      const raw  = fs.readFileSync(file.path);
      writeFile(dest, raw);
      fs.unlinkSync(file.path);
      files = [file.originalname];
    }

    const now = new Date().toISOString();
    const metaData = {
      slug,
      userId,
      url: `https://${slug}.allpredictor.com`,
      filename: file.originalname,
      files,
      created_at: existing ? existing.created_at : now,
      updated_at: now,
    };

    if (shield_site_id) {
      metaData.shield_site_id = shield_site_id;
      shieldCache.delete(slug);
    } else if (existing && existing.shield_site_id) {
      metaData.shield_site_id = existing.shield_site_id;
    }

    writeMeta(slug, metaData);

    res.json({
      success: true,
      slug,
      url: `https://${slug}.allpredictor.com`,
      files,
      shield_protected: !!metaData.shield_site_id,
    });

  } catch (e) {
    console.error('[DEPLOY ERROR]', e.message);
    if (req.file?.path && fs.existsSync(req.file.path))
      fs.unlinkSync(req.file.path);
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────────────────
// LIER / DÉLIER ShieldWall
// ─────────────────────────────────────────────────────────
app.post('/api/sites/:slug/shield', (req, res) => {
  const slug   = cleanSlug(req.params.slug);
  const { userId, shield_site_id } = req.body;
  const meta   = readMeta(slug);

  if (!meta) return res.status(404).json({ error: 'Site introuvable' });
  if (meta.userId !== userId) return res.status(403).json({ error: 'Non autorisé' });

  if (shield_site_id) {
    meta.shield_site_id = shield_site_id;
  } else {
    delete meta.shield_site_id;
  }

  meta.updated_at = new Date().toISOString();
  writeMeta(slug, meta);
  shieldCache.delete(slug);

  res.json({
    success: true,
    shield_protected: !!meta.shield_site_id,
  });
});

app.delete('/api/sites/:slug', (req, res) => {
  const slug   = cleanSlug(req.params.slug);
  const { userId } = req.body;
  const meta   = readMeta(slug);
  if (!meta)                    return res.status(404).json({ error: 'Site introuvable' });
  if (meta.userId !== userId)   return res.status(403).json({ error: 'Non autorisé' });
  fs.rmSync(path.join(SITES_DIR, slug), { recursive: true, force: true });
  shieldCache.delete(slug);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`[OK] Sites Manager démarré — port ${PORT}`);
  console.log(`[ENC] Chiffrement AES-256 : ${ENCRYPTION_ENABLED ? 'ACTIVÉ' : 'DÉSACTIVÉ'}`);
  console.log(`[🛡️] ShieldWall : ACTIVÉ (protection dynamique par sous-domaine)`);
  console.log(`[SPA] Fallback index.html : ACTIVÉ (React, Vue, Angular, Svelte)`);
});
