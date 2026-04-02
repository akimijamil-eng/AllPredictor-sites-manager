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
// Générer une clé : node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
// Puis : export SITES_ENCRYPTION_KEY=<clé hex 64 chars>
const ENC_ALGO = 'aes-256-cbc';
const ENC_KEY  = process.env.SITES_ENCRYPTION_KEY
  ? Buffer.from(process.env.SITES_ENCRYPTION_KEY, 'hex')
  : null;

const ENCRYPTION_ENABLED = ENC_KEY && ENC_KEY.length === 32;

if (!ENCRYPTION_ENABLED) {
  console.warn('[WARN] SITES_ENCRYPTION_KEY non défini ou invalide — chiffrement désactivé.');
  console.warn('       Générez une clé : node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
}

// Format sur disque : [16 bytes IV][ciphertext AES-256-CBC]
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
};

// Lire, déchiffrer si besoin, envoyer au navigateur
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

// Chiffrer si besoin, écrire sur disque
function writeFile(destPath, buf) {
  fs.writeFileSync(destPath, ENCRYPTION_ENABLED ? encryptBuffer(buf) : buf);
}

// ── Middleware ────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

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
  // .meta.json stocké en clair (métadonnées internes, jamais exposées)
  fs.writeFileSync(
    path.join(SITES_DIR, slug, '.meta.json'),
    JSON.stringify(data, null, 2)
  );
}

// ─────────────────────────────────────────────────────────
// SOUS-DOMAINES — doit être avant toutes les routes API
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
        <a href="https://allpredictor.com">← Retour à AllPredictor</a>
      </body>
      </html>
    `);
  }

  // Bloquer les fichiers cachés (.meta.json, etc.)
  if (path.basename(req.path).startsWith('.')) return res.status(404).send('Not found');

  // Résoudre le chemin et vérifier path traversal
  const filePath = path.join(siteDir, req.path);
  if (!filePath.startsWith(siteDir + path.sep) && filePath !== siteDir) {
    return res.status(403).send('Interdit');
  }

  // Racine : chercher index.html ou premier .html
  if (req.path === '/' || req.path === '') {
    const indexPath = path.join(siteDir, 'index.html');
    if (fs.existsSync(indexPath)) return serveFile(indexPath, res);
    const htmlFiles = fs.readdirSync(siteDir)
      .filter(f => f.endsWith('.html') && !f.startsWith('.'));
    if (htmlFiles.length > 0) return serveFile(path.join(siteDir, htmlFiles[0]), res);
    return next();
  }

  // Fichier direct
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    return serveFile(filePath, res);
  }

  // Index dans un sous-dossier
  const subIndex = path.join(filePath, 'index.html');
  if (fs.existsSync(subIndex)) return serveFile(subIndex, res);

  return res.status(404).send('Not found');
});

// ─────────────────────────────────────────────────────────
// ROUTES API
// ─────────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'AllPredictor Sites Manager', encryption: ENCRYPTION_ENABLED });
});

// Vérifier dispo d'un slug
app.get('/api/sites/check/:slug', (req, res) => {
  const slug = cleanSlug(req.params.slug);
  if (!slug) return res.status(400).json({ error: 'Slug invalide' });
  const exists = fs.existsSync(path.join(SITES_DIR, slug));
  res.json({ available: !exists, slug });
});

// Lister les sites d'un user
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

// Déployer un site
app.post('/api/sites/deploy', upload.single('file'), async (req, res) => {
  try {
    const { slug: rawSlug, userId } = req.body;
    if (!rawSlug || !userId)
      return res.status(400).json({ error: 'slug et userId requis' });

    const slug = cleanSlug(rawSlug);
    if (!slug) return res.status(400).json({ error: 'Slug invalide' });

    // Vérifier ownership
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
        writeFile(destPath, entry.getData()); // chiffré si ENCRYPTION_ENABLED
        files.push(entry.entryName);
      }
      fs.unlinkSync(file.path);
    } else {
      const dest = path.join(siteDir, file.originalname);
      const raw  = fs.readFileSync(file.path);
      writeFile(dest, raw); // chiffré si ENCRYPTION_ENABLED
      fs.unlinkSync(file.path);
      files = [file.originalname];
    }

    const now = new Date().toISOString();
    writeMeta(slug, {
      slug,
      userId,
      url: `https://${slug}.allpredictor.com`,
      filename: file.originalname,
      files,
      created_at: existing ? existing.created_at : now,
      updated_at: now,
    });

    res.json({
      success: true,
      slug,
      url: `https://${slug}.allpredictor.com`,
      files,
    });

  } catch (e) {
    console.error('[DEPLOY ERROR]', e.message);
    if (req.file?.path && fs.existsSync(req.file.path))
      fs.unlinkSync(req.file.path);
    res.status(500).json({ error: e.message });
  }
});

// Supprimer un site
app.delete('/api/sites/:slug', (req, res) => {
  const slug   = cleanSlug(req.params.slug);
  const { userId } = req.body;
  const meta   = readMeta(slug);
  if (!meta)                    return res.status(404).json({ error: 'Site introuvable' });
  if (meta.userId !== userId)   return res.status(403).json({ error: 'Non autorisé' });
  fs.rmSync(path.join(SITES_DIR, slug), { recursive: true, force: true });
  res.json({ success: true });
});


app.listen(PORT, () => {
  console.log(`[OK] Sites Manager démarré — port ${PORT}`);
  console.log(`[ENC] Chiffrement AES-256 : ${ENCRYPTION_ENABLED ? 'ACTIVÉ' : 'DÉSACTIVÉ'}`);
});
