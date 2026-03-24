const express = require('express');
const multer  = require('multer');
const AdmZip  = require('adm-zip');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Dossiers ──────────────────────────────────────────────
const SITES_DIR = path.join(__dirname, 'sites');
const TMP_DIR   = path.join(__dirname, 'tmp');
if (!fs.existsSync(SITES_DIR)) fs.mkdirSync(SITES_DIR);
if (!fs.existsSync(TMP_DIR))   fs.mkdirSync(TMP_DIR);

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
  fs.writeFileSync(
    path.join(SITES_DIR, slug, '.meta.json'),
    JSON.stringify(data, null, 2)
  );
}

// ─────────────────────────────────────────────────────────
// ROUTES API
// ─────────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'AllPredictor Sites Manager' });
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
        fs.writeFileSync(destPath, entry.getData());
        files.push(entry.entryName);
      }
      fs.unlinkSync(file.path);
    } else {
      const dest = path.join(siteDir, file.originalname);
      fs.renameSync(file.path, dest);
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

// ─────────────────────────────────────────────────────────
// SERVEUR STATIQUE — détection par sous-domaine
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

  express.static(siteDir)(req, res, next);
});

app.listen(PORT, () => {
  console.log(`[OK] Sites Manager démarré — port ${PORT}`);
});
