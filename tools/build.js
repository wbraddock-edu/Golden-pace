// Build step: compiles Tailwind to ../styles.css, copies pinned libraries into ../vendor,
// and stamps ../sw.js with a content hash so installed copies refresh when files change.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = path.join(__dirname, '..');
const nm = path.join(__dirname, 'node_modules');

console.log('Building styles.css ...');
execFileSync('npx', ['tailwindcss', '-c', 'tailwind.config.js', '-i', 'input.css', '-o', '../styles.css', '--minify'],
  { cwd: __dirname, stdio: 'inherit' });

console.log('Copying vendor libraries ...');
fs.mkdirSync(path.join(root, 'vendor'), { recursive: true });
const vendor = {
  'dexie.min.js': 'dexie/dist/dexie.min.js',
  'chart.umd.js': 'chart.js/dist/chart.umd.js',
  'confetti.browser.js': 'canvas-confetti/dist/confetti.browser.js'
};
for (const [out, src] of Object.entries(vendor)) fs.copyFileSync(path.join(nm, src), path.join(root, 'vendor', out));

const files = ['index.html', 'privacy.html', 'terms.html', 'faq.html', 'styles.css', 'manifest.webmanifest', ...Object.keys(vendor).map(f => 'vendor/' + f)];
const hash = crypto.createHash('sha256');
for (const f of files) hash.update(fs.readFileSync(path.join(root, f)));
const version = hash.digest('hex').slice(0, 12);

const swPath = path.join(root, 'sw.js');
const sw = fs.readFileSync(swPath, 'utf8').replace(/const VERSION = '[^']*';/, `const VERSION = '${version}';`);
fs.writeFileSync(swPath, sw);
console.log('Service worker cache version:', version);
