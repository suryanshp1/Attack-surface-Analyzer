// Static Retire.js engine only: no CLI, network modules, dynamic extractors or page execution.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const retire = require('./retire.cjs');
const snapshot = 'e5e228659bbcaea7ba85536a2ef8d4fb97b366e9';

if (process.argv[2] === '--version') {
  process.stdout.write(`Retire.js ${retire.version}\n`);
  process.exit(0);
}
if (process.argv.length !== 4 || process.argv[2] !== '--path') {
  throw new Error('Expected --path <download directory>');
}
const raw = fs.readFileSync(path.join(__dirname, 'jsrepository.json'));
if (crypto.createHash('sha256').update(raw).digest('hex') !== '01756a592875f31e99481ace7a05a9c23e6915027c719495d542709db7ee2c35') {
  throw new Error('Advisory snapshot checksum mismatch');
}
const repo = JSON.parse(retire.replaceVersion(raw.toString('utf8')));
delete repo['dont check'];
const directory = process.argv[3];
const names = fs.readdirSync(directory).sort();
if (names.length > 100) throw new Error('JavaScript file cap exceeded');
let total = 0;
for (const file of names) {
  if (!/^[a-f0-9]{32}\.js$/.test(file)) throw new Error('Unexpected JavaScript filename');
  const filename = path.join(directory, file);
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.size > 512 * 1024) throw new Error('Invalid JavaScript file');
  total += stat.size;
  if (total > 16 * 1024 * 1024) throw new Error('JavaScript byte cap exceeded');
  const content = fs.readFileSync(filename, 'utf8');
  const results = retire.scanFileContent(content, repo, {
    sha1: data => crypto.createHash('sha1').update(data).digest('hex'),
  }).filter(result => result.vulnerabilities?.length);
  // Contents and extracted secrets never enter scanner output.
  process.stdout.write(JSON.stringify({ file, results }) + '\n');
}
process.stdout.write(JSON.stringify({ complete: true, database: snapshot }) + '\n');
