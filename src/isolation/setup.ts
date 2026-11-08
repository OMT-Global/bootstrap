// Fixed trusted orchestration. Repository-controlled code runs only in the two final modes.
export const CONTAINER_SETUP = String.raw`
const fs = require('node:fs'), cp = require('node:child_process'), path = require('node:path'), crypto = require('node:crypto');
const manifest = JSON.parse(fs.readFileSync('/input/manifest.json', 'utf8'));
const run = (command, args, cwd = '/repo/project') => cp.execFileSync(command, args, { cwd, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
const hash = b => crypto.createHash('sha256').update(b).digest('hex');
function writable() {
  fs.mkdirSync('/tmp/home', { recursive: true });
  fs.writeFileSync('/tmp/empty-npmrc', ''); fs.writeFileSync('/tmp/empty-global-npmrc', '');
}
function git(args, input) { return cp.execFileSync('git', args, { cwd: '/repo/project', encoding: 'utf8', input, maxBuffer: 8 * 1024 * 1024 }); }
try {
  writable();
  if (process.argv[2] === 'prepare') {
    const tools = { bash: run('bash', ['--version'], '/input').split('\n')[0], git: run('git', ['--version'], '/input').trim(),
      python: run('python3', ['--version'], '/input').trim(), node: process.version, npm: run('npm', ['--version'], '/input').trim() };
    if (!tools.node.startsWith('v24.') || Object.values(tools).some(v => !v || v.length > 512)) throw Error();
    fs.mkdirSync('/install', { recursive: true });
    for (const name of ['package.json', 'package-lock.json']) fs.copyFileSync('/input/files/' + name, '/install/' + name);
    for (const name of fs.readdirSync('/input/archives')) run('npm', ['cache', 'add', '/input/archives/' + name, '--cache', '/pristine-cache', '--offline', '--ignore-scripts', '--no-audit', '--no-fund'], '/install');
    run('npm', ['ci', '--cache', '/pristine-cache', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--engine-strict'], '/install');
    for (const file of manifest.files) {
      const bytes = fs.readFileSync('/input/files/' + file.path); if (hash(bytes) !== file.sha256) throw Error();
      const destination = '/repo/project/' + file.path; fs.mkdirSync(path.dirname(destination), { recursive: true }); fs.writeFileSync(destination, bytes, { mode: file.mode === '100755' ? 0o555 : 0o444 });
    }
    git(['init', '-q', '--template=/input/empty-template']);
    git(['config', 'core.hooksPath', '/disabled-hooks']); git(['config', 'core.fsmonitor', 'false']);
    git(['config', 'user.name', manifest.committer.name]); git(['config', 'user.email', manifest.committer.email]);
    const selected = manifest.phase === 'final-check' ? manifest.candidateCommit : manifest.baseCommit;
    git(['fetch', '-q', '--no-tags', '--no-write-fetch-head', '/input/base.bundle', selected]);
    if (git(['rev-parse', manifest.baseCommit + '^{commit}']).trim() !== manifest.baseCommit) throw Error();
    git(['check-ref-format', '--branch', manifest.branch]); git(['symbolic-ref', 'HEAD', 'refs/heads/' + manifest.branch]);
    git(['update-ref', 'refs/heads/' + manifest.branch, selected]);
    const entries = [];
    for (const file of manifest.files) {
      const oid = git(['hash-object', '-w', '--no-filters', '--stdin'], fs.readFileSync('/repo/project/' + file.path)).trim();
      entries.push(file.mode + ' ' + oid + '\t' + file.path + '\0');
    }
    git(['update-index', '-z', '--index-info'], entries.join(''));
    fs.writeFileSync('/repo/project/.git/COMMIT_EDITMSG', manifest.commitMessage);
    const tree = git(['write-tree']).trim();
    if (manifest.phase === 'final-check') {
      const raw = cp.execFileSync('git', ['cat-file', 'commit', selected], { cwd: '/repo/project', maxBuffer: 8 * 1024 * 1024 }), split = raw.indexOf(Buffer.from('\n\n'));
      const headers = new TextDecoder('utf-8', { fatal: true }).decode(raw.subarray(0, split)).split('\n'), parents = headers.filter(line => line.startsWith('parent '));
      for (const kind of ['author', 'committer']) {
        const expected = kind + ' ' + manifest[kind].name + ' <' + manifest[kind].email + '> ' + manifest[kind].date;
        const actual = headers.filter(line => line.startsWith(kind + ' ')); if (actual.length !== 1 || actual[0] !== expected) throw Error();
      }
      if (split < 0 || parents.length !== 1 || parents[0] !== 'parent ' + manifest.baseCommit || !raw.subarray(split + 2).equals(Buffer.from(manifest.commitMessage, 'utf8')) || git(['rev-parse', selected + '^{tree}']).trim() !== tree || git(['rev-parse', 'HEAD']).trim() !== selected) throw Error();
      git(['diff', '--cached', '--exit-code', '--quiet']);
    }
    console.log(JSON.stringify({ tools, tree }));
  } else {
    fs.cpSync('/pristine-cache', '/npm-cache', { recursive: true });
    const mode = process.argv[2];
    if (mode === 'check') {
      cp.execFileSync('bash', ['scripts/ci/run-fast-checks.sh'], { cwd: '/repo/project', stdio: 'inherit' });
    } else if (mode === 'hook' && manifest.hook !== 'none') {
      // Fixed no-editor/all-staged commit context; never inherit operator Git identity or environment.
      const env = { ...process.env, GIT_INDEX_FILE: '.git/index', GIT_PREFIX: '', GIT_EDITOR: ':', GIT_EXEC_PATH: run('git', ['--exec-path']).trim() };
      for (const kind of ['author', 'committer']) for (const field of ['name', 'email', 'date']) env['GIT_' + kind.toUpperCase() + '_' + field.toUpperCase()] = (field === 'date' ? '@' : '') + manifest[kind][field];
      cp.execFileSync('/repo/project/.githooks/pre-commit', [], { cwd: '/repo/project', env, stdio: 'inherit' });
    } else throw Error();
  }
} catch { console.error('Isolated phase failed.'); process.exitCode = 1; }
`;
