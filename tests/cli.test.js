import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const project_root = fileURLToPath(new URL('..', import.meta.url));

function run_cli(arguments_list) {
  return spawnSync(process.execPath, ['index.js', ...arguments_list], {
    cwd: project_root,
    encoding: 'utf8',
    timeout: 10_000,
  });
}

test('CLI rejects missing, extra, or unsupported arguments', () => {
  const invalid_argument_sets = [
    [],
    ['--help'],
    ['-host'],
    ['-host', 'example.com', 'extra'],
    ['--host', 'example.com'],
    ['-host', ''],
  ];

  for (const arguments_list of invalid_argument_sets) {
    const result = run_cli(arguments_list);
    assert.equal(result.status, 1, `expected exit 1 for: ${arguments_list.join(' ') || '(none)'}`);
    assert.match(result.stderr, /^usage: node index\.js -host example\.com$/m);
  }
});

test('CLI rejects an invalid hostname before scanning', () => {
  const result = run_cli(['-host', 'not a host']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /^error: /m);
  assert.equal(result.stdout, '');
});
