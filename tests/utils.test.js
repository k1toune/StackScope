import test from 'node:test';
import assert from 'node:assert/strict';
import {
  compare_versions,
  make_version_spec,
  normalize_severity,
  normalize_target,
  strip_control_characters,
  version_spec_intersects,
} from '../src/utils.js';

test('normalize_target accepts a bare hostname', () => {
  const result = normalize_target('example.com');
  assert.equal(result.ok, true);
  assert.equal(result.hostname, 'example.com');
  assert.equal(result.scheme, 'https');
  assert.equal(result.display_host, 'example.com');
});

test('normalize_target accepts a scheme, port, and uppercase host', () => {
  const result = normalize_target('HTTP://Example.COM:8080/');
  assert.equal(result.ok, true);
  assert.equal(result.hostname, 'example.com');
  assert.equal(result.scheme, 'http');
  assert.equal(result.port, '8080');
  assert.equal(result.display_host, 'example.com:8080');
});

test('normalize_target ignores a path but records a note', () => {
  const result = normalize_target('https://example.com/admin?x=1');
  assert.equal(result.ok, true);
  assert.equal(result.display_host, 'example.com');
  assert.equal(result.notes.length, 1);
});

test('normalize_target rejects bad input', () => {
  for (const input of ['', '   ', 'exa mple.com', 'ftp://example.com', 'http://', 'user:pass@example.com', 'http://exa_mple.com']) {
    const result = normalize_target(input);
    assert.equal(result.ok, false, `expected rejection for ${JSON.stringify(input)}`);
  }
});

test('compare_versions handles common release forms', () => {
  assert.equal(compare_versions('1.2.3', '1.2.3'), 0);
  assert.equal(compare_versions('1.2.3', '1.2.4'), -1);
  assert.equal(compare_versions('1.10.0', '1.9.9'), 1);
  assert.equal(compare_versions('1.2', '1.2.0'), 0);
  assert.equal(compare_versions('2.0.0', '2.0.0-beta.1'), 1);
  assert.equal(compare_versions('v1.24.0', '1.24.0'), 0);
});

test('make_version_spec distinguishes exact from partial versions', () => {
  const exact = make_version_spec('8.2.17');
  assert.equal(exact.kind, 'exact');
  assert.equal(exact.version, '8.2.17');

  const partial = make_version_spec('1.24');
  assert.equal(partial.kind, 'partial');
  assert.equal(partial.lower, '1.24.0');
  assert.equal(partial.upper, '1.25.0');
  assert.equal(partial.display, '1.24.x');

  const wildcard = make_version_spec('6.x');
  assert.equal(wildcard.kind, 'partial');
  assert.equal(wildcard.lower, '6.0.0');
  assert.equal(wildcard.upper, '7.0.0');

  assert.equal(make_version_spec('unknown').kind, 'unknown');
});

test('version_spec_intersects uses the partial range, not string comparison', () => {
  const partial = make_version_spec('8.2');
  assert.equal(version_spec_intersects('8.1.0', '8.3.0', partial), true);
  assert.equal(version_spec_intersects('8.3.0', '8.4.0', partial), false);
  assert.equal(version_spec_intersects('8.2.17', '8.2.18', partial), true);
});

test('normalize_severity maps source-specific labels', () => {
  assert.equal(normalize_severity('MODERATE'), 'MEDIUM');
  assert.equal(normalize_severity('important'), 'HIGH');
  assert.equal(normalize_severity('nonsense'), 'UNKNOWN');
});

test('strip_control_characters removes terminal escape sequences', () => {
  assert.equal(strip_control_characters('\u001b[31mred\u001b[0m\nline'), 'red line');
});
