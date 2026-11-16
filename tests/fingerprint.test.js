import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extract_resources,
  fingerprint_response,
  parse_meta_tags,
} from '../src/fingerprint.js';
import { resolve_technology_version } from '../src/version_detector.js';

const wordpress_html = `<!doctype html>
<html>
<head>
  <meta content="WordPress 6.4.2" name="generator">
  <link rel="stylesheet" href="/wp-content/themes/site/style.css?ver=1.2">
  <script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.4.2"></script>
  <script src="https://cdn.example.net/react.production.min.js"></script>
</head>
<body data-reactroot>
  <div id="app"></div>
</body>
</html>`;

test('parses meta tags regardless of attribute order', () => {
  const tags = parse_meta_tags(wordpress_html);
  assert.deepEqual(tags.get('generator'), ['WordPress 6.4.2']);
});

test('fingerprints headers, cookies, HTML, and resources together', () => {
  const resources = extract_resources(wordpress_html, 'https://example.com/');
  const detections = fingerprint_response({
    headers: {
      server: 'nginx/1.24.0',
      'x-powered-by': 'PHP/8.2.17',
      'cf-ray': '8abc123-CDG',
    },
    set_cookie: ['PHPSESSID=abc123; Path=/; HttpOnly'],
    html: wordpress_html,
    resources,
  });

  const by_name = Object.fromEntries(detections.map((detection) => [detection.name, detection]));

  assert.equal(by_name.PHP.confidence, 'HIGH');
  assert.equal(resolve_technology_version(by_name.PHP.version_candidates).version_spec.version, '8.2.17');

  assert.equal(by_name.Nginx.confidence, 'HIGH');
  assert.equal(resolve_technology_version(by_name.Nginx.version_candidates).version_spec.version, '1.24.0');

  assert.equal(by_name.WordPress.confidence, 'HIGH');
  assert.equal(resolve_technology_version(by_name.WordPress.version_candidates).version_spec.version, '6.4.2');
  assert.equal(by_name.WordPress.version_candidates.length > 0, true);

  assert.equal(by_name.Cloudflare.confidence, 'HIGH');
  assert.equal(by_name.React.confidence, 'MEDIUM');
  assert.ok(by_name.PHP.evidence.some((entry) => entry.label.includes('X-Powered-By')));
  assert.ok(by_name.WordPress.evidence.length >= 2);
});

test('does not treat ordinary words as frameworks', () => {
  const detections = fingerprint_response({
    headers: { server: 'nginx' },
    set_cookie: [],
    html: '<html><body>This reactive application uses angular momentum and a bootstrap loader.</body></html>',
    resources: [],
  });
  const names = detections.map((detection) => detection.name);
  assert.equal(names.includes('React'), false);
  assert.equal(names.includes('Vue.js'), false);
  assert.equal(names.includes('Angular'), false);
  assert.equal(names.includes('Bootstrap'), false);
});

test('does not infer the origin server from a CDN response', () => {
  const detections = fingerprint_response({
    headers: { server: 'cloudflare', 'cf-ray': 'abc123' },
    set_cookie: [],
    html: '<html><body>edge</body></html>',
    resources: [],
  });
  const names = detections.map((detection) => detection.name);
  assert.deepEqual(names.sort(), ['Cloudflare']);
});

test('keeps the version unknown when no version evidence exists', () => {
  const detections = fingerprint_response({
    headers: { 'x-powered-by': 'PHP' },
    set_cookie: [],
    html: '',
    resources: [],
  });
  const php = detections.find((detection) => detection.name === 'PHP');
  assert.ok(php);
  const resolution = resolve_technology_version(php.version_candidates);
  assert.equal(resolution.version_spec.kind, 'unknown');
  assert.equal(resolution.status, 'Version unknown');
});

test('resolves an inferred partial version without upgrading it to exact', () => {
  const resolution = resolve_technology_version([
    { value: '1.24', source: 'Server header', disclosed: true, confidence: 86 },
  ]);
  assert.equal(resolution.version_spec.kind, 'partial');
  assert.equal(resolution.version_spec.display, '1.24.x');
  assert.equal(resolution.status, 'Partial version disclosed');
});

test('records a version conflict instead of silently merging values', () => {
  const resolution = resolve_technology_version([
    { value: '6.4.2', source: 'generator meta tag', disclosed: true, confidence: 96 },
    { value: '6.5.0', source: 'asset query string', disclosed: false, confidence: 78 },
  ]);
  assert.equal(resolution.conflict, true);
  assert.equal(resolution.version_spec.version, '6.4.2');
});

test('extracts only http resources and marks cross-origin references', () => {
  const resources = extract_resources(
    '<script src="/app.js"></script><script src="https://cdn.example.net/lib.js"></script><img src="data:image/png;base64,xx">',
    'https://example.com/page',
  );
  assert.equal(resources.length, 2);
  assert.equal(resources[0].same_origin, true);
  assert.equal(resources[1].same_origin, false);
});

test('carries CPE aliases through fingerprinting', () => {
  const detections = fingerprint_response({
    headers: { server: 'nginx/1.24.0' },
    html: '',
  });
  const nginx = detections.find((entry) => entry.name === 'Nginx');
  assert.ok(nginx);
  assert.deepEqual(nginx.cpe_aliases, ['cpe:2.3:a:f5:nginx_open_source']);
});
