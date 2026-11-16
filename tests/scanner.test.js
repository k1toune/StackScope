import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as create_http_server } from 'node:http';
import { createServer as create_https_server } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scan_website, ScanError } from '../src/scanner.js';
import { format_report } from '../src/reporter.js';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const osv_fixture = {
  vulns: [
    {
      id: 'GHSA-jquery-test',
      aliases: ['CVE-2024-7777'],
      summary: 'jQuery version-specific issue',
      details: 'An issue affects older jQuery releases.',
      published: '2024-04-01T00:00:00Z',
      database_specific: { severity: 'MEDIUM' },
      references: [{ url: 'https://example.test/jquery' }],
      affected: [
        {
          package: { ecosystem: 'npm', name: 'jquery' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '3.7.1' }] }],
        },
      ],
    },
  ],
};

const nvd_fixture = {
  totalResults: 1,
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-2024-1234',
        published: '2024-03-01T00:00:00.000',
        descriptions: [{ lang: 'en', value: 'WordPress core is affected. Apply the vendor update.' }],
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 8.1, baseSeverity: 'HIGH' } }] },
        configurations: [
          {
            nodes: [
              {
                cpeMatch: [
                  {
                    vulnerable: true,
                    criteria: 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*',
                    versionStartIncluding: '6.0',
                    versionEndExcluding: '6.4.3',
                  },
                ],
              },
            ],
          },
        ],
        references: [{ url: 'https://example.test/wordpress' }],
      },
    },
  ],
};

const wordpress_page = `<!doctype html>
<html>
<head>
  <meta name="generator" content="WordPress 6.4.2">
  <link rel="stylesheet" href="/wp-content/themes/example/style.css">
  <script src="/wp-includes/js/jquery/jquery-3.6.0.min.js"></script>
</head>
<body><h1>Example</h1></body>
</html>`;

async function start_fixture_server(overrides = {}) {
  const server = create_http_server((request, response) => {
    if (overrides.handler && overrides.handler(request, response)) return;

    if (request.url === '/robots.txt') {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('User-agent: *\nAllow: /\n');
      return;
    }
    if (request.url.startsWith('/v1/query')) {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(osv_fixture));
      return;
    }
    if (request.url.startsWith('/rest/json/cves/2.0')) {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(nvd_fixture));
      return;
    }
    if (request.url === '/') {
      response.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        server: 'nginx/1.25.3',
        'x-powered-by': 'PHP/8.2.29',
        'set-cookie': 'PHPSESSID=abc; Path=/; HttpOnly',
      });
      response.end(wordpress_page);
      return;
    }
    response.writeHead(404);
    response.end();
  });
  server.on('clientError', (error, socket) => socket.destroy());
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return server;
}

async function build_scan_options(server, extra = {}) {
  const cache_directory = await mkdtemp(path.join(tmpdir(), 'stackscope-scan-'));
  return {
    options: {
      timeout_ms: 2_000,
      cache_dir: cache_directory,
      osv_base_url: `http://127.0.0.1:${server.address().port}`,
      nvd_base_url: `http://127.0.0.1:${server.address().port}/rest/json`,
      nvd_delay_ms: 0,
      ...extra,
    },
    cleanup: () => rm(cache_directory, { recursive: true, force: true }),
  };
}

test('full scan fingerprints the page and matches CVEs', async () => {
  const server = await start_fixture_server();
  const scan_setup = await build_scan_options(server);
  try {
    const target = `http://127.0.0.1:${server.address().port}`;
    const assessment = await scan_website(target, scan_setup.options);

    assert.equal(assessment.completed, true);
    assert.equal(assessment.http_status, 200);
    assert.equal(assessment.technologies.some((technology) => technology.name === 'PHP'), true);
    assert.equal(assessment.technologies.some((technology) => technology.name === 'WordPress'), true);
    assert.equal(assessment.technologies.some((technology) => technology.name === 'Nginx'), true);
    assert.equal(assessment.technologies.some((technology) => technology.name === 'jQuery'), true);
    assert.equal(assessment.vulnerabilities.length, 2);
    assert.equal(assessment.vulnerabilities.some((entry) => entry.cve_id === 'CVE-2024-1234'), true);
    assert.equal(assessment.vulnerabilities.some((entry) => entry.cve_id === 'CVE-2024-7777'), true);
    assert.equal(assessment.vulnerabilities.find((entry) => entry.cve_id === 'CVE-2024-1234').match, 'confirmed');

    const report = format_report(assessment, { color: false });
    assert.match(report, /WEBSITE SECURITY ASSESSMENT/);
    assert.match(report, /\[01\] TECHNOLOGY FINGERPRINTING/);
    assert.match(report, /CVE-2024-1234/);
    assert.match(report, /Assessment completed\./);
    assert.equal(report.includes('\u001b['), false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await scan_setup.cleanup();
  }
});

test('site that hides its backend produces no invented technologies or CVEs', async () => {
  const server = create_http_server((request, response) => {
    if (request.url === '/robots.txt') {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html', server: 'nginx' });
    response.end('<html><head><title>Static</title></head><body>Hello.</body></html>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const scan_setup = await build_scan_options(server);
  try {
    const assessment = await scan_website(
      `http://127.0.0.1:${server.address().port}`,
      scan_setup.options,
    );
    const nginx = assessment.technologies.find((technology) => technology.name === 'Nginx');
    assert.ok(nginx);
    assert.equal(nginx.version_spec.kind, 'unknown');
    assert.equal(assessment.vulnerabilities.length, 0);
    assert.equal(assessment.technologies.some((technology) => technology.name === 'PHP'), false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await scan_setup.cleanup();
  }
});

test('robots.txt disallow stops the scan before the root page', async () => {
  let root_hits = 0;
  const server = create_http_server((request, response) => {
    if (request.url === '/robots.txt') {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('User-agent: *\nDisallow: /\n');
      return;
    }
    if (request.url === '/') root_hits += 1;
    response.writeHead(200);
    response.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const scan_setup = await build_scan_options(server);
  try {
    await assert.rejects(
      () => scan_website(`http://127.0.0.1:${server.address().port}`, scan_setup.options),
      (error) => error instanceof ScanError && /robots\.txt/.test(error.message),
    );
    assert.equal(root_hits, 0);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await scan_setup.cleanup();
  }
});

test('rate-limited robots.txt stops the scan', async () => {
  const server = create_http_server((request, response) => {
    response.writeHead(429, { 'retry-after': '60' });
    response.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const scan_setup = await build_scan_options(server);
  try {
    await assert.rejects(
      () => scan_website(`http://127.0.0.1:${server.address().port}`, scan_setup.options),
      (error) => error instanceof ScanError && /rate limited/i.test(error.message),
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await scan_setup.cleanup();
  }
});

test('timeouts surface as a scan error, not a crash', async () => {
  const server = create_http_server((request, response) => {
    if (request.url === '/robots.txt') {
      response.writeHead(404);
      response.end();
      return;
    }
    setTimeout(() => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<html></html>');
    }, 300);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const scan_setup = await build_scan_options(server, { timeout_ms: 80 });
  try {
    await assert.rejects(
      () => scan_website(`http://127.0.0.1:${server.address().port}`, scan_setup.options),
      (error) => error instanceof ScanError && /timed out/i.test(error.message),
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await scan_setup.cleanup();
  }
});

test('unreachable targets fail with a scan error', async () => {
  const scan_setup = {
    options: { timeout_ms: 300, nvd_delay_ms: 0 },
    cleanup: async () => {},
  };
  try {
    await assert.rejects(
      () => scan_website('http://127.0.0.1:1', scan_setup.options),
      (error) => error instanceof ScanError,
    );
  } finally {
    await scan_setup.cleanup();
  }
});

test('invalid host input is rejected before any network request', async () => {
  await assert.rejects(
    () => scan_website('not a host', { timeout_ms: 100 }),
    (error) => error instanceof ScanError,
  );
});

test('scans a self-signed HTTPS endpoint automatically', async (t) => {
  const certificate_directory = mkdtempSync(path.join(tmpdir(), 'stackscope-cert-'));
  const key_path = path.join(certificate_directory, 'key.pem');
  const certificate_path = path.join(certificate_directory, 'cert.pem');
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', key_path, '-out', certificate_path,
      '-days', '1', '-subj', '/CN=127.0.0.1',
    ], { stdio: 'ignore' });
  } catch {
    t.skip('openssl is not available for the local HTTPS fixture');
    await rm(certificate_directory, { recursive: true, force: true });
    return;
  }

  const server = create_https_server({
    key: await readFile(key_path),
    cert: await readFile(certificate_path),
  }, (request, response) => {
    if (request.url === '/robots.txt') {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html', 'x-powered-by': 'Express' });
    response.end('<html><body>https</body></html>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const scan_setup = await build_scan_options(server, {
    nvd_delay_ms: 0,
    nvd_base_url: 'http://127.0.0.1:1/rest/json',
  });
  try {
    const assessment = await scan_website(`127.0.0.1:${server.address().port}`, scan_setup.options);
    assert.equal(assessment.scheme, 'https');
    assert.equal(assessment.technologies.some((technology) => technology.name === 'Express'), true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await scan_setup.cleanup();
    await rm(certificate_directory, { recursive: true, force: true });
  }
});
