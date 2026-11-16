import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  evaluate_nvd_cve,
  evaluate_osv_vuln,
  format_ranges,
  lookup_vulnerabilities,
} from '../src/cve_lookup.js';
import { make_version_spec } from '../src/utils.js';

const osv_fixture = {
  id: 'GHSA-test-1234',
  aliases: ['CVE-2024-9999'],
  summary: 'Express accepts malformed input',
  details: 'A malformed request can trigger unexpected behavior. Upgrade to a fixed release.',
  published: '2024-02-01T12:00:00Z',
  database_specific: { severity: 'HIGH' },
  references: [{ url: 'https://example.test/osv-advisory' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'express' },
      ranges: [
        {
          type: 'SEMVER',
          events: [{ introduced: '0' }, { fixed: '4.18.3' }],
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
        descriptions: [
          {
            lang: 'en',
            value: 'WordPress core is affected by a version-specific issue. Apply the vendor update.',
          },
        ],
        metrics: {
          cvssMetricV31: [
            {
              cvssData: { baseScore: 8.1, baseSeverity: 'HIGH' },
            },
          ],
        },
        configurations: [
          {
            nodes: [
              {
                operator: 'OR',
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
        references: [{ url: 'https://example.test/nvd-advisory' }],
      },
    },
  ],
};

test('OSV range matching distinguishes confirmed, potential, and outside', () => {
  const package_reference = { ecosystem: 'npm', package: 'express' };
  assert.equal(evaluate_osv_vuln(osv_fixture, make_version_spec('4.18.2'), package_reference).status, 'confirmed');
  assert.equal(evaluate_osv_vuln(osv_fixture, make_version_spec('4.18.3'), package_reference).status, 'not_affected');
  assert.equal(evaluate_osv_vuln(osv_fixture, make_version_spec('4.18'), package_reference).status, 'potential');
  assert.equal(
    evaluate_osv_vuln(osv_fixture, make_version_spec('4.18.2'), { ecosystem: 'PyPI', package: 'flask' }).status,
    'not_affected',
  );
});

test('OSV last_affected is inclusive', () => {
  const advisory = {
    id: 'OSV-test',
    affected: [
      {
        package: { ecosystem: 'npm', name: 'example' },
        ranges: [
          {
            type: 'SEMVER',
            events: [{ introduced: '1.0.0' }, { last_affected: '1.2.5' }],
          },
        ],
      },
    ],
  };
  const package_reference = { ecosystem: 'npm', package: 'example' };
  assert.equal(evaluate_osv_vuln(advisory, make_version_spec('1.2.5'), package_reference).status, 'confirmed');
  assert.equal(evaluate_osv_vuln(advisory, make_version_spec('1.2.6'), package_reference).status, 'not_affected');
});

test('NVD CPE ranges are matched against the technology product', () => {
  const cve = nvd_fixture.vulnerabilities[0].cve;
  assert.equal(evaluate_nvd_cve(cve, make_version_spec('6.4.2'), 'cpe:2.3:a:wordpress:wordpress').status, 'confirmed');
  assert.equal(evaluate_nvd_cve(cve, make_version_spec('6.4.3'), 'cpe:2.3:a:wordpress:wordpress').status, 'not_affected');
  assert.equal(evaluate_nvd_cve(cve, make_version_spec('6.4'), 'cpe:2.3:a:wordpress:wordpress').status, 'potential');
  assert.equal(evaluate_nvd_cve(cve, make_version_spec('6.4.2'), 'cpe:2.3:a:nginx:nginx').status, 'not_affected');
});

test('format_ranges renders inclusive and exclusive bounds', () => {
  assert.equal(
    format_ranges([{ lower: '1.0.0', upper: '2.0.0', upper_inclusive: false }]),
    '>= 1.0.0, < 2.0.0',
  );
  assert.equal(
    format_ranges([{ lower: '1.0.0', upper: '2.0.0', upper_inclusive: true }]),
    '>= 1.0.0, <= 2.0.0',
  );
  assert.equal(format_ranges([]), 'Not specified by source');
});

test('lookup combines OSV and NVD results and deduplicates by CVE', async () => {
  const server = createServer((request, response) => {
    if (request.url.startsWith('/v1/query')) {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ vulns: [osv_fixture] }));
      return;
    }
    if (request.url.startsWith('/rest/json/cves/2.0')) {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(nvd_fixture));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const cache_directory = await mkdtemp(path.join(tmpdir(), 'stackscope-cve-'));

  try {
    const technologies = [
      {
        name: 'Express',
        cpe: null,
        osv: [{ ecosystem: 'npm', package: 'express' }],
        version_spec: make_version_spec('4.18.2'),
      },
      {
        name: 'WordPress',
        cpe: 'cpe:2.3:a:wordpress:wordpress',
        osv: [],
        version_spec: make_version_spec('6.4.2'),
      },
    ];
    const result = await lookup_vulnerabilities(technologies, {
      osv_base_url: `http://127.0.0.1:${address.port}`,
      nvd_base_url: `http://127.0.0.1:${address.port}/rest/json`,
      nvd_delay_ms: 0,
      cache_dir: cache_directory,
    });

    assert.equal(result.unavailable_sources.length, 0);
    assert.equal(result.vulnerabilities.length, 2);
    const express_match = result.vulnerabilities.find((entry) => entry.cve_id === 'CVE-2024-9999');
    assert.equal(express_match.match, 'confirmed');
    assert.equal(express_match.severity, 'HIGH');
    const wordpress_match = result.vulnerabilities.find((entry) => entry.cve_id === 'CVE-2024-1234');
    assert.equal(wordpress_match.match, 'confirmed');
    assert.equal(wordpress_match.score, 8.1);
    assert.deepEqual(wordpress_match.fixed_versions, ['6.4.3']);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(cache_directory, { recursive: true, force: true });
  }
});

test('NVD responses are cached across lookups', async () => {
  let request_count = 0;
  const server = createServer((request, response) => {
    request_count += 1;
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(nvd_fixture));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const cache_directory = await mkdtemp(path.join(tmpdir(), 'stackscope-cve-cache-'));
  const technologies = [
    {
      name: 'WordPress',
      cpe: 'cpe:2.3:a:wordpress:wordpress',
      osv: [],
      version_spec: make_version_spec('6.4.2'),
    },
  ];
  const options = {
    nvd_base_url: `http://127.0.0.1:${address.port}/rest/json`,
    nvd_delay_ms: 0,
    cache_dir: cache_directory,
  };

  try {
    const first = await lookup_vulnerabilities(technologies, options);
    assert.equal(request_count, 1);
    assert.equal(first.vulnerabilities.length, 1);

    await new Promise((resolve) => server.close(resolve));
    const second = await lookup_vulnerabilities(technologies, options);
    assert.equal(request_count, 1);
    assert.equal(second.unavailable_sources.length, 0);
    assert.equal(second.vulnerabilities.length, 1);
  } finally {
    if (server.listening) await new Promise((resolve) => server.close(resolve));
    await rm(cache_directory, { recursive: true, force: true });
  }
});

test('malformed vulnerability APIs do not crash the scan', async () => {
  const server = createServer((request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    if (request.url.startsWith('/v1/query')) {
      response.end(JSON.stringify({ vulns: 'not-an-array' }));
    } else {
      response.end('{not json');
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const cache_directory = await mkdtemp(path.join(tmpdir(), 'stackscope-cve-bad-'));

  try {
    const result = await lookup_vulnerabilities([
      {
        name: 'Express',
        cpe: 'cpe:2.3:a:expressjs:express',
        osv: [{ ecosystem: 'npm', package: 'express' }],
        version_spec: make_version_spec('4.18.2'),
      },
    ], {
      osv_base_url: `http://127.0.0.1:${address.port}`,
      nvd_base_url: `http://127.0.0.1:${address.port}/rest/json`,
      nvd_delay_ms: 0,
      cache_dir: cache_directory,
    });

    assert.deepEqual(result.vulnerabilities, []);
    assert.equal(result.unavailable_sources.some((entry) => entry.source === 'OSV'), true);
    assert.equal(result.unavailable_sources.some((entry) => entry.source === 'NVD'), true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(cache_directory, { recursive: true, force: true });
  }
});

test('unavailable vulnerability APIs are reported, not thrown', async () => {
  const cache_directory = await mkdtemp(path.join(tmpdir(), 'stackscope-cve-down-'));
  try {
    const result = await lookup_vulnerabilities([
      {
        name: 'Express',
        cpe: null,
        osv: [{ ecosystem: 'npm', package: 'express' }],
        version_spec: make_version_spec('4.18.2'),
      },
    ], {
      osv_base_url: 'http://127.0.0.1:1',
      nvd_base_url: 'http://127.0.0.1:1/rest/json',
      nvd_delay_ms: 0,
      cache_dir: cache_directory,
    });

    assert.deepEqual(result.vulnerabilities, []);
    assert.equal(result.unavailable_sources.length, 1);
    assert.equal(result.unavailable_sources[0].source, 'OSV');
  } finally {
    await rm(cache_directory, { recursive: true, force: true });
  }
});

test('NVD rate limits are retried once with Retry-After', async () => {
  let request_count = 0;
  const server = createServer((request, response) => {
    if (!request.url.startsWith('/rest/json/cves/2.0')) {
      response.writeHead(404);
      response.end();
      return;
    }
    request_count += 1;
    if (request_count === 1) {
      response.writeHead(503, {
        'content-type': 'text/plain',
        'retry-after': '1',
      });
      response.end('service unavailable');
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(nvd_fixture));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const cache_directory = await mkdtemp(path.join(tmpdir(), 'stackscope-cve-retry-'));

  try {
    const result = await lookup_vulnerabilities([
      {
        name: 'WordPress',
        cpe: 'cpe:2.3:a:wordpress:wordpress',
        osv: [],
        version_spec: make_version_spec('6.4.2'),
      },
    ], {
      nvd_base_url: `http://127.0.0.1:${address.port}/rest/json`,
      nvd_delay_ms: 0,
      cache_dir: cache_directory,
    });

    assert.equal(request_count, 2);
    assert.equal(result.unavailable_sources.length, 0);
    assert.equal(result.vulnerabilities.length, 1);
    assert.equal(result.vulnerabilities[0].cve_id, 'CVE-2024-1234');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(cache_directory, { recursive: true, force: true });
  }
});

test('NVD platform entries and bare wildcards are not treated as affected versions', () => {
  const platform_cve = {
    id: 'CVE-2024-5555',
    configurations: [
      {
        nodes: [
          {
            cpeMatch: [
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:wordpress:wordpress:-:*:*:*:*:*:*:*',
              },
            ],
          },
        ],
      },
    ],
  };
  const platform_result = evaluate_nvd_cve(
    platform_cve,
    make_version_spec('6.4.2'),
    'cpe:2.3:a:wordpress:wordpress',
  );
  assert.equal(platform_result.status, 'not_affected');
  assert.equal(platform_result.unconstrained_count, 0);

  const wildcard_cve = {
    id: 'CVE-2007-0000',
    configurations: [
      {
        nodes: [
          {
            cpeMatch: [
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*',
              },
            ],
          },
        ],
      },
    ],
  };
  const wildcard_result = evaluate_nvd_cve(
    wildcard_cve,
    make_version_spec('6.4.2'),
    'cpe:2.3:a:wordpress:wordpress',
  );
  assert.equal(wildcard_result.status, 'not_affected');
  assert.equal(wildcard_result.unconstrained_count, 1);
});

test('NVD evaluation accepts product aliases', () => {
  const cve = {
    id: 'CVE-2024-24989',
    configurations: [
      {
        nodes: [
          {
            cpeMatch: [
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:f5:nginx_open_source:1.25.3:*:*:*:*:*:*:*',
              },
            ],
          },
        ],
      },
    ],
  };
  const result = evaluate_nvd_cve(cve, make_version_spec('1.25.3'), [
    'cpe:2.3:a:nginx:nginx',
    'cpe:2.3:a:f5:nginx_open_source',
  ]);
  assert.equal(result.status, 'confirmed');
});
