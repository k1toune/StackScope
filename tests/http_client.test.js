import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
  HttpClient,
  parse_robots_txt,
  robots_allows,
} from '../src/http_client.js';

function create_fixture_server() {
  return createServer((request, response) => {
    if (request.url === '/') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'x-test': 'root' });
      response.end('<html><body>root</body></html>');
      return;
    }
    if (request.url === '/redirect') {
      response.writeHead(302, { location: '/final' });
      response.end();
      return;
    }
    if (request.url === '/final') {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<html><body>final</body></html>');
      return;
    }
    if (request.url === '/offsite') {
      response.writeHead(302, { location: 'http://otherwise.invalid/landing' });
      response.end();
      return;
    }
    if (request.url === '/slow') {
      setTimeout(() => {
        response.writeHead(200, { 'content-type': 'text/html' });
        response.end('late');
      }, 250);
      return;
    }
    if (request.url === '/big') {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('x'.repeat(4096));
      return;
    }
    if (request.url === '/latin1') {
      response.writeHead(200, { 'content-type': 'text/html; charset=iso-8859-1' });
      response.end(Buffer.from([0xe9]));
      return;
    }
    response.writeHead(404);
    response.end();
  });
}

async function with_server(callback) {
  const server = create_fixture_server();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    await callback(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('follows same-host redirects and returns final headers', async () => {
  await with_server(async (base_url) => {
    const client = new HttpClient();
    const result = await client.request(`${base_url}/redirect`, {
      allowed_hostnames: new Set(['127.0.0.1']),
    });
    assert.equal(result.status, 200);
    assert.equal(result.redirects, 1);
    assert.match(result.body, /final/);
  });
});

test('blocks redirects to another host', async () => {
  await with_server(async (base_url) => {
    const client = new HttpClient();
    await assert.rejects(
      () => client.request(`${base_url}/offsite`, {
        allowed_hostnames: new Set(['127.0.0.1']),
      }),
      (error) => error.code === 'redirect_offsite',
    );
  });
});

test('enforces the body size limit', async () => {
  await with_server(async (base_url) => {
    const client = new HttpClient({ max_body_bytes: 256 });
    const result = await client.request(`${base_url}/big`);
    assert.equal(result.truncated, true);
    assert.equal(result.body_bytes > 256, true);
  });
});

test('times out slow responses', async () => {
  await with_server(async (base_url) => {
    const client = new HttpClient({ timeout_ms: 50 });
    await assert.rejects(
      () => client.request(`${base_url}/slow`),
      (error) => error.name === 'TimeoutError',
    );
  });
});

test('decodes a declared legacy charset', async () => {
  await with_server(async (base_url) => {
    const client = new HttpClient();
    const result = await client.request(`${base_url}/latin1`);
    assert.equal(result.body, 'é');
  });
});

test('parses robots rules with longest-match precedence', () => {
  const robots = parse_robots_txt(`
User-agent: *
Disallow: /private
Allow: /private/public
Crawl-delay: 2

User-agent: stackscope
Disallow: /
`);
  assert.equal(robots_allows(robots, '/'), false);
  assert.equal(robots.crawl_delay_seconds, null);
});

test('falls back to the wildcard robots group', () => {
  const robots = parse_robots_txt(`
User-agent: *
Disallow: /admin
Allow: /admin/public
`);
  assert.equal(robots_allows(robots, '/'), true);
  assert.equal(robots_allows(robots, '/admin'), false);
  assert.equal(robots_allows(robots, '/admin/public/page'), true);
});

test('allow rules win equal-length robots conflicts', () => {
  const robots = parse_robots_txt(`
User-agent: *
Disallow: /page
Allow: /page
`);
  assert.equal(robots_allows(robots, '/page'), true);
});
