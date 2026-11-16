import { APP_NAME, APP_VERSION } from './utils.js';

const DEFAULT_TIMEOUT_MS = 12_000;
const DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_REDIRECTS = 5;

export class HttpClient {
  constructor(options = {}) {
    this.timeout_ms = options.timeout_ms ?? DEFAULT_TIMEOUT_MS;
    this.max_body_bytes = options.max_body_bytes ?? DEFAULT_MAX_BODY_BYTES;
    this.max_redirects = options.max_redirects ?? DEFAULT_MAX_REDIRECTS;
    this.user_agent = options.user_agent
      ?? `${APP_NAME}/${APP_VERSION} (passive technology assessment)`;
    this.signal = options.signal ?? null;
  }

  async request(url, options = {}) {
    const max_body_bytes = options.max_body_bytes ?? this.max_body_bytes;
    const timeout_ms = options.timeout_ms ?? this.timeout_ms;
    const method = options.method ?? 'GET';
    const allowed_hostnames = options.allowed_hostnames ?? null;

    let current_url = url;
    let redirects = 0;

    while (true) {
      const result = await this.perform_request(current_url, {
        method,
        timeout_ms,
        max_body_bytes,
        headers: options.headers ?? {},
      });

      if (result.status >= 300 && result.status < 400 && result.headers.location) {
        if (redirects >= this.max_redirects) {
          throw create_http_error('too many redirects', 'redirect_limit');
        }
        const next_url = new URL(result.headers.location, current_url);
        if (next_url.protocol !== 'http:' && next_url.protocol !== 'https:') {
          throw create_http_error('redirect to an unsupported protocol', 'redirect_protocol');
        }
        if (allowed_hostnames && !hostname_is_allowed(next_url.hostname.toLowerCase(), allowed_hostnames)) {
          throw create_http_error(
            `redirect leaves the target host (${next_url.hostname})`,
            'redirect_offsite',
          );
        }
        redirects += 1;
        current_url = next_url.toString();
        continue;
      }

      return {
        ...result,
        final_url: current_url,
        redirects,
      };
    }
  }

  async perform_request(url, { method, timeout_ms, max_body_bytes, headers }) {
    const timeout_controller = new AbortController();
    let timed_out = false;
    const timer = setTimeout(() => {
      timed_out = true;
      timeout_controller.abort();
    }, timeout_ms);

    const abort_from_parent = () => timeout_controller.abort();
    if (this.signal) {
      if (this.signal.aborted) {
        clearTimeout(timer);
        throw new DOMException('The operation was aborted.', 'AbortError');
      }
      this.signal.addEventListener('abort', abort_from_parent, { once: true });
    }

    try {
      const response = await fetch(url, {
        method,
        redirect: 'manual',
        signal: timeout_controller.signal,
        headers: {
          'user-agent': this.user_agent,
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'accept-language': 'en',
          ...headers,
        },
      });

      const response_headers = {};
      for (const [name, value] of response.headers.entries()) {
        response_headers[name.toLowerCase()] = value;
      }
      const set_cookie = typeof response.headers.getSetCookie === 'function'
        ? response.headers.getSetCookie()
        : [];

      let body = '';
      let body_bytes = 0;
      let truncated = false;

      if (method !== 'HEAD' && response.body) {
        const reader = response.body.getReader();
        const chunks = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          body_bytes += value.byteLength;
          if (body_bytes > max_body_bytes) {
            truncated = true;
            await reader.cancel();
            break;
          }
          chunks.push(value);
        }
        const buffer = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));
        body = decode_body(buffer, response_headers['content-type'] ?? '');
      }

      return {
        status: response.status,
        headers: response_headers,
        set_cookie,
        body,
        body_bytes,
        truncated,
      };
    } catch (error) {
      if (this.signal?.aborted) {
        throw new DOMException('The operation was aborted.', 'AbortError');
      }
      if (timed_out || error.name === 'AbortError') {
        const timeout_error = create_http_error(`request timed out after ${timeout_ms} ms`, 'timeout');
        timeout_error.name = 'TimeoutError';
        throw timeout_error;
      }
      throw create_http_error(error.cause?.message ?? error.message ?? 'network request failed', 'network');
    } finally {
      clearTimeout(timer);
      if (this.signal) {
        this.signal.removeEventListener('abort', abort_from_parent);
      }
    }
  }
}

function decode_body(buffer, content_type) {
  const charset_match = content_type.match(/charset\s*=\s*"?([^";\s]+)/i);
  if (charset_match) {
    try {
      return new TextDecoder(charset_match[1]).decode(buffer);
    } catch {
      // unknown charset from the server, utf-8 is the safest fallback - k1toune
    }
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(buffer);
}

function create_http_error(message, code) {
  const error = new Error(message);
  error.name = 'HttpError';
  error.code = code;
  return error;
}

function hostname_is_allowed(hostname, allowed_hostnames) {
  if (allowed_hostnames.has(hostname)) return true;
  if (hostname.startsWith('www.')) {
    return allowed_hostnames.has(hostname.slice(4));
  }
  return allowed_hostnames.has(`www.${hostname}`);
}

export function parse_robots_txt(text) {
  const groups = [];
  let current_agents = [];
  let current_rules = [];
  let current_crawl_delay = null;

  const flush = () => {
    if (current_agents.length > 0) {
      for (const agent of current_agents) {
        const existing = groups.find((group) => group.agent === agent);
        if (existing) {
          existing.rules.push(...current_rules);
          if (current_crawl_delay !== null) existing.crawl_delay_seconds = current_crawl_delay;
        } else {
          groups.push({
            agent,
            rules: [...current_rules],
            crawl_delay_seconds: current_crawl_delay,
          });
        }
      }
    }
    current_agents = [];
    current_rules = [];
    current_crawl_delay = null;
  };

  for (const raw_line of String(text ?? '').split(/\r?\n/)) {
    const line = raw_line.replace(/#.*$/, '').trim();
    if (line === '') continue;
    const separator = line.indexOf(':');
    if (separator === -1) continue;

    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();

    if (name === 'user-agent') {
      if (current_rules.length > 0 || current_crawl_delay !== null) {
        flush();
      }
      current_agents.push(value.toLowerCase());
      continue;
    }
    if (name === 'allow' || name === 'disallow') {
      if (value === '') continue;
      current_rules.push({ allow: name === 'allow', path: value });
      continue;
    }
    if (name === 'crawl-delay') {
      const parsed = Number.parseFloat(value);
      if (Number.isFinite(parsed) && parsed >= 0) current_crawl_delay = parsed;
    }
  }
  flush();

  const specific = groups.find((group) => group.agent === APP_NAME)
    ?? groups.find((group) => group.agent === '*')
    ?? null;

  return {
    groups,
    rules: specific?.rules ?? [],
    crawl_delay_seconds: specific?.crawl_delay_seconds ?? null,
  };
}

export function robots_allows(robots, path) {
  if (!robots || robots.rules.length === 0) return true;

  const matching_rules = robots.rules.filter((rule) => robots_pattern_matches(rule.path, path));
  if (matching_rules.length === 0) return true;

  matching_rules.sort((left, right) => (
    robots_pattern_length(right.path) - robots_pattern_length(left.path)
    || Number(right.allow) - Number(left.allow)
  ));
  return matching_rules[0].allow;
}

function robots_pattern_length(pattern) {
  return pattern.replace(/[*$]/g, '').length;
}

function robots_pattern_matches(pattern, path) {
  if (pattern === '/') return true;
  let expression = '^';
  for (const character of pattern) {
    if (character === '*') {
      expression += '.*';
    } else if (character === '$') {
      expression += '$';
    } else {
      expression += character.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
  }
  if (!pattern.endsWith('$')) expression += '.*';
  try {
    return new RegExp(expression).test(path);
  } catch {
    return false;
  }
}
