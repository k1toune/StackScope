import { HttpClient, parse_robots_txt, robots_allows } from './http_client.js';
import {
  extract_page_title,
  extract_resources,
  fingerprint_response,
} from './fingerprint.js';
import { resolve_technology_version } from './version_detector.js';
import { lookup_vulnerabilities } from './cve_lookup.js';
import {
  build_origin,
  normalize_target,
  redact_url_credentials,
  strip_control_characters,
} from './utils.js';

const MAX_ROBOTS_BYTES = 256 * 1024;

export class ScanError extends Error {
  constructor(message, detail = null) {
    super(message);
    this.name = 'ScanError';
    this.detail = detail;
  }
}

export async function scan_website(host_input, options = {}) {
  const started_at = Date.now();
  const target = normalize_target(host_input);
  if (!target.ok) {
    throw new ScanError(target.error);
  }

  const notes = [...target.notes];
  const http = new HttpClient({
    timeout_ms: options.timeout_ms,
    signal: options.signal,
  });
  const allowed_hostnames = new Set([target.hostname]);
  if (target.hostname.startsWith('www.')) {
    allowed_hostnames.add(target.hostname.slice(4));
  } else {
    allowed_hostnames.add(`www.${target.hostname}`);
  }

  const scheme_candidates = target.scheme_was_explicit ? [target.scheme] : ['https', 'http'];
  const selection = await select_origin_with_robots(
    http,
    target,
    scheme_candidates,
    allowed_hostnames,
    options.signal,
  );
  notes.push(...selection.notes);

  const root_response = await fetch_root_page(http, selection.origin, allowed_hostnames);
  const final_hostname = new URL(root_response.final_url).hostname.toLowerCase();
  if (final_hostname !== target.hostname && final_hostname !== `www.${target.hostname}` && `www.${final_hostname}` !== target.hostname) {
    notes.push(`final response came from ${final_hostname} after a redirect`);
  }
  if (final_hostname !== target.hostname) {
    allowed_hostnames.add(final_hostname);
  }
  if (root_response.redirects > 0) {
    notes.push(
      `followed ${root_response.redirects} same-site redirect${root_response.redirects === 1 ? '' : 's'} to ${redact_url_credentials(root_response.final_url)}`,
    );
  }
  if (root_response.truncated) {
    notes.push('the HTML response exceeded the 2 MB inspection limit and was truncated');
  }
  if (root_response.status === 429) {
    notes.push('the target returned HTTP 429; no further requests were made');
  }
  if (root_response.status >= 500 && is_edge_response(root_response.headers)) {
    notes.push('the target returned a CDN-generated error page; origin technology may not be visible');
  }

  const content_type = root_response.headers['content-type'] ?? '';
  if (content_type && !/text\/html|application\/xhtml\+xml/i.test(content_type)) {
    notes.push(`root response content type is ${strip_control_characters(content_type).split(';')[0]}`);
  }

  const resources = extract_resources(root_response.body, root_response.final_url);
  const raw_detections = fingerprint_response({
    headers: root_response.headers,
    set_cookie: root_response.set_cookie,
    html: root_response.body,
    resources,
  });

  const technologies = raw_detections.map((detection) => {
    const resolution = resolve_technology_version(detection.version_candidates);
    if (resolution.conflict) {
      notes.push(`${detection.name}: conflicting public version indicators were found; the strongest one is shown`);
    }
    return {
      ...detection,
      version_spec: resolution.version_spec,
      version_status: resolution.status,
      version_disclosed: resolution.disclosed,
      version_conflict: resolution.conflict,
    };
  });

  const unknown_versions = technologies
    .filter((technology) => technology.version_spec.kind === 'unknown')
    .map((technology) => technology.name);
  if (unknown_versions.length > 0) {
    notes.push(`CVE matching skipped for technologies without a usable version: ${unknown_versions.join(', ')}`);
  }

  const cve_results = await lookup_vulnerabilities(technologies, {
    signal: options.signal,
    cache_dir: options.cache_dir,
    osv_base_url: options.osv_base_url,
    nvd_base_url: options.nvd_base_url,
    nvd_api_key: options.nvd_api_key,
    nvd_delay_ms: options.nvd_delay_ms,
  });

  const completed_at = Date.now();

  return {
    target: target.display_host,
    hostname: target.hostname,
    url: redact_url_credentials(root_response.final_url),
    scheme: selection.scheme,
    http_status: root_response.status,
    page_title: extract_page_title(root_response.body),
    completed: true,
    started_at: new Date(started_at).toISOString(),
    duration_ms: completed_at - started_at,
    technologies,
    vulnerabilities: cve_results.vulnerabilities,
    unknown_version_technologies: cve_results.unknown_version_technologies,
    unavailable_sources: cve_results.unavailable_sources,
    lookup_notes: cve_results.notes,
    notes: [...new Set(notes)],
    sources: ['OSV', 'NVD'],
  };
}

async function select_origin_with_robots(http, target, scheme_candidates, allowed_hostnames, signal) {
  const failures = [];
  const notes = [];

  for (const scheme of scheme_candidates) {
    const origin = build_origin(scheme, target);
    try {
      const robots_response = await http.request(`${origin}/robots.txt`, {
        allowed_hostnames,
        max_body_bytes: MAX_ROBOTS_BYTES,
      });
      if (signal?.aborted) throw new DOMException('The operation was aborted.', 'AbortError');

      const robots_path = new URL(robots_response.final_url).pathname;
      const robots_content_is_valid = robots_path === '/robots.txt';
      if (!robots_content_is_valid) {
        notes.push(`robots.txt redirected to ${robots_path}; treating it as unavailable`);
      }

      if (robots_response.status === 401 || robots_response.status === 403) {
        throw new ScanError('target denies access to robots.txt; refusing to scan');
      }
      if (robots_response.status === 429) {
        throw new ScanError('target rate limited the robots.txt request; refusing to scan');
      }
      if (robots_response.status >= 500) {
        failures.push(`${scheme}: robots.txt returned HTTP ${robots_response.status}`);
        continue;
      }

      if (robots_content_is_valid && robots_response.status >= 200 && robots_response.status < 300) {
        const robots = parse_robots_txt(robots_response.body);
        if (!robots_allows(robots, '/')) {
          throw new ScanError('the site disallows the root path in robots.txt; refusing to scan');
        }
      }

      return { origin, scheme, notes };
    } catch (error) {
      if (error.name === 'AbortError' || error.code === 'redirect_offsite') throw error;
      if (error instanceof ScanError) throw error;
      failures.push(`${scheme}: ${error.message}`);
    }
  }

  throw new ScanError(
    'target could not be reached',
    failures.length > 0 ? failures.join('; ') : 'no usable HTTP or HTTPS endpoint',
  );
}

async function fetch_root_page(http, origin, allowed_hostnames) {
  try {
    return await http.request(`${origin}/`, { allowed_hostnames });
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    throw new ScanError(`failed to fetch the target page: ${error.message}`);
  }
}

function is_edge_response(headers) {
  return Boolean(
    headers['cf-ray']
    || /cloudflare/i.test(headers.server ?? '')
    || headers['x-fastly-request-id']
    || headers['x-amz-cf-id']
    || /akamai/i.test(headers.server ?? ''),
  );
}
