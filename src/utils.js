import { createHash } from 'node:crypto';

export const APP_NAME = 'stackscope';
export const APP_VERSION = '1.0.0';

const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export function normalize_target(input) {
  if (typeof input !== 'string') {
    return { ok: false, error: 'host is required' };
  }

  let raw = input.trim();
  if (raw === '') {
    return { ok: false, error: 'host is empty' };
  }
  if (/\s|[\u0000-\u001f\u007f]/.test(raw)) {
    return { ok: false, error: 'host contains whitespace or control characters' };
  }

  const notes = [];
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    raw = `https://${raw}`;
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: `"${input}" is not a valid hostname or URL` };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, error: `unsupported protocol ${parsed.protocol}` };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: 'credentials in the target URL are not accepted' };
  }

  let hostname = parsed.hostname.toLowerCase();
  if (hostname.endsWith('.')) {
    hostname = hostname.slice(0, -1);
  }
  if (hostname === '') {
    return { ok: false, error: 'hostname is empty' };
  }

  const is_ipv6 = hostname.startsWith('[') && hostname.endsWith(']');
  if (!is_ipv6 && !HOSTNAME_PATTERN.test(hostname) && !IPV4_PATTERN.test(hostname)) {
    return { ok: false, error: `"${hostname}" is not a valid hostname` };
  }
  if (IPV4_PATTERN.test(hostname)) {
    const octets = hostname.split('.').map(Number);
    if (octets.some((octet) => octet > 255)) {
      return { ok: false, error: `"${hostname}" is not a valid IPv4 address` };
    }
  }

  if (parsed.pathname !== '/' || parsed.search !== '' || parsed.hash !== '') {
    notes.push('path, query, and fragment were ignored; only the origin is scanned');
  }

  const default_port = parsed.protocol === 'https:' ? '443' : '80';
  const explicit_port = parsed.port !== '' && parsed.port !== default_port ? parsed.port : '';
  const host_for_url = is_ipv6 ? hostname : hostname;
  const display_host = explicit_port ? `${strip_ipv6_brackets(host_for_url)}:${explicit_port}` : strip_ipv6_brackets(host_for_url);

  return {
    ok: true,
    hostname,
    host_for_url,
    display_host,
    scheme: parsed.protocol === 'https:' ? 'https' : 'http',
    scheme_was_explicit: /^[a-z][a-z0-9+.-]*:\/\//i.test(input.trim()),
    port: explicit_port,
    notes,
  };
}

export function strip_ipv6_brackets(hostname) {
  return hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;
}

export function build_origin(scheme, target) {
  return `${scheme}://${target.host_for_url}${target.port ? `:${target.port}` : ''}`;
}

export function compare_versions(left, right) {
  const a = split_version(left);
  const b = split_version(right);
  const length = Math.max(a.parts.length, b.parts.length, 3);

  for (let index = 0; index < length; index += 1) {
    const left_part = a.parts[index] ?? { number: 0, suffix: '' };
    const right_part = b.parts[index] ?? { number: 0, suffix: '' };

    if (left_part.number !== right_part.number) {
      return left_part.number > right_part.number ? 1 : -1;
    }
    if (left_part.suffix !== right_part.suffix) {
      if (left_part.suffix === '') return 1;
      if (right_part.suffix === '') return -1;
      return left_part.suffix > right_part.suffix ? 1 : -1;
    }
  }

  if (a.prerelease.length === 0 && b.prerelease.length > 0) return 1;
  if (a.prerelease.length > 0 && b.prerelease.length === 0) return -1;
  for (let index = 0; index < Math.max(a.prerelease.length, b.prerelease.length); index += 1) {
    const left_token = a.prerelease[index] ?? '0';
    const right_token = b.prerelease[index] ?? '0';
    if (left_token === right_token) continue;
    const left_number = Number(left_token);
    const right_number = Number(right_token);
    if (Number.isFinite(left_number) && Number.isFinite(right_number)) {
      return left_number > right_number ? 1 : -1;
    }
    return left_token > right_token ? 1 : -1;
  }

  return 0;
}

function split_version(value) {
  const text = String(value ?? '').trim().replace(/^v/i, '');
  const without_build = text.split('+')[0];
  const dash_index = without_build.indexOf('-');
  const core = dash_index === -1 ? without_build : without_build.slice(0, dash_index);
  const prerelease = dash_index === -1 ? [] : without_build.slice(dash_index + 1).split('.');

  const parts = core.split('.').map((part) => {
    const match = part.match(/^(\d+)(.*)$/);
    if (match) {
      return { number: Number(match[1]), suffix: match[2] };
    }
    return { number: 0, suffix: part };
  });

  return { parts, prerelease };
}

export function make_version_spec(raw_value, metadata = {}) {
  const text = String(raw_value ?? '').trim();
  const match = text.match(/(\d+(?:\.\d+)*)(?:\.([xX*]))?/);
  if (!match) {
    return { kind: 'unknown', display: 'Unknown', source: metadata.source ?? null };
  }

  const numeric = match[1];
  const wildcard = match[2] !== undefined;
  const groups = numeric.split('.').map(Number);
  const is_exact = !wildcard && groups.length >= 3;

  if (is_exact) {
    return {
      kind: 'exact',
      version: numeric,
      display: numeric,
      source: metadata.source ?? null,
      disclosed: metadata.disclosed ?? null,
    };
  }

  const width = Math.max(groups.length, 3);
  const lower_parts = Array.from({ length: width }, (_, index) => groups[index] ?? 0);
  const upper_parts = [...lower_parts];
  upper_parts[groups.length - 1] += 1;
  for (let index = groups.length; index < width; index += 1) {
    upper_parts[index] = 0;
  }

  return {
    kind: 'partial',
    display: `${groups.join('.')}.x`,
    lower: lower_parts.join('.'),
    upper: upper_parts.join('.'),
    source: metadata.source ?? null,
    disclosed: metadata.disclosed ?? null,
  };
}

export function version_spec_intersects(lower, upper, version_spec) {
  if (version_spec.kind === 'unknown') return false;
  if (version_spec.kind === 'exact') {
    return compare_versions(version_spec.version, lower) >= 0
      && (upper === null || compare_versions(version_spec.version, upper) < 0);
  }
  if (compare_versions(version_spec.upper, lower) <= 0) return false;
  if (upper !== null && compare_versions(version_spec.lower, upper) >= 0) return false;
  return true;
}

export function version_spec_contains(version_spec, version) {
  if (version_spec.kind === 'exact') {
    return compare_versions(version_spec.version, version) === 0;
  }
  if (version_spec.kind === 'partial') {
    return compare_versions(version, version_spec.lower) >= 0
      && compare_versions(version, version_spec.upper) < 0;
  }
  return false;
}

export function format_version_spec(version_spec) {
  if (!version_spec || version_spec.kind === 'unknown') return 'Unknown';
  return version_spec.display;
}

export function normalize_severity(value) {
  const text = String(value ?? '').trim().toUpperCase();
  if (text === 'MODERATE') return 'MEDIUM';
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(text)) return text;
  if (text === 'IMPORTANT') return 'HIGH';
  if (text === 'MODERATE') return 'MEDIUM';
  if (text === 'UNIMPORTANT' || text === 'NEGLIGIBLE') return 'LOW';
  return 'UNKNOWN';
}

export function severity_rank(severity) {
  return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 }[severity] ?? 0;
}

export function format_duration(milliseconds) {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return 'unknown';
  if (milliseconds < 1000) return `${Math.round(milliseconds)} ms`;
  const seconds = milliseconds / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} seconds`;
  const minutes = Math.floor(seconds / 60);
  const remaining = Math.round(seconds % 60);
  return `${minutes}m ${remaining}s`;
}

export function strip_control_characters(text) {
  return String(text ?? '')
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '')
    .replace(/\r?\n/g, ' ');
}

export function truncate(text, maximum) {
  const clean = strip_control_characters(text);
  if (clean.length <= maximum) return clean;
  return `${clean.slice(0, Math.max(0, maximum - 3)).trimEnd()}...`;
}

export function redact_url_credentials(url) {
  try {
    const parsed = new URL(url);
    parsed.username = '';
    parsed.password = '';
    return parsed.toString();
  } catch {
    return url;
  }
}

export function stable_hash(value) {
  return createHash('sha256').update(value).digest('hex');
}
