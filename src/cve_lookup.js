import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  compare_versions,
  normalize_severity,
  severity_rank,
  stable_hash,
  strip_control_characters,
  truncate,
} from './utils.js';

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_OSV_VULNS_PER_TECHNOLOGY = 250;
const MAX_NVD_TECHNOLOGIES = 12;
const MAX_NVD_REQUESTS_WITHOUT_KEY = 14;
const OSV_CONCURRENCY = 3;

export async function lookup_vulnerabilities(technologies, options = {}) {
  const notes = [];
  const unavailable_sources = [];
  const cache_directory = options.cache_dir
    ?? process.env.STACKSCOPE_CACHE_DIR
    ?? path.join(os.homedir(), '.cache', 'stackscope');
  const osv_base_url = (options.osv_base_url
    ?? process.env.STACKSCOPE_OSV_BASE_URL
    ?? 'https://api.osv.dev').replace(/\/$/, '');
  const nvd_base_url = (options.nvd_base_url
    ?? process.env.STACKSCOPE_NVD_BASE_URL
    ?? 'https://services.nvd.nist.gov/rest/json').replace(/\/$/, '');
  const nvd_api_key = options.nvd_api_key ?? process.env.NVD_API_KEY ?? null;
  const nvd_delay_ms = options.nvd_delay_ms
    ?? number_from_environment('STACKSCOPE_NVD_DELAY_MS')
    ?? (nvd_api_key ? 700 : 6_500);

  const versioned = technologies.filter((technology) => technology.version_spec.kind !== 'unknown');
  const unknown = technologies.filter((technology) => technology.version_spec.kind === 'unknown');

  if (versioned.length === 0) {
    return {
      vulnerabilities: [],
      unknown_version_technologies: unknown.map((technology) => technology.name),
      unavailable_sources,
      notes,
    };
  }

  const collected = [];

  const osv_technologies = versioned.filter((technology) => technology.osv.length > 0);
  const osv_results = await run_bounded(osv_technologies, OSV_CONCURRENCY, async (technology) => {
    try {
      return await lookup_osv_for_technology(technology, {
        osv_base_url,
        cache_directory,
        signal: options.signal,
        notes,
      });
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      unavailable_sources.push({
        source: 'OSV',
        reason: `${technology.name}: ${error.message}`,
      });
      return [];
    }
  });
  for (const result of osv_results) {
    if (result) collected.push(...result);
  }

  const nvd_technologies = versioned
    .filter((technology) => technology.cpe)
    .slice(0, MAX_NVD_TECHNOLOGIES);
  if (versioned.filter((technology) => technology.cpe).length > MAX_NVD_TECHNOLOGIES) {
    notes.push(`NVD lookups were limited to ${MAX_NVD_TECHNOLOGIES} technologies to respect API rate limits.`);
  }

  const nvd_state = {
    last_request_at: 0,
    delay_ms: nvd_delay_ms,
    requests_made: 0,
    max_requests: nvd_api_key ? 60 : MAX_NVD_REQUESTS_WITHOUT_KEY,
  };
  for (const technology of nvd_technologies) {
    try {
      const results = await lookup_nvd_for_technology(technology, {
        nvd_base_url,
        nvd_api_key,
        cache_directory,
        signal: options.signal,
        notes,
        nvd_state,
      });
      collected.push(...results);
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      unavailable_sources.push({
        source: 'NVD',
        reason: `${technology.name}: ${error.message}`,
      });
    }
  }

  const vulnerabilities = deduplicate_vulnerabilities(collected);

  return {
    vulnerabilities,
    unknown_version_technologies: unknown.map((technology) => technology.name),
    unavailable_sources: deduplicate_sources(unavailable_sources),
    notes: [...new Set(notes)],
  };
}

async function lookup_osv_for_technology(technology, context) {
  const results = [];
  for (const package_reference of technology.osv) {
    const payload = { package: package_reference };
    if (technology.version_spec.kind === 'exact') {
      payload.version = technology.version_spec.version;
    }
    const cache_key = stable_hash(`osv:${JSON.stringify(payload)}`);
    let response = await read_cache(context.cache_directory, cache_key);

    if (!response) {
      response = await fetch_json(`${context.osv_base_url}/v1/query`, {
        method: 'POST',
        body: payload,
        signal: context.signal,
        cache_directory: context.cache_directory,
        cache_key,
      });
    }

    if (!response || !Array.isArray(response.vulns)) {
      throw new Error('malformed response from OSV');
    }
    if (response.next_page_token) {
      context.notes.push('OSV returned paginated results; only the first page was assessed.');
    }

    let counted = 0;
    for (const vulnerability of response.vulns) {
      if (counted >= MAX_OSV_VULNS_PER_TECHNOLOGY) {
        context.notes.push(`OSV advisory list for ${technology.name} was truncated at ${MAX_OSV_VULNS_PER_TECHNOLOGY}.`);
        break;
      }
      const evaluation = evaluate_osv_vuln(vulnerability, technology.version_spec, package_reference);
      if (evaluation.status === 'not_affected' || evaluation.status === 'insufficient') continue;
      counted += 1;
      results.push(adapt_osv_vulnerability(vulnerability, evaluation, technology, package_reference));
    }
  }
  return results;
}

async function lookup_nvd_for_technology(technology, context) {
  // vendor names move around in CPE data (nginx became f5:nginx), so match on
  // the product and let the local product filter do the rest - k1toune
  const cpe_list = technology_cpe_list(technology);
  const products = [...new Set(cpe_list.map((cpe) => product_from_cpe(cpe)).filter(Boolean))];
  const cves = new Map();
  let successful_requests = 0;
  let last_error = null;

  for (const product of products) {
    const parameters = new URLSearchParams({
      virtualMatchString: `cpe:2.3:a:*:${product}`,
      resultsPerPage: '2000',
      noRejected: '',
    });
    const request_url = `${context.nvd_base_url}/cves/2.0?${parameters.toString()}`;

    try {
      const response = await fetch_nvd_response(request_url, context);
      if (!response || !Array.isArray(response.vulnerabilities)) {
        throw new Error('malformed response from NVD');
      }
      successful_requests += 1;
      for (const wrapper of response.vulnerabilities) {
        const cve = wrapper?.cve;
        if (!cve?.id) continue;
        if (!cves.has(cve.id)) cves.set(cve.id, cve);
      }
      if (response.totalResults > (response.vulnerabilities?.length ?? 0)) {
        context.notes.push(`NVD returned ${response.vulnerabilities.length} of ${response.totalResults} records for ${technology.name} (${product}).`);
      }
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      last_error = error;
      if (error.code === 'nvd_budget') {
        context.notes.push('NVD request budget was reached; remaining NVD lookups were skipped.');
        break;
      }
    }
  }

  if (successful_requests === 0) {
    throw last_error ?? new Error('no NVD query completed');
  }
  if (last_error) {
    context.notes.push(`${technology.name}: partial NVD coverage (${last_error.message}).`);
  }

  const results = [];
  let unconstrained_records = 0;
  for (const cve of cves.values()) {
    const evaluation = evaluate_nvd_cve(cve, technology.version_spec, cpe_list);
    if ((evaluation.unconstrained_count ?? 0) > 0) unconstrained_records += 1;
    if (evaluation.status === 'not_affected') continue;
    results.push(adapt_nvd_vulnerability(cve, evaluation, technology));
  }

  if (unconstrained_records > 0) {
    context.notes.push(
      `${technology.name}: ${unconstrained_records} NVD records had no machine-readable version range and were not matched.`,
    );
  }

  return results;
}

async function fetch_nvd_response(request_url, context) {
  const cache_key = stable_hash(`nvd:${request_url}`);
  const cached = await read_cache(context.cache_directory, cache_key);
  if (cached) return cached;

  if (context.nvd_state.requests_made >= context.nvd_state.max_requests) {
    const budget_error = new Error('NVD request budget exhausted');
    budget_error.code = 'nvd_budget';
    throw budget_error;
  }
  context.nvd_state.requests_made += 1;

  const headers = { accept: 'application/json' };
  if (context.nvd_api_key) headers.apiKey = context.nvd_api_key;

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const wait_ms = Math.max(0, context.nvd_state.delay_ms - (Date.now() - context.nvd_state.last_request_at));
    if (wait_ms > 0) await sleep(wait_ms, context.signal);
    context.nvd_state.last_request_at = Date.now();

    try {
      return await fetch_json(request_url, {
        headers,
        signal: context.signal,
        cache_directory: context.cache_directory,
        cache_key,
      });
    } catch (error) {
      const retryable = error.status === 429 || error.status === 503;
      if (!retryable || attempt === 1) throw error;
      const retry_delay_ms = Math.min(15_000, (error.retry_after_seconds ?? 8) * 1000);
      await sleep(retry_delay_ms, context.signal);
    }
  }

  throw new Error('NVD request failed');
}

export function evaluate_osv_vuln(vulnerability, version_spec, package_reference = null) {
  if (!vulnerability || version_spec.kind === 'unknown') {
    return { status: 'insufficient', ranges: [], fixed_versions: [] };
  }

  const affected_entries = Array.isArray(vulnerability.affected) ? vulnerability.affected : [];
  const relevant_entries = package_reference
    ? affected_entries.filter((entry) => (
      entry?.package?.ecosystem === package_reference.ecosystem
      && entry?.package?.name === package_reference.package
    ))
    : affected_entries;

  let best_status = 'not_affected';
  const matched_ranges = [];
  const fixed_versions = [];

  for (const entry of relevant_entries) {
    const explicit_versions = Array.isArray(entry?.versions) ? entry.versions : [];

    if (version_spec.kind === 'exact') {
      const exact_match = explicit_versions.some((version) => compare_versions(version, version_spec.version) === 0);
      if (exact_match) {
        best_status = 'confirmed';
      }
    } else if (version_spec.kind === 'partial') {
      const listed_intersection = explicit_versions.some((version) => (
        compare_versions(version, version_spec.lower) >= 0
        && compare_versions(version, version_spec.upper) < 0
      ));
      if (listed_intersection) best_status = 'potential';
    }

    const ranges = Array.isArray(entry?.ranges) ? entry.ranges : [];
    for (const range of ranges) {
      const intervals = osv_range_intervals(range);
      for (const interval of intervals) {
        const status = match_interval(interval, version_spec);
        if (status === 'confirmed') {
          best_status = 'confirmed';
          matched_ranges.push(interval);
        } else if (status === 'potential') {
          if (best_status !== 'confirmed') best_status = 'potential';
          matched_ranges.push(interval);
        }
      }
      for (const event of range.events ?? []) {
        if (event?.fixed) fixed_versions.push(event.fixed);
      }
    }
  }

  const threshold = version_spec.kind === 'exact' ? version_spec.version : version_spec.lower;
  const relevant_fixes = [...new Set(fixed_versions)]
    .filter((version) => compare_versions(version, threshold) > 0)
    .sort(compare_versions);

  return {
    status: best_status,
    ranges: deduplicate_ranges(matched_ranges),
    fixed_versions: relevant_fixes,
  };
}

function osv_range_intervals(range) {
  const intervals = [];
  let current_start = null;

  for (const event of range?.events ?? []) {
    if (!event || typeof event !== 'object') continue;
    if (typeof event.introduced === 'string') {
      current_start = event.introduced;
      continue;
    }
    if (typeof event.fixed === 'string') {
      intervals.push({
        lower: current_start ?? '0',
        upper: event.fixed,
        upper_inclusive: false,
      });
      current_start = null;
      continue;
    }
    if (typeof event.last_affected === 'string') {
      intervals.push({
        lower: current_start ?? '0',
        upper: event.last_affected,
        upper_inclusive: true,
      });
      current_start = null;
      continue;
    }
    if (typeof event.limit === 'string') {
      intervals.push({
        lower: current_start ?? '0',
        upper: event.limit,
        upper_inclusive: false,
      });
      current_start = null;
    }
  }

  if (current_start !== null) {
    intervals.push({ lower: current_start, upper: null, upper_inclusive: false });
  }

  return intervals;
}

function match_interval(interval, version_spec) {
  const lower = interval.lower ?? '0';
  const upper = interval.upper ?? null;

  if (version_spec.kind === 'exact') {
    if (compare_versions(version_spec.version, lower) < 0) return 'not_affected';
    if (upper === null) return 'confirmed';
    const comparison = compare_versions(version_spec.version, upper);
    if (comparison < 0) return 'confirmed';
    if (comparison === 0 && interval.upper_inclusive) return 'confirmed';
    return 'not_affected';
  }

  if (version_spec.kind === 'partial') {
    if (compare_versions(version_spec.upper, lower) <= 0) return 'not_affected';
    if (upper !== null) {
      if (interval.upper_inclusive) {
        if (compare_versions(version_spec.lower, upper) > 0) return 'not_affected';
      } else if (compare_versions(version_spec.lower, upper) >= 0) {
        return 'not_affected';
      }
    }
    return 'potential';
  }

  return 'insufficient';
}

export function evaluate_nvd_cve(cve, version_spec, technology_cpe) {
  if (!cve || version_spec.kind === 'unknown') {
    return { status: 'not_affected', matches: [], unconstrained_count: 0 };
  }

  const cpe_inputs = Array.isArray(technology_cpe) ? technology_cpe : [technology_cpe];
  const products = new Set(
    cpe_inputs.filter(Boolean).map((cpe) => product_from_cpe(cpe)).filter(Boolean),
  );
  const nodes = [];
  for (const configuration of cve.configurations ?? []) {
    for (const node of configuration?.nodes ?? []) {
      nodes.push(node);
    }
  }

  const matches = [];
  let unconstrained_count = 0;
  for (const node of nodes) {
    for (const cpe_match of node?.cpeMatch ?? []) {
      if (!cpe_match?.vulnerable) continue;
      const criteria_product = product_from_cpe(cpe_match.criteria);
      if (products.size > 0 && criteria_product && !products.has(criteria_product)) continue;
      const evaluation = evaluate_cpe_match(cpe_match, version_spec);
      if (evaluation.status === 'unconstrained') {
        unconstrained_count += 1;
        continue;
      }
      if (evaluation.status !== 'not_affected') {
        matches.push({ cpe_match, status: evaluation.status, range: evaluation.range });
      }
    }
  }

  if (matches.some((entry) => entry.status === 'confirmed')) {
    return { status: 'confirmed', matches, unconstrained_count: unconstrained_count };
  }
  if (matches.length > 0) {
    return { status: 'potential', matches, unconstrained_count: unconstrained_count };
  }
  return { status: 'not_affected', matches: [], unconstrained_count: unconstrained_count };
}

function evaluate_cpe_match(cpe_match, version_spec) {
  const criteria_version = cpe_match.criteria?.split(':')[5] ?? '*';
  const has_bounds = Boolean(
    cpe_match.versionStartIncluding
    || cpe_match.versionStartExcluding
    || cpe_match.versionEndIncluding
    || cpe_match.versionEndExcluding,
  );
  const concrete_version = criteria_version !== '*' && criteria_version !== '-' ? criteria_version : null;

  if (!has_bounds && !concrete_version) {
    // a bare '*' CPE says nothing about affected versions; '-' is used by NVD
    // for platform entries - k1toune
    if (criteria_version === '-') {
      return { status: 'not_affected', range: null };
    }
    return { status: 'unconstrained', range: null };
  }

  if (concrete_version) {
    if (version_spec.kind === 'exact') {
      return {
        status: compare_versions(version_spec.version, concrete_version) === 0 ? 'confirmed' : 'not_affected',
        range: { lower: concrete_version, upper: concrete_version, upper_inclusive: true },
      };
    }
    const inside = compare_versions(concrete_version, version_spec.lower) >= 0
      && compare_versions(concrete_version, version_spec.upper) < 0;
    return {
      status: inside ? 'potential' : 'not_affected',
      range: { lower: concrete_version, upper: concrete_version, upper_inclusive: true },
    };
  }

  const interval = {
    lower: cpe_match.versionStartIncluding ?? cpe_match.versionStartExcluding ?? '0',
    upper: cpe_match.versionEndIncluding ?? cpe_match.versionEndExcluding ?? null,
    upper_inclusive: Boolean(cpe_match.versionEndIncluding),
  };

  const status = match_interval(interval, version_spec);
  if (status === 'not_affected') return { status, range: null };

  if (
    version_spec.kind === 'exact'
    && cpe_match.versionStartExcluding
    && compare_versions(version_spec.version, cpe_match.versionStartExcluding) === 0
  ) {
    return { status: 'not_affected', range: null };
  }

  return { status, range: interval };
}

function adapt_osv_vulnerability(vulnerability, evaluation, technology, package_reference) {
  const aliases = Array.isArray(vulnerability.aliases) ? vulnerability.aliases : [];
  const cve_id = [vulnerability.id, ...aliases].find((identifier) => /^CVE-\d{4}-\d+$/i.test(identifier ?? '')) ?? null;
  const severity = normalize_severity(
    vulnerability.database_specific?.severity
    ?? vulnerability.database_specific?.cvss?.severity
    ?? null,
  );
  const score = number_or_null(vulnerability.database_specific?.cvss?.score);
  const details = pick_description(vulnerability);
  const references = collect_references(vulnerability.references);

  return {
    id: cve_id ?? vulnerability.id ?? 'UNKNOWN',
    source_id: vulnerability.id ?? 'UNKNOWN',
    cve_id,
    title: truncate(vulnerability.summary ?? first_sentence(details) ?? vulnerability.id ?? 'Untitled advisory', 180),
    description: truncate(details, 600),
    severity,
    score,
    sources: ['OSV'],
    technologies: [technology.name],
    package: `${package_reference.ecosystem}:${package_reference.package}`,
    match: evaluation.status,
    affected_versions: [format_ranges(evaluation.ranges)],
    fixed_versions: evaluation.fixed_versions.slice(0, 8),
    published: normalize_date(vulnerability.published ?? vulnerability.modified),
    references,
    aliases,
  };
}

function adapt_nvd_vulnerability(cve, evaluation, technology) {
  const details = cve.descriptions?.find((entry) => entry?.lang === 'en')?.value ?? '';
  const metrics = extract_cvss(cve.metrics);
  const matched_ranges = evaluation.matches
    .map((entry) => entry.range)
    .filter(Boolean);
  const fixed_versions = evaluation.matches
    .map((entry) => entry.cpe_match?.versionEndExcluding)
    .filter(Boolean);

  return {
    id: cve.id,
    source_id: cve.id,
    cve_id: cve.id,
    title: truncate(first_sentence(details) ?? cve.id, 180),
    description: truncate(details, 600),
    severity: metrics.severity,
    score: metrics.score,
    sources: ['NVD'],
    technologies: [technology.name],
    package: technology.cpe,
    match: evaluation.status,
    affected_versions: [format_ranges(deduplicate_ranges(matched_ranges))],
    fixed_versions: [...new Set(fixed_versions)].sort(compare_versions),
    published: normalize_date(cve.published),
    references: collect_references(cve.references?.map((reference) => ({ url: reference.url }))),
    aliases: [],
  };
}

function extract_cvss(metrics) {
  if (!metrics || typeof metrics !== 'object') return { severity: 'UNKNOWN', score: null };
  const ordered_keys = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];
  for (const key of ordered_keys) {
    const entries = Array.isArray(metrics[key]) ? metrics[key] : [];
    for (const entry of entries) {
      const data = entry?.cvssData;
      if (!data) continue;
      const score = number_or_null(data.baseScore);
      const severity = normalize_severity(data.baseSeverity ?? severity_from_score(score));
      return { severity, score };
    }
  }
  return { severity: 'UNKNOWN', score: null };
}

function severity_from_score(score) {
  if (score === null) return 'UNKNOWN';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'UNKNOWN';
}

function deduplicate_ranges(ranges) {
  const seen = new Set();
  const unique = [];
  for (const range of ranges) {
    const key = `${range.lower}|${range.upper}|${range.upper_inclusive}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(range);
  }
  return unique;
}

export function format_ranges(ranges) {
  if (!Array.isArray(ranges) || ranges.length === 0) return 'Not specified by source';
  const texts = ranges.slice(0, 3).map((range) => {
    const parts = [];
    if (range.lower && range.lower !== '0') parts.push(`>= ${range.lower}`);
    if (range.upper) parts.push(`${range.upper_inclusive ? '<=' : '<'} ${range.upper}`);
    if (parts.length === 0) return 'All versions';
    return parts.join(', ');
  });
  if (ranges.length > 3) texts.push(`+${ranges.length - 3} more ranges`);
  return texts.join(' | ');
}

function deduplicate_vulnerabilities(vulnerabilities) {
  const by_identifier = new Map();

  for (const vulnerability of vulnerabilities) {
    const key = vulnerability.cve_id ?? vulnerability.id;
    const existing = by_identifier.get(key);
    if (!existing) {
      by_identifier.set(key, vulnerability);
      continue;
    }

    existing.sources = [...new Set([...existing.sources, ...vulnerability.sources])];
    existing.technologies = [...new Set([...existing.technologies, ...vulnerability.technologies])];
    existing.references = [...new Set([...existing.references, ...vulnerability.references])];
    existing.fixed_versions = [...new Set([...existing.fixed_versions, ...vulnerability.fixed_versions])];
    existing.aliases = [...new Set([...existing.aliases, ...vulnerability.aliases])];
    if (vulnerability.match === 'confirmed') existing.match = 'confirmed';
    if (severity_rank(vulnerability.severity) > severity_rank(existing.severity)) {
      existing.severity = vulnerability.severity;
    }
    if (existing.score === null && vulnerability.score !== null) {
      existing.score = vulnerability.score;
    }
    if (existing.title === 'Untitled advisory' && vulnerability.title) {
      existing.title = vulnerability.title;
    }
    if (!existing.published && vulnerability.published) existing.published = vulnerability.published;
    const existing_affected = existing.affected_versions.join(' ');
    const incoming_affected = vulnerability.affected_versions.join(' ');
    if (existing_affected !== incoming_affected) {
      existing.affected_versions = [...new Set([...existing.affected_versions, ...vulnerability.affected_versions])];
    }
  }

  return [...by_identifier.values()].sort((left, right) => {
    const match_difference = Number(right.match === 'confirmed') - Number(left.match === 'confirmed');
    if (match_difference !== 0) return match_difference;
    const severity_difference = severity_rank(right.severity) - severity_rank(left.severity);
    if (severity_difference !== 0) return severity_difference;
    if ((right.score ?? 0) !== (left.score ?? 0)) return (right.score ?? 0) - (left.score ?? 0);
    return (right.published ?? '').localeCompare(left.published ?? '');
  });
}

function deduplicate_sources(sources) {
  const seen = new Map();
  for (const source of sources) {
    const key = `${source.source}|${source.reason}`;
    if (!seen.has(key)) seen.set(key, source);
  }
  return [...seen.values()];
}

async function fetch_json(url, options = {}) {
  const timeout_controller = new AbortController();
  const timer = setTimeout(() => timeout_controller.abort(), DEFAULT_TIMEOUT_MS);
  const forward_abort = () => timeout_controller.abort();
  if (options.signal) {
    if (options.signal.aborted) {
      clearTimeout(timer);
      throw new DOMException('The operation was aborted.', 'AbortError');
    }
    options.signal.addEventListener('abort', forward_abort, { once: true });
  }

  try {
    const response = await fetch(url, {
      method: options.method ?? 'GET',
      signal: timeout_controller.signal,
      headers: {
        'user-agent': 'stackscope/1.0 vulnerability-lookup',
        ...(options.headers ?? {}),
        ...(options.body ? { 'content-type': 'application/json' } : {}),
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    if (!response.ok) {
      const hint = response.status === 403 || response.status === 429
        ? 'rate limited or blocked'
        : (response.statusText || 'request failed');
      const error = new Error(`HTTP ${response.status} (${hint})`);
      error.status = response.status;
      const retry_after = Number(response.headers.get('retry-after'));
      if (Number.isFinite(retry_after) && retry_after > 0) {
        error.retry_after_seconds = retry_after;
      }
      throw error;
    }

    const text = await response.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error('response was not valid JSON');
    }
    if (options.cache_directory && options.cache_key) {
      await write_cache(options.cache_directory, options.cache_key, parsed);
    }
    return parsed;
  } catch (error) {
    if (options.signal?.aborted) {
      throw new DOMException('The operation was aborted.', 'AbortError');
    }
    if (error.name === 'AbortError') {
      throw new Error('request timed out');
    }
    throw error;
  } finally {
    clearTimeout(timer);
    if (options.signal) {
      options.signal.removeEventListener('abort', forward_abort);
    }
  }
}

function cache_file(cache_directory, cache_key) {
  return path.join(cache_directory, `${cache_key}.json`);
}

async function read_cache(cache_directory, cache_key) {
  try {
    const raw = await fs.readFile(cache_file(cache_directory, cache_key), 'utf8');
    const parsed = JSON.parse(raw);
    if (typeof parsed?.expires_at !== 'number' || parsed.expires_at < Date.now()) {
      return null;
    }
    return parsed.payload;
  } catch {
    return null;
  }
}

async function write_cache(cache_directory, cache_key, payload) {
  try {
    await fs.mkdir(cache_directory, { recursive: true });
    const record = JSON.stringify({ expires_at: Date.now() + CACHE_TTL_MS, payload });
    await fs.writeFile(cache_file(cache_directory, cache_key), record, 'utf8');
  } catch {
    // a read-only or full cache dir must never take down the scan - k1toune
  }
}

async function run_bounded(items, concurrency, worker) {
  const results = new Array(items.length);
  let cursor = 0;

  async function run_next() {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  }

  const workers = Array.from(
    { length: Math.min(concurrency, Math.max(1, items.length)) },
    () => run_next(),
  );
  await Promise.all(workers);
  return results;
}

function sleep(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('The operation was aborted.', 'AbortError'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', on_abort);
      resolve();
    }, milliseconds);
    const on_abort = () => {
      clearTimeout(timer);
      reject(new DOMException('The operation was aborted.', 'AbortError'));
    };
    signal?.addEventListener('abort', on_abort, { once: true });
  });
}

function technology_cpe_list(technology) {
  return [technology.cpe, ...(technology.cpe_aliases ?? [])].filter(Boolean);
}

function product_from_cpe(cpe) {
  if (typeof cpe !== 'string') return null;
  const parts = cpe.split(':');
  if (parts.length < 5) return null;
  return parts[4].replace(/\\/g, '').toLowerCase();
}

function collect_references(references) {
  if (!Array.isArray(references)) return [];
  const urls = [];
  for (const reference of references) {
    const url = reference?.url;
    if (typeof url === 'string' && /^https?:\/\//i.test(url) && !urls.includes(url)) {
      urls.push(url);
    }
    if (urls.length >= 10) break;
  }
  return urls;
}

function pick_description(vulnerability) {
  const details = vulnerability.details ?? vulnerability.description ?? vulnerability.summary ?? '';
  return strip_control_characters(details).trim();
}

function first_sentence(text) {
  if (!text) return null;
  const clean = strip_control_characters(text).trim();
  if (clean === '') return null;
  const match = clean.match(/^(.{20,220}?[.!?])(?:\s|$)/);
  return match ? match[1] : truncate(clean, 180);
}

function normalize_date(value) {
  if (typeof value !== 'string' || value === '') return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().slice(0, 10);
}

function number_or_null(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function number_from_environment(name) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}
