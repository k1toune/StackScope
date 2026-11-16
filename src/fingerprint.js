import { TECHNOLOGY_RULES } from './technologies.js';
import { strip_control_characters } from './utils.js';

export function fingerprint_response(input) {
  const headers = input.headers ?? {};
  const set_cookie = input.set_cookie ?? [];
  const html = input.html ?? '';
  const resources = input.resources ?? [];
  const meta_tags = parse_meta_tags(html);
  const resource_text = resources.map((resource) => (
    typeof resource === 'string' ? resource : resource.path
  )).join('\n');

  const detections = [];

  for (const rule of TECHNOLOGY_RULES) {
    const evidence = [];
    const version_candidates = [];
    let best_signal_confidence = 0;

    for (const signal of rule.signals) {
      const subjects = signal_subjects(signal, {
        headers,
        set_cookie,
        html,
        resource_text,
        meta_tags,
      });

      for (const subject of subjects) {
        const match = subject.match(signal.pattern);
        if (!match) continue;

        const label = evidence_label(signal, match);
        if (!evidence.some((entry) => entry.label === label)) {
          evidence.push({ label });
        }
        best_signal_confidence = Math.max(best_signal_confidence, signal.confidence);

        const version = match.groups?.version ?? match[1] ?? null;
        if (version && signal.pattern.source.includes('version')) {
          version_candidates.push({
            value: version,
            source: label,
            disclosed: Boolean(signal.disclosed),
            confidence: signal.confidence,
          });
        }
      }
    }

    if (evidence.length === 0) continue;

    const confidence_score = Math.min(
      98,
      best_signal_confidence + Math.min(18, Math.max(0, evidence.length - 1) * 6),
    );

    detections.push({
      name: rule.name,
      category: rule.category,
      priority: rule.priority ?? 50,
      confidence: confidence_label(confidence_score),
      confidence_score,
      evidence,
      version_candidates,
      cpe: rule.cpe ?? null,
      cpe_aliases: rule.cpe_aliases ?? [],
      osv: rule.osv ?? [],
    });
  }

  detections.sort((left, right) => {
    if (left.priority !== right.priority) return left.priority - right.priority;
    return left.name.localeCompare(right.name);
  });

  return detections;
}

function signal_subjects(signal, context) {
  switch (signal.where) {
    case 'header': {
      const value = context.headers[signal.header];
      return value ? [value] : [];
    }
    case 'header_any':
      return [Object.entries(context.headers).map(([name, value]) => `${name}: ${value}`).join('\n')];
    case 'cookie':
      return context.set_cookie.length > 0 ? [context.set_cookie.join('\n')] : [];
    case 'html':
      return context.html ? [context.html] : [];
    case 'resources':
      return context.resource_text ? [context.resource_text] : [];
    case 'meta': {
      const values = context.meta_tags.get(signal.meta_name?.toLowerCase());
      return values ?? [];
    }
    default:
      return [];
  }
}

function evidence_label(signal, match) {
  const label = signal.label ?? signal.where;
  const version = match.groups?.version;
  if (version && signal.disclosed) {
    return `${label} (${strip_control_characters(version)})`;
  }
  return label;
}

function confidence_label(score) {
  if (score >= 80) return 'HIGH';
  if (score >= 50) return 'MEDIUM';
  return 'LOW';
}

export function parse_meta_tags(html) {
  const tags = new Map();
  const tag_pattern = /<meta\b[^>]*>/gi;
  let tag_match;
  while ((tag_match = tag_pattern.exec(html)) !== null) {
    const attributes = parse_attributes(tag_match[0]);
    const name = (attributes.name ?? attributes.property ?? attributes['http-equiv'] ?? '').toLowerCase();
    const content = attributes.content;
    if (!name || typeof content !== 'string') continue;
    const existing = tags.get(name) ?? [];
    existing.push(content);
    tags.set(name, existing);
  }
  return tags;
}

function parse_attributes(tag_text) {
  const attributes = {};
  const attribute_pattern = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;
  let attribute_match;
  while ((attribute_match = attribute_pattern.exec(tag_text)) !== null) {
    const name = attribute_match[1].toLowerCase();
    const value = attribute_match[2] ?? attribute_match[3] ?? attribute_match[4] ?? '';
    attributes[name] = value;
  }
  return attributes;
}

export function extract_resources(html, base_url) {
  const resources = [];
  const seen = new Set();
  const attribute_pattern = /<(script|link|img)\b[^>]*\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/gi;
  let base;
  try {
    base = new URL(base_url);
  } catch {
    return resources;
  }

  let match;
  while ((match = attribute_pattern.exec(html)) !== null) {
    const raw_url = match[2] ?? match[3] ?? match[4] ?? '';
    if (raw_url === '') continue;
    let resolved;
    try {
      resolved = new URL(raw_url, base);
    } catch {
      continue;
    }
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') continue;
    const path = `${resolved.pathname}${resolved.search}`;
    if (seen.has(path)) continue;
    seen.add(path);
    resources.push({
      url: resolved.toString(),
      hostname: resolved.hostname.toLowerCase(),
      path,
      same_origin: resolved.hostname.toLowerCase() === base.hostname.toLowerCase(),
    });
    if (resources.length >= 200) break;
  }

  return resources;
}

export function extract_page_title(html) {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!match) return null;
  return strip_control_characters(match[1]).trim().slice(0, 200) || null;
}
