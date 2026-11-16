import { make_version_spec } from './utils.js';

export function resolve_technology_version(candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    return {
      version_spec: { kind: 'unknown', display: 'Unknown', source: null },
      status: 'Version unknown',
      disclosed: null,
      conflict: false,
      candidates: [],
    };
  }

  const normalized = [];
  for (const candidate of candidates) {
    const raw = String(candidate.value ?? '').trim();
    if (!/^\d+(?:\.\d+){0,3}$/.test(raw)) continue;
    const spec = make_version_spec(raw, {
      source: candidate.source ?? null,
      disclosed: candidate.disclosed ?? null,
    });
    if (spec.kind === 'unknown') continue;
    const duplicate = normalized.find((entry) => entry.spec.display === spec.display);
    if (duplicate) {
      duplicate.occurrences += 1;
      duplicate.confidence = Math.max(duplicate.confidence, candidate.confidence ?? 0);
      duplicate.disclosed = duplicate.disclosed || Boolean(candidate.disclosed);
      continue;
    }
    normalized.push({
      spec,
      source: candidate.source ?? null,
      disclosed: Boolean(candidate.disclosed),
      confidence: candidate.confidence ?? 0,
      occurrences: 1,
    });
  }

  if (normalized.length === 0) {
    return {
      version_spec: { kind: 'unknown', display: 'Unknown', source: null },
      status: 'Version unknown',
      disclosed: null,
      conflict: false,
      candidates: [],
    };
  }

  normalized.sort((left, right) => {
    const exact_difference = Number(right.spec.kind === 'exact') - Number(left.spec.kind === 'exact');
    if (exact_difference !== 0) return exact_difference;
    const disclosed_difference = Number(right.disclosed) - Number(left.disclosed);
    if (disclosed_difference !== 0) return disclosed_difference;
    if (right.confidence !== left.confidence) return right.confidence - left.confidence;
    return right.occurrences - left.occurrences;
  });

  const best = normalized[0];
  const distinct_displays = new Set(normalized.map((entry) => entry.spec.display));
  const conflict = distinct_displays.size > 1;

  const version_spec = {
    ...best.spec,
    source: best.source,
    disclosed: best.disclosed,
  };

  let status;
  if (version_spec.kind === 'exact') {
    status = best.disclosed ? 'Exact version disclosed' : 'Exact version inferred';
  } else {
    status = best.disclosed ? 'Partial version disclosed' : 'Partial version inferred';
  }

  return {
    version_spec,
    status,
    disclosed: best.disclosed,
    conflict,
    candidates: normalized.map((entry) => ({
      display: entry.spec.display,
      source: entry.source,
      disclosed: entry.disclosed,
    })),
  };
}
