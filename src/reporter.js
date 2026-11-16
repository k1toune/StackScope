import {
  format_duration,
  format_version_spec,
  strip_control_characters,
  truncate,
} from './utils.js';

const MAX_DISPLAYED_VULNERABILITIES = 30;

export function format_report(assessment, options = {}) {
  const color_enabled = options.color ?? detect_color_support();
  const paint = create_painter(color_enabled);
  const lines = [];

  lines.push('');
  lines.push(`  ${paint.bold('WEBSITE SECURITY ASSESSMENT')}`);
  lines.push('  ---------------------------');
  lines.push('');
  lines.push(`  ${paint.dim('Target')}       ${safe(assessment.target, 80)}`);
  if (assessment.url) {
    lines.push(`  ${paint.dim('URL')}          ${safe(assessment.url, 120)}`);
  }
  if (Number.isInteger(assessment.http_status)) {
    lines.push(`  ${paint.dim('HTTP')}         ${assessment.http_status}`);
  }
  lines.push(`  ${paint.dim('Status')}       ${assessment.completed ? 'Completed' : 'Incomplete'}`);
  lines.push(`  ${paint.dim('Duration')}     ${format_duration(assessment.duration_ms)}`);
  if (assessment.page_title) {
    lines.push(`  ${paint.dim('Page title')}   ${truncate(assessment.page_title, 80)}`);
  }
  lines.push('');

  lines.push(`  ${paint.heading('[01] TECHNOLOGY FINGERPRINTING')}`);
  lines.push('');

  if (assessment.technologies.length === 0) {
    lines.push('      No technologies could be identified from public response data.');
  } else {
    const name_width = 24;
    const version_width = 14;
    const confidence_width = 12;
    lines.push(`      ${paint.dim(pad('TECHNOLOGY', name_width))}${paint.dim(pad('VERSION', version_width))}${paint.dim(pad('CONFIDENCE', confidence_width))}${paint.dim('CATEGORY')}`);
    for (const technology of assessment.technologies) {
      const name = truncate(technology.name, name_width - 1);
      const version = truncate(format_version_spec(technology.version_spec), version_width - 1);
      const confidence = confidence_text(technology.confidence);
      lines.push(
        `      ${pad(name, name_width)}${pad(version, version_width)}${pad(confidence, confidence_width)}${truncate(technology.category, 30)}`,
      );
      for (const evidence of technology.evidence.slice(0, 4)) {
        lines.push(`        ${paint.dim('-')} ${truncate(evidence.label, 100)}`);
      }
    }
  }
  lines.push('');

  lines.push(`  ${paint.heading('[02] VERSION ANALYSIS')}`);
  lines.push('');
  if (assessment.technologies.length === 0) {
    lines.push('      No version analysis was possible.');
  } else {
    for (const technology of assessment.technologies) {
      lines.push(`      ${pad(truncate(technology.name, 23), 24)}${technology.version_status}`);
      if (technology.version_conflict) {
        lines.push(`        ${paint.dim('multiple public indicators disagreed; strongest source shown')}`);
      }
    }
  }
  lines.push('');

  lines.push(`  ${paint.heading('[03] CVE RESEARCH')}`);
  lines.push('');
  const displayed_vulnerabilities = assessment.vulnerabilities.slice(0, MAX_DISPLAYED_VULNERABILITIES);
  const versioned_technologies = assessment.technologies.filter((technology) => technology.version_spec.kind !== 'unknown');
  if (displayed_vulnerabilities.length === 0) {
    if (versioned_technologies.length === 0) {
      lines.push('      No versioned technology was available for CVE matching.');
    } else {
      lines.push('      No potential CVE matches were found for the identified technology versions.');
    }
  } else {
    for (const vulnerability of displayed_vulnerabilities) {
      const identifier = truncate(vulnerability.cve_id ?? vulnerability.id, 20);
      const severity = vulnerability.severity ?? 'UNKNOWN';
      const score_text = vulnerability.score === null ? '' : ` ${vulnerability.score.toFixed(1)}`;
      lines.push(`      ${pad(identifier, 18)}${severity_color(paint, severity)(pad(severity, 10))}${score_text}`);
      lines.push(`        ${truncate(vulnerability.title, 150)}`);
      const details = [
        `Technology: ${vulnerability.technologies.join(', ')}`,
        `Match: ${vulnerability.match === 'confirmed' ? 'confirmed version match' : 'potential match'}`,
      ];
      lines.push(`        ${paint.dim(details.join('  |  '))}`);
      lines.push(`        ${paint.dim('Affected:')} ${truncate(vulnerability.affected_versions.join(' ; '), 180)}`);
      if (vulnerability.fixed_versions.length > 0) {
        lines.push(`        ${paint.dim('Fixed:')} ${truncate(vulnerability.fixed_versions.slice(0, 4).join(', '), 120)}`);
      }
      const source_line = [
        vulnerability.published ? `Published: ${vulnerability.published}` : null,
        `Source: ${vulnerability.sources.join(' + ')}`,
      ].filter(Boolean).join('  |  ');
      lines.push(`        ${paint.dim(source_line)}`);
      if (vulnerability.references.length > 0) {
        lines.push(`        ${paint.dim(truncate(vulnerability.references[0], 140))}`);
      }
      lines.push('');
    }
    if (assessment.vulnerabilities.length > displayed_vulnerabilities.length) {
      lines.push(`      ${paint.dim(`... ${assessment.vulnerabilities.length - displayed_vulnerabilities.length} more CVE matches not shown`)}`);
      lines.push('');
    }
  }
  lines.push('      CVE presence indicates potential exposure, not confirmed exploitability.');
  lines.push('');

  lines.push(`  ${paint.heading('[04] SUMMARY')}`);
  lines.push('');
  const versioned_count = assessment.technologies.filter((technology) => technology.version_spec.kind !== 'unknown').length;
  const exact_count = assessment.technologies.filter((technology) => technology.version_spec.kind === 'exact').length;
  const confirmed_count = assessment.vulnerabilities.filter((vulnerability) => vulnerability.match === 'confirmed').length;
  const potential_count = assessment.vulnerabilities.length - confirmed_count;
  lines.push(`      Technologies detected:        ${assessment.technologies.length}`);
  lines.push(`      Versions identified:          ${versioned_count}`);
  lines.push(`      CVEs with confirmed version:  ${confirmed_count}`);
  lines.push(`      Potential-only matches:       ${potential_count}`);
  lines.push(`      CVE matches assessed:         ${assessment.vulnerabilities.length}`);
  if (exact_count > 0) {
    lines.push(`      Exact versions detected:      ${exact_count}`);
  }

  if ((assessment.unavailable_sources ?? []).length > 0) {
    lines.push('');
    lines.push(`      ${paint.warning('Vulnerability sources unavailable:')}`);
    for (const source of assessment.unavailable_sources) {
      lines.push(`        ${truncate(source.source, 20)}: ${truncate(source.reason, 140)}`);
    }
    lines.push('      CVE coverage is incomplete for this scan.');
  }

  const all_notes = [...(assessment.lookup_notes ?? []), ...(assessment.notes ?? [])];
  if (all_notes.length > 0) {
    lines.push('');
    lines.push(`      ${paint.dim('Notes:')}`);
    for (const note of all_notes.slice(0, 12)) {
      lines.push(`        - ${truncate(note, 180)}`);
    }
  }

  lines.push('');
  lines.push('  Assessment completed.');
  lines.push('');

  return lines.join('\n');
}

export function render_report(assessment, options = {}) {
  process.stdout.write(`${format_report(assessment, options)}\n`);
}

function detect_color_support() {
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.TERM === 'dumb') return false;
  return Boolean(process.stdout.isTTY);
}

function create_painter(enabled) {
  const wrap = (code) => (text) => (enabled ? `\u001b[${code}m${text}\u001b[0m` : String(text));
  return {
    bold: wrap('1'),
    dim: wrap('2'),
    heading: (text) => (enabled ? `\u001b[1;36m${text}\u001b[0m` : String(text)),
    warning: (text) => (enabled ? `\u001b[33m${text}\u001b[0m` : String(text)),
    high: (text) => (enabled ? `\u001b[1;31m${text}\u001b[0m` : String(text)),
    medium: (text) => (enabled ? `\u001b[33m${text}\u001b[0m` : String(text)),
    low: (text) => (enabled ? `\u001b[32m${text}\u001b[0m` : String(text)),
  };
}

function severity_color(paint, severity) {
  if (severity === 'CRITICAL' || severity === 'HIGH') return paint.high;
  if (severity === 'MEDIUM') return paint.medium;
  if (severity === 'LOW') return paint.low;
  return paint.dim;
}

function confidence_text(confidence) {
  return confidence ?? 'UNKNOWN';
}

function pad(text, width) {
  const value = String(text ?? '');
  return value.length >= width ? value : value + ' '.repeat(width - value.length);
}

function safe(value, maximum) {
  return truncate(strip_control_characters(value), maximum);
}

