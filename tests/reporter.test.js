import test from 'node:test';
import assert from 'node:assert/strict';
import { format_report } from '../src/reporter.js';

test('reporter sanitizes remote text and survives empty optional sections', () => {
  const report = format_report({
    target: 'example.com\u001b[31m',
    completed: true,
    duration_ms: 1234,
    page_title: 'Title\nwith newline',
    technologies: [
      {
        name: 'Test',
        category: 'Framework',
        confidence: 'HIGH',
        evidence: [{ label: 'header\u001b[31m value' }],
        version_spec: { kind: 'unknown', display: 'Unknown' },
        version_status: 'Version unknown',
        version_conflict: false,
      },
    ],
    vulnerabilities: [
      {
        id: 'CVE-2024-0001',
        cve_id: 'CVE-2024-0001',
        title: 'Injection\u001b[2Jin title',
        severity: 'HIGH',
        score: 7.5,
        technologies: ['Test'],
        match: 'confirmed',
        affected_versions: ['< 1.2.3'],
        fixed_versions: ['1.2.3'],
        published: '2024-01-01',
        sources: ['NVD'],
        references: ['https://example.test/advisory'],
      },
    ],
    unknown_version_technologies: [],
    unavailable_sources: [],
    lookup_notes: [],
    notes: [],
  }, { color: false });

  assert.equal(report.includes('\u001b['), false);
  assert.match(report, /\[01\] TECHNOLOGY FINGERPRINTING/);
  assert.match(report, /CVE-2024-0001/);
  assert.match(report, /Assessment completed\./);
});
