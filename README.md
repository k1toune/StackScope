# StackScope

StackScope is a passive website technology fingerprinting and CVE exposure assessment CLI. It makes a small number of requests to a single origin, identifies publicly visible technologies and version indicators, then checks the identified versions against the OSV and NVD vulnerability databases.

It is built for quick, low-impact assessments and produces a terminal report with the evidence behind each detection.

```
node index.js -host example.com
```

## Features

- Passively fingerprints servers, languages, frameworks, CMS platforms, JavaScript libraries, CDNs, and cache layers.
- Infers exact and partial versions from response headers, cookies, generator metadata, and asset URLs.
- Distinguishes disclosed versions from inferred versions, and records conflicting indicators.
- Matches identified versions against OSV and NVD data.
- Labels matches as `confirmed` or `potential` instead of treating every CVE as proven.
- Deduplicates CVEs returned by multiple sources.
- Respects `robots.txt` and refuses to scan when the root path is disallowed.
- Follows only same-host redirects, including the `www` variant.
- Caches vulnerability API responses for 24 hours.
- Handles API timeouts, rate limits, malformed responses, and partial NVD coverage without crashing.
- Limits and sanitizes untrusted response data before printing it.
- Zero runtime dependencies.

## How It Works

1. The target is normalized and validated. A scheme is added when omitted.
2. StackScope requests `/robots.txt` over HTTPS, falling back to HTTP when HTTPS is unavailable.
3. The scan stops if `robots.txt` returns `401`, `403`, or `429`, or if the root path is disallowed.
4. The root HTML page is fetched once. Redirects are followed only within the target host and its `www` variant.
5. Response headers, cookies, HTML metadata, and script/style asset references are inspected against the technology rule set.
6. Version indicators are resolved into one of: exact, partial, or unknown.
7. Technologies with a usable version are checked against OSV and NVD.
8. Results are merged, deduplicated, sorted by severity, and printed.

The scanner does not crawl the site, execute JavaScript, submit forms, authenticate, brute force paths, or attempt exploitation.

## Requirements

- Node.js 22 or newer.
- Network access to the target, `api.osv.dev`, and `services.nvd.nist.gov`.
- No package installation is required at runtime.

Tested on Node.js `v26.13.0` with npm `11.20.0`.

## Installation

```bash
git clone https://github.com/k1toune/StackScope.git stackscope
cd stackscope
npm test
```

There are no runtime dependencies. To install the CLI as a local command:

```bash
npm link
stackscope -host example.com
```

The primary invocation remains:

```bash
node index.js -host example.com
```

## Usage

StackScope accepts exactly one argument pair:

```text
node index.js -host <target>
```

Accepted target forms:

```bash
node index.js -host example.com
node index.js -host www.example.com
node index.js -host https://example.com
node index.js -host http://example.com:8080
node index.js -host 192.0.2.10
```

Any other flag, extra argument, missing value, or empty value prints usage and exits with status 1. There are no `--help`, `--version`, or additional scan flags.

The path, query string, and fragment of a URL are ignored; only the origin is assessed.

## Example Output

```text
  WEBSITE SECURITY ASSESSMENT
  ---------------------------

  Target       example.com
  URL          https://example.com/
  HTTP         200
  Status       Completed
  Duration     144 ms
  Page title   Example Domain

  [01] TECHNOLOGY FINGERPRINTING

      TECHNOLOGY              VERSION       CONFIDENCE  CATEGORY
      Cloudflare              Unknown       HIGH        CDN
        - CF-Ray header
        - Server header names Cloudflare

  [02] VERSION ANALYSIS

      Cloudflare              Version unknown

  [03] CVE RESEARCH

      No versioned technology was available for CVE matching.
      CVE presence indicates potential exposure, not confirmed exploitability.

  [04] SUMMARY

      Technologies detected:        1
      Versions identified:          0
      CVEs with confirmed version:  0
      Potential-only matches:       0
      CVE matches assessed:        0

      Notes:
        - CVE matching skipped for technologies without a usable version: Cloudflare

  Assessment completed.
```

## Report Sections

| Section | Contents |
|---|---|
| `[01] TECHNOLOGY FINGERPRINTING` | Detected technologies, resolved version, confidence, category, and supporting evidence. |
| `[02] VERSION ANALYSIS` | Version status for every detected technology and any conflict warning. |
| `[03] CVE RESEARCH` | Up to 30 CVE matches with severity, score, affected ranges, fixed versions, source, and reference. |
| `[04] SUMMARY` | Counts, unavailable data sources, and scan notes. |

Color is enabled only when stdout is a TTY. Set `NO_COLOR=1` to disable it explicitly. Remote text is stripped of terminal control sequences before display.

## Technology Coverage

StackScope currently contains rules for 39 technology families:

- Languages and runtimes: PHP, Node.js, ASP.NET, Python, Ruby, Java.
- Frameworks: Express, Laravel, Symfony, Django, Flask, Ruby on Rails, Spring, Next.js, Nuxt.
- Frontend: React, Vue.js, Angular, Svelte, jQuery, Bootstrap.
- CMS and e-commerce: WordPress, Drupal, Joomla, Magento, Shopify, Ghost.
- Servers and application servers: Nginx, OpenResty, Apache HTTP Server, Microsoft IIS, Caddy, LiteSpeed, Apache Tomcat.
- CDN and cache: Cloudflare, Fastly, Akamai, Amazon CloudFront, Varnish.

Detection evidence includes headers such as `Server` and `X-Powered-By`, cookies, generator metadata, framework-specific markup, and same-origin asset names. CDN detections are reported separately and are not used to infer the origin server.

## Version Detection And Confidence

Versions are classified as:

| Status | Meaning |
|---|---|
| `Exact version disclosed` | A full version such as `6.4.2` appears in a public response indicator. |
| `Exact version inferred` | A full version is assembled from indirect evidence. |
| `Partial version disclosed` | A version family such as `6.4.x` is disclosed. |
| `Partial version inferred` | A partial version is derived from asset paths or similar evidence. |
| `Version unknown` | No usable version evidence was found. |

Confidence is `HIGH` at a score of 80 or above, `MEDIUM` at 50 or above, and `LOW` below that. The score combines the strongest matching signal with corroboration from additional independent signals.

When multiple public indicators disagree, the strongest indicator is shown and a conflict is recorded in the notes.

## CVE Matching

StackScope uses two public sources:

- **OSV** for ecosystem advisories and range information.
- **NVD** for CVE records and CPE applicability data.

Rules:

- An exact version inside an affected range is reported as `confirmed`.
- A partial version that overlaps an affected range is reported as `potential`.
- Technologies with an unknown version are skipped.
- NVD platform records with a `-` version are ignored.
- NVD wildcard `*` records with no machine-readable range are counted but not matched.
- NVD queries use a wildcard vendor and filter locally by product, because vendor names change in CPE data.
- Product aliases are supported where the same technology appears under multiple CPE products, such as the historical `nginx:nginx` entry and the current `f5:nginx_open_source` entry.
- Duplicate CVEs returned by both sources are merged by CVE identifier.
- Results are sorted by severity, then by score, then by CVE identifier.

A CVE match means the detected version falls inside a published affected range. It does not confirm that the target is exploitable, reachable, configured in the vulnerable mode, or missing a vendor backport. Treat results as exposure indicators that require manual validation.

### Rate Limits And Request Budget

NVD publishes anonymous rate limits. StackScope spaces anonymous NVD requests by 6.5 seconds and allows up to 14 NVD network requests per scan. Setting `NVD_API_KEY` reduces the spacing to 700 ms and raises the request budget to 60.

OSV requests are limited to three concurrent requests. OSV advisory processing is capped at 250 entries per technology. Up to 12 technologies are sent to NVD per scan, and each NVD query requests at most 2,000 records.

## Configuration

Configuration is environment-only. The CLI intentionally exposes a single flag.

| Variable | Default | Purpose |
|---|---|---|
| `NVD_API_KEY` | unset | NVD API key. Strongly recommended for regular use. |
| `STACKSCOPE_CACHE_DIR` | `~/.cache/stackscope` | Cache directory for OSV and NVD responses. |
| `STACKSCOPE_OSV_BASE_URL` | `https://api.osv.dev` | Override the OSV API base URL. |
| `STACKSCOPE_NVD_BASE_URL` | `https://services.nvd.nist.gov/rest/json` | Override the NVD API base URL. |
| `STACKSCOPE_NVD_DELAY_MS` | `6500`, or `700` with a key | Delay between NVD requests. |
| `NO_COLOR` | unset | Disable colored output when set. |

Cached responses expire after 24 hours. Delete the cache directory to force fresh vulnerability data.

Request an NVD API key at <https://nvd.nist.gov/developers/request-an-api-key>.

## Performance

Typical timings observed during development:

| Scenario | Duration |
|---|---|
| `example.com`, no versioned technology and no NVD query | about 150 ms |
| Cached scan with vulnerability lookups | under 1 second |
| Cold Nginx assessment with two NVD product queries | roughly 20-30 seconds |

NVD latency dominates cold scans. The delay is deliberate: NVD rejects bursts of anonymous requests. With an API key, the delay drops from 6.5 seconds to 700 ms.

The HTTP client uses a 12-second request timeout, a 2 MB body limit, and a maximum of five redirects. Vulnerability API calls use a 30-second timeout.

## Testing

Run the full suite:

```bash
npm test
```

The suite contains 48 tests and covers:

- Strict CLI argument parsing, usage output, and invalid input handling.
- Host normalization, scheme handling, ports, paths, and invalid input.
- Version parsing, comparison, and range overlap.
- Fingerprint detection across headers, cookies, HTML, metadata, and resources.
- False-positive resistance for ordinary page text and CDN headers.
- Unknown, partial, inferred, and conflicting version handling.
- Same-host redirect following and cross-host redirect blocking.
- Body size limits, timeouts, and legacy charset decoding.
- `robots.txt` longest-match precedence, allow-on-tie, wildcard groups, and refusal behavior.
- Full scans against local HTTP and HTTPS fixtures with mock OSV and NVD APIs.
- Rate-limited and unreachable targets.
- Malformed and unavailable vulnerability APIs, NVD rate-limit retry handling, and response caching.
- NVD platform filtering, unconstrained records, CPE product aliases, and alias propagation through fingerprinting.
- Reporter sanitization and empty optional sections.

The HTTPS test creates a temporary self-signed certificate with `openssl` and runs the client with certificate verification disabled for that test only.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Assessment completed and the report was printed. |
| `1` | Invalid arguments, invalid target, refused scan, unreachable target, or fatal scan error. |
| `130` | Scan cancelled with `Ctrl+C`. |

A report can complete with exit code `0` while listing unavailable vulnerability sources. Check section `[04]` before treating CVE coverage as complete.

## Limitations And Accuracy

- **Passive only.** StackScope reads public responses. It does not exploit, fuzz, brute force, or verify a CVE against the target.
- **Root page only.** It does not crawl, enumerate subdomains, inspect API endpoints, or authenticate.
- **No JavaScript execution.** Technologies injected at runtime by client-side code may not be detected.
- **Headers can be misleading.** `Server`, `X-Powered-By`, generator tags, and asset names can be spoofed, stripped, or altered by a proxy.
- **CDNs hide origin servers.** A CDN response may reveal nothing about the software behind it.
- **Version inference is heuristic.** A version found in a public indicator may refer to a dependency, a cache key, or stale metadata rather than the deployed component.
- **Partial versions produce potential matches.** A `7.2.x` detection can overlap many advisories without proving the exact patch level.
- **NVD data is noisy.** Historical CPE entries, moved vendors, and unconstrained records require local filtering. Some valid records may still be missed.
- **Vulnerability data changes.** Results depend on the state of OSV and NVD at scan time and on local cache age.
- **Coverage is bounded.** The technology rule set is finite, NVD lookups are capped, and only the first 30 CVE matches are displayed.
- **Not an audit.** StackScope is a reconnaissance aid, not a compliance certification or a substitute for source review and manual testing.

## Troubleshooting

| Symptom | Cause and resolution |
|---|---|
| `target could not be reached` | DNS, TLS, firewall, or timeout failure. Verify the host and try `http://` explicitly. |
| `the site disallows the root path in robots.txt` | The site's robots policy forbids the scan. StackScope will not override it. |
| `target denies access to robots.txt` | The site returned `401` or `403` for `robots.txt`. |
| `target rate limited the robots.txt request` | The site returned `429` before the scan started. Retry later. |
| No technologies identified | The page may be a bare SPA, heavily proxied, or stripped of identifying headers. |
| Technologies found, versions unknown | CVE matching is skipped because no usable version was disclosed. |
| `Vulnerability sources unavailable` | OSV or NVD timed out, rate-limited, or returned an error. Re-run later or set `NVD_API_KEY`. |
| HTTP 503 from NVD | Anonymous rate limit. Wait, reduce scan frequency, or use an API key. |
| TLS certificate error | The target uses an invalid or self-signed certificate. Do not disable verification outside an isolated test environment. |
| Repeated scans return stale CVE data | The 24-hour cache is active. Remove `~/.cache/stackscope` or set a fresh cache directory. |

## Project Structure

```text
index.js                 CLI argument parsing and entry point
src/scanner.js           Scan orchestration and robots enforcement
src/http_client.js       HTTP client, redirect policy, body limits, robots parser
src/technologies.js      Technology detection rules and CPE identifiers
src/fingerprint.js       Response fingerprinting and resource extraction
src/version_detector.js  Version candidate resolution and conflict tracking
src/cve_lookup.js        OSV/NVD clients, matching, deduplication, caching
src/reporter.js          Terminal report formatting
src/utils.js             Validation, version comparison, hashing, sanitization
tests/                   Unit and integration tests
```

## Data Sources And Attribution

- **NVD** — National Vulnerability Database, NIST. <https://nvd.nist.gov>
- **OSV** — Open Source Vulnerabilities. <https://osv.dev>

CVE identifiers and NVD records are public data. StackScope does not bundle a vulnerability database; every lookup is performed against the live APIs and cached locally for 24 hours.

## License

MIT. See [LICENSE](LICENSE).

Copyright (c) 2026 k1toune.
