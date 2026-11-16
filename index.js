#!/usr/bin/env node

import { scan_website } from './src/scanner.js';
import { render_report } from './src/reporter.js';

function print_usage() {
  process.stderr.write('usage: node index.js -host example.com\n');
}

function parse_cli_arguments(argv) {
  if (argv.length !== 2 || argv[0] !== '-host' || argv[1].trim() === '') {
    return null;
  }
  return { host: argv[1] };
}

async function main() {
  const parsed = parse_cli_arguments(process.argv.slice(2));
  if (!parsed) {
    print_usage();
    process.exitCode = 1;
    return;
  }

  const abort_controller = new AbortController();
  const on_sigint = () => abort_controller.abort();
  process.once('SIGINT', on_sigint);

  try {
    const assessment = await scan_website(parsed.host, {
      signal: abort_controller.signal,
    });
    render_report(assessment);
    process.exitCode = assessment.completed ? 0 : 1;
  } catch (error) {
    if (error.name === 'AbortError') {
      process.stderr.write('\nscan cancelled\n');
      process.exitCode = 130;
      return;
    }
    process.stderr.write(`error: ${error.message}\n`);
    if (error.detail) {
      process.stderr.write(`detail: ${error.detail}\n`);
    }
    process.exitCode = 1;
  } finally {
    process.removeListener('SIGINT', on_sigint);
  }
}

await main();
