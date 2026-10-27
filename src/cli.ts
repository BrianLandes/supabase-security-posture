#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { ConfigError, DEFAULT_CONFIG_PATH, loadConfig, RULE_IDS } from './config.js';
import { generateConfig } from './init.js';
import { type Format, render } from './report.js';
import { check, RULE_DESCRIPTIONS } from './rules.js';
import { SnapshotError, takeSnapshot } from './snapshot.js';

/** The local stack's database, as `supabase start` serves it. */
const LOCAL_DB_URL = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

const HELP = `supabase-security-posture — fail CI when your database drifts from its declared security posture.

Usage:
  supabase-security-posture check [options]   Compare the database against the config
  supabase-security-posture init  [options]   Write a starting config, everything unreviewed
  supabase-security-posture rules             List the rules

Options:
  --db-url <url>        Postgres connection string. Default: $SUPABASE_DB_URL, then
                        $DATABASE_URL, then the local stack (${LOCAL_DB_URL})
  --config <path>       Config file. Default: ${DEFAULT_CONFIG_PATH}
  --format <fmt>        check: text, json or github. Default: github on GitHub Actions, else text
  --allow-unreviewed    check: report unreviewed entries as warnings, not errors
  --schema <name>       init: schema to cover (repeatable). Default: public
  --role <name>         init: an extra client role to check, e.g. guest (repeatable)
  --force               init: overwrite an existing config
  -h, --help            Show this help

Exit codes: 0 clean (warnings allowed), 1 findings, 2 usage, config or connection error.
`;

async function main(argv: string[]): Promise<number> {
  const { positionals, values } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      'db-url': { type: 'string' },
      config: { type: 'string' },
      format: { type: 'string' },
      'allow-unreviewed': { type: 'boolean', default: false },
      schema: { type: 'string', multiple: true },
      role: { type: 'string', multiple: true },
      force: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  const command = positionals[0];
  if (values.help || !command) {
    process.stdout.write(HELP);
    return command || values.help ? 0 : 2;
  }

  const dbUrl =
    values['db-url'] ?? process.env.SUPABASE_DB_URL ?? process.env.DATABASE_URL ?? LOCAL_DB_URL;
  const configPath = values.config ?? DEFAULT_CONFIG_PATH;

  switch (command) {
    case 'check': {
      const format = (values.format ?? (process.env.GITHUB_ACTIONS === 'true' ? 'github' : 'text')) as Format;
      if (!['text', 'json', 'github'].includes(format)) {
        throw new UsageError(`--format must be text, json or github, not ${format}`);
      }
      const config = await loadConfig(configPath);
      const snapshot = await takeSnapshot(dbUrl, config.clientRoles, config.schemas);
      const result = check(snapshot, config, { allowUnreviewed: values['allow-unreviewed'] });
      const color = format === 'text' && process.stdout.isTTY && !process.env.NO_COLOR;
      process.stdout.write(`${render(result, format, color)}\n`);
      return result.findings.some((f) => f.severity === 'error') ? 1 : 0;
    }
    case 'init': {
      if (existsSync(configPath) && !values.force) {
        throw new UsageError(`${configPath} already exists. Pass --force to overwrite it.`);
      }
      const schemas = values.schema ?? ['public'];
      const extraRoles = values.role ?? [];
      const snapshot = await takeSnapshot(dbUrl, ['anon', 'authenticated', ...extraRoles], schemas);
      await writeFile(configPath, generateConfig(snapshot, schemas, extraRoles));
      process.stdout.write(
        `Wrote ${configPath}: ${snapshot.tables.length} tables and the definer functions clients can call, all unreviewed.\n` +
          'Classify each one, then run `supabase-security-posture check`.\n',
      );
      return 0;
    }
    case 'rules': {
      for (const id of RULE_IDS) process.stdout.write(`${id.padEnd(24)} ${RULE_DESCRIPTIONS[id]}\n`);
      return 0;
    }
    default:
      throw new UsageError(`Unknown command "${command}". Run with --help.`);
  }
}

class UsageError extends Error {}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    const known = e instanceof UsageError || e instanceof ConfigError || e instanceof SnapshotError;
    process.stderr.write(`${known ? (e as Error).message : (e as Error).stack ?? String(e)}\n`);
    process.exitCode = 2;
  },
);
