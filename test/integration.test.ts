// Runs the real snapshot query against a real Postgres, set up the way a fresh
// Supabase project is. Skipped unless POSTGRES_URL points at a server where the
// connecting user may create databases and roles, e.g.:
//
//   docker run -d --rm -p 54399:5432 -e POSTGRES_PASSWORD=postgres postgres:17
//   POSTGRES_URL=postgresql://postgres:postgres@127.0.0.1:54399/postgres npm test

import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { parseConfig } from '../src/config.js';
import { generateConfig } from '../src/init.js';
import { check, type Finding } from '../src/rules.js';
import { takeSnapshot } from '../src/snapshot.js';

const serverUrl = process.env.POSTGRES_URL;
const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

describe.skipIf(!serverUrl)('against a real database', () => {
  const dbName = `posture_${randomBytes(4).toString('hex')}`;
  let dbUrl: string;

  async function sql(text: string, url = dbUrl) {
    const client = new pg.Client({ connectionString: url });
    await client.connect();
    try {
      await client.query(text);
    } finally {
      await client.end();
    }
  }

  beforeAll(async () => {
    await sql(`CREATE DATABASE ${dbName}`, serverUrl);
    const url = new URL(serverUrl as string);
    url.pathname = `/${dbName}`;
    dbUrl = url.toString();
    await sql(fixture('leaky.sql'));
  });

  afterAll(async () => {
    if (serverUrl) await sql(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`, serverUrl);
  });

  const roles = ['anon', 'authenticated', 'guest'];
  const leakyConfig = () => parseConfig(parse(fixture('leaky.yaml')));
  const summarize = (findings: Finding[]) =>
    findings.map((f) => `${f.rule} ${f.subject}`).sort();

  it('finds every planted mistake, and nothing else', async () => {
    const snapshot = await takeSnapshot(dbUrl, roles, ['public']);
    const { findings } = check(snapshot, leakyConfig());

    expect(summarize(findings)).toEqual(
      [
        // RLS never turned on.
        'rls-enabled api_keys',
        // Nobody classified it.
        'tables-classified drafts',
        // Supabase's default grants, left on a scoped table and an internal one.
        ...['notes', 'api_keys'].flatMap((t) => Array(4).fill(`anon-privileges ${t}`)),
        'internal-closed api_keys',
        'internal-closed api_keys',
        'internal-closed api_keys',
        // WITH CHECK (true) for authenticated, and a policy with no TO.
        'no-permissive-writes comments',
        'no-public-policies comments',
        'open-select-declared comments',
        // A view that is readable and runs as its owner.
        'views-closed note_counts',
        // REVOKE FROM PUBLIC left anon's default grant in place.
        'definer-anon-pre-login whoami',
        // Unclassified, PUBLIC-granted, no search_path.
        'definers-classified notes_for',
        'definer-not-public notes_for',
        'definer-search-path notes_for',
        'open-issue-format join_room',
        'no-stale-entries tables.dropped_table',
      ].sort(),
    );
  });

  it('suggests the REVOKE that actually closes a function', async () => {
    const snapshot = await takeSnapshot(dbUrl, roles, ['public']);
    const { findings } = check(snapshot, leakyConfig());
    const whoami = findings.find((f) => f.subject === 'whoami');
    expect(whoami?.fix).toContain('FROM public, anon, authenticated');
  });

  it('init writes a config that parses and classifies nothing', async () => {
    const snapshot = await takeSnapshot(dbUrl, roles, ['public']);
    const text = generateConfig(snapshot, ['public'], ['guest']);
    const config = parseConfig(parse(text));

    expect([...config.tables.keys()].sort()).toEqual(
      ['api_keys', 'audit_log', 'comments', 'countries', 'drafts', 'notes', 'rooms'],
    );
    expect([...config.tables.values()].every((t) => t.kind === 'unreviewed')).toBe(true);
    expect([...config.functions.values()].every((f) => f.scope === 'unreviewed')).toBe(true);

    const strict = check(snapshot, config);
    expect(strict.findings.some((f) => f.severity === 'error')).toBe(true);
    // Adopting gradually softens "not classified yet", never a real leak.
    const lenient = check(snapshot, config, { allowUnreviewed: true });
    const errors = lenient.findings.filter((f) => f.severity === 'error');
    expect(errors.filter((f) => f.rule.endsWith('-classified'))).toEqual([]);
    expect(summarize(errors)).toEqual(
      expect.arrayContaining([
        'rls-enabled api_keys',
        'no-permissive-writes comments',
        'definer-not-public notes_for',
        'views-closed note_counts',
      ]),
    );
    expect(summarize(errors)).not.toContain('open-select-declared countries');
  });

  // Mutates the database, so it runs after everything that reads the leaks.
  it('passes once the migration and the config are fixed', async () => {
    await sql(`
      ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
      REVOKE ALL ON public.api_keys FROM anon, authenticated;
      REVOKE ALL ON public.notes FROM anon;
      DROP POLICY comments_insert ON public.comments;
      CREATE POLICY comments_insert ON public.comments FOR INSERT TO authenticated
        WITH CHECK (author = auth.uid());
      DROP POLICY comments_read ON public.comments;
      CREATE POLICY comments_read ON public.comments FOR SELECT TO authenticated
        USING (author = auth.uid());
      REVOKE ALL ON public.note_counts FROM anon, authenticated;
      REVOKE ALL ON FUNCTION public.whoami() FROM public, anon, authenticated;
      GRANT EXECUTE ON FUNCTION public.whoami() TO authenticated;
      DROP FUNCTION public.notes_for(uuid);
    `);
    const raw = parse(fixture('leaky.yaml'));
    raw.tables.drafts = 'scoped';
    delete raw.tables.dropped_table;
    raw.functions.join_room.openIssue = 'SEC-1';

    const snapshot = await takeSnapshot(dbUrl, roles, ['public']);
    const result = check(snapshot, parseConfig(raw));
    expect(summarize(result.findings)).toEqual([]);
    expect(result.openIssues).toEqual([{ subject: 'join_room', issue: 'SEC-1' }]);
  });

  it('refuses a role that does not exist', async () => {
    await expect(takeSnapshot(dbUrl, ['anon', 'no_such_role'], ['public'])).rejects.toThrow(
      /no_such_role/,
    );
  });
});
