import { describe, expect, it } from 'vitest';
import { ConfigError, parseConfig } from '../src/config.js';
import { render } from '../src/report.js';
import { check } from '../src/rules.js';
import type { FunctionSnapshot, PrivilegeSet, Snapshot, TableSnapshot } from '../src/snapshot.js';

const none: PrivilegeSet = { select: false, insert: false, update: false, delete: false };
const all: PrivilegeSet = { select: true, insert: true, update: true, delete: true };

function table(name: string, overrides: Partial<TableSnapshot> = {}): TableSnapshot {
  return {
    schema: 'public',
    name,
    rls: true,
    privileges: { anon: none, authenticated: all },
    policies: [],
    ...overrides,
  };
}

function fn(name: string, overrides: Partial<FunctionSnapshot> = {}): FunctionSnapshot {
  return {
    schema: 'public',
    name,
    args: '',
    definer: true,
    pinsSearchPath: true,
    grantedToPublic: false,
    callableBy: { anon: false, authenticated: true },
    ...overrides,
  };
}

function snapshot(overrides: Partial<Snapshot> = {}): Snapshot {
  return { roles: ['anon', 'authenticated'], tables: [], views: [], functions: [], ...overrides };
}

describe('parseConfig', () => {
  it('reports every mistake at once', () => {
    let message = '';
    try {
      parseConfig({
        tables: { a: 'nonsense', b: { kind: 'custom' } },
        functions: { f: { scope: 'whatever' } },
        rules: { 'not-a-rule': 'off' },
      });
    } catch (e) {
      message = (e as Error).message;
    }
    for (const path of ['tables.a:', 'tables.b.anon:', 'functions.f.scope:', 'rules.not-a-rule:']) {
      expect(message).toContain(path);
    }
  });

  it('accepts custom scopes', () => {
    const config = parseConfig({ scopes: ['party'], functions: { f: 'party' } });
    expect(config.functions.get('f')?.scope).toBe('party');
  });

  it('rejects listing anon or authenticated as an extra role', () => {
    expect(() => parseConfig({ roles: { anon: {} } })).toThrow(ConfigError);
  });

  it('rejects inheriting from an unchecked role', () => {
    expect(() => parseConfig({ roles: { guest: { inherits: 'nobody' } } })).toThrow(/inherits/);
  });

  it('lets an entry override its kind defaults', () => {
    const config = parseConfig({ tables: { t: { kind: 'scoped', anon: ['select'] } } });
    expect([...(config.tables.get('t')?.anon ?? [])]).toEqual(['select']);
  });
});

describe('check', () => {
  it('names the anon privilege a table kind forbids', () => {
    const result = check(
      snapshot({ tables: [table('notes', { privileges: { anon: { ...none, select: true }, authenticated: all } })] }),
      parseConfig({ tables: { notes: 'scoped' } }),
    );
    expect(result.findings).toMatchObject([
      { rule: 'anon-privileges', subject: 'notes', fix: 'REVOKE SELECT ON public.notes FROM anon;' },
    ]);
  });

  it('notices when anon loses a privilege it needs', () => {
    const result = check(snapshot({ tables: [table('countries')] }), parseConfig({ tables: { countries: 'public-read' } }));
    expect(result.findings[0]?.message).toMatch(/anon lost SELECT/);
  });

  it('ignores policies that apply only to non-client roles', () => {
    const t = table('jobs', {
      policies: [{ name: 'svc', cmd: 'ALL', roles: ['service_role'], using: 'true', check: 'true' }],
    });
    expect(check(snapshot({ tables: [t] }), parseConfig({ tables: { jobs: 'scoped' } })).findings).toEqual([]);
  });

  it('qualifies objects outside public', () => {
    const result = check(snapshot({ tables: [table('items', { schema: 'api' })] }), parseConfig({ schemas: ['api'] }));
    expect(result.findings[0]?.subject).toBe('api.items');
  });

  it('downgrades unreviewed entries to warnings only when asked', () => {
    const snap = snapshot({ tables: [table('t')], functions: [fn('f')] });
    const config = parseConfig({ tables: { t: 'unreviewed' }, functions: { f: 'unreviewed' } });
    expect(check(snap, config).findings.map((f) => f.severity)).toEqual(['error', 'error']);
    expect(check(snap, config, { allowUnreviewed: true }).findings.map((f) => f.severity)).toEqual(['warn', 'warn']);
  });

  it('honors per-rule severities', () => {
    const snap = snapshot({ functions: [fn('f', { pinsSearchPath: false })] });
    expect(check(snap, parseConfig({ functions: { f: 'self' }, rules: { 'definer-search-path': 'off' } })).findings).toEqual([]);
    expect(
      check(snap, parseConfig({ functions: { f: 'self' }, rules: { 'definer-search-path': 'warn' } })).findings[0]?.severity,
    ).toBe('warn');
  });

  it('checks only what an extra role holds beyond the role it inherits', () => {
    const snap = snapshot({
      roles: ['anon', 'authenticated', 'guest'],
      tables: [
        table('countries', {
          privileges: { anon: { ...none, select: true }, authenticated: all, guest: { ...none, select: true } },
          policies: [{ name: 'read', cmd: 'SELECT', roles: ['anon'], using: 'true', check: null }],
        }),
        table('rooms', { privileges: { anon: none, authenticated: all, guest: { ...none, select: true, update: true } } }),
      ],
      functions: [fn('join_room', { callableBy: { anon: false, authenticated: false, guest: true } })],
    });
    const config = parseConfig({
      roles: { guest: { inherits: 'anon', tables: { rooms: ['select'] }, functions: { join_room: 'why' } } },
      tables: { countries: 'public-read', rooms: 'scoped' },
      functions: { join_room: 'membership' },
    });
    expect(check(snap, config).findings.map((f) => `${f.rule} ${f.subject}: ${f.message}`)).toEqual([
      'role-privileges rooms: guest holds UPDATE beyond anon, and roles.guest.tables does not list it',
    ]);
  });
});

describe('render', () => {
  it('escapes GitHub annotations', () => {
    const out = render(
      {
        findings: [{ rule: 'rls-enabled', severity: 'error', subject: 'a,b', message: '100%\nnext', fix: 'x: y' }],
        openIssues: [],
        counted: { tables: 1, views: 0, definers: 0 },
      },
      'github',
    );
    expect(out.split('\n')[0]).toBe('::error title=rls-enabled%3A a%2Cb::100%25%0Anext%0Afix: x: y');
  });
});
