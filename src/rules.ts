import type { Config, RuleId, Severity } from './config.js';
import type { FunctionSnapshot, Policy, Privilege, PrivilegeSet, Snapshot } from './snapshot.js';
import { PRIVILEGES } from './snapshot.js';

export interface Finding {
  rule: RuleId;
  severity: Exclude<Severity, 'off'>;
  /** The table, view, function or config entry the finding is about. */
  subject: string;
  message: string;
  /** What to do about it, when there is one obvious fix. */
  fix?: string;
}

export interface CheckResult {
  findings: Finding[];
  /** Known gaps the config tracks with `openIssue:`, listed so they stay visible. */
  openIssues: { subject: string; issue: string }[];
  counted: { tables: number; views: number; definers: number };
}

export interface CheckOptions {
  /** Report `unreviewed` entries as warnings rather than errors (for adopting the tool). */
  allowUnreviewed?: boolean;
}

/** The name a config uses for an object: bare in `public`, qualified elsewhere. */
export function configKey(schema: string, name: string): string {
  return schema === 'public' ? name : `${schema}.${name}`;
}

export const RULE_DESCRIPTIONS: Record<RuleId, string> = {
  'rls-enabled': 'Every table has row level security enabled.',
  'tables-classified': 'Every table is classified in the config.',
  'anon-privileges': 'anon holds exactly the privileges its table kind allows.',
  'internal-closed': 'Internal tables have no policies and no client grants.',
  'no-permissive-writes': 'No INSERT/UPDATE/DELETE policy is unconditionally true.',
  'no-public-policies': 'Every policy names its roles; none is TO public.',
  'open-select-declared': 'USING (true) on SELECT only where the config declares it.',
  'views-closed': 'Client-readable views are listed, and respect RLS unless declared.',
  'definers-classified': 'Every client-callable SECURITY DEFINER function is classified.',
  'definer-anon-pre-login': 'anon can call a definer function only if it is classified pre-login.',
  'definer-not-public': 'No SECURITY DEFINER function is granted to PUBLIC.',
  'definer-search-path': 'Every client-callable SECURITY DEFINER function pins search_path.',
  'role-privileges': 'Extra roles hold exactly their inherited table privileges plus their list.',
  'role-functions': 'Extra roles can call exactly their inherited functions plus their list.',
  'open-issue-format': 'Every openIssue matches issuePattern.',
  'no-stale-entries': 'Every config entry still matches something in the database.',
};

const WRITE_COMMANDS = new Set(['INSERT', 'UPDATE', 'DELETE', 'ALL']);

export function check(snapshot: Snapshot, config: Config, options: CheckOptions = {}): CheckResult {
  const findings: Finding[] = [];
  const report = (
    rule: RuleId,
    subject: string,
    message: string,
    extra: { fix?: string; unreviewed?: boolean } = {},
  ) => {
    let severity = config.rules.get(rule) ?? 'error';
    if (severity === 'off') return;
    if (extra.unreviewed && options.allowUnreviewed) severity = 'warn';
    findings.push({ rule, severity, subject, message, ...(extra.fix ? { fix: extra.fix } : {}) });
  };

  const clientRoles = snapshot.roles;
  const appliesToClients = (p: Policy) =>
    p.roles.includes('PUBLIC') || p.roles.some((r) => clientRoles.includes(r));
  const held = (privs: PrivilegeSet | undefined): Set<Privilege> =>
    new Set(PRIVILEGES.filter((p) => privs?.[p]));
  const list = (privs: Iterable<Privilege>) =>
    [...privs].map((p) => p.toUpperCase()).join(', ');

  // ── Tables ──────────────────────────────────────────────────────────────────
  const liveTables = new Set<string>();
  for (const t of snapshot.tables) {
    const key = configKey(t.schema, t.name);
    liveTables.add(key);
    const entry = config.tables.get(key);

    if (!t.rls) {
      report('rls-enabled', key, 'row level security is off', {
        fix: `ALTER TABLE ${t.schema}.${t.name} ENABLE ROW LEVEL SECURITY;`,
      });
    }

    if (!entry) {
      report('tables-classified', key, 'not classified — decide what it is and say why', {
        fix: `add \`${key}: <kind>\` under tables:`,
      });
    } else if (entry.kind === 'unreviewed') {
      report('tables-classified', key, 'still unreviewed', { unreviewed: true });
    }

    if (entry && entry.kind !== 'unreviewed') {
      const anon = held(t.privileges.anon);
      for (const p of PRIVILEGES) {
        if (anon.has(p) && !entry.anon.has(p)) {
          report('anon-privileges', key, `anon holds ${p.toUpperCase()}, which a ${entry.kind} table must not grant`, {
            fix: `REVOKE ${p.toUpperCase()} ON ${t.schema}.${t.name} FROM anon;`,
          });
        } else if (!anon.has(p) && entry.anon.has(p)) {
          report('anon-privileges', key, `anon lost ${p.toUpperCase()}, which the config says it needs${entry.reason ? ` — ${entry.reason}` : ''}`);
        }
      }
    }

    if (entry?.kind === 'internal') {
      if (t.policies.length > 0) {
        report('internal-closed', key, `internal, but has ${t.policies.length} polic${t.policies.length === 1 ? 'y' : 'ies'}`);
      }
      for (const role of clientRoles) {
        const privs = held(t.privileges[role]);
        if (privs.size > 0) {
          report('internal-closed', key, `internal, but ${role} holds ${list(privs)}`, {
            fix: `REVOKE ALL ON ${t.schema}.${t.name} FROM ${role};`,
          });
        }
      }
    }

    for (const p of t.policies) {
      if (p.roles.includes('PUBLIC')) {
        report('no-public-policies', key, `${p.cmd} policy "${p.name}" is TO public, so it admits every role, including ones added later`, {
          fix: 'recreate it TO authenticated (or TO anon, authenticated where anon really uses it)',
        });
      }
      if (!appliesToClients(p)) continue;
      if (WRITE_COMMANDS.has(p.cmd) && (p.using === 'true' || p.check === 'true')) {
        report('no-permissive-writes', key, `${p.cmd} policy "${p.name}" is always true`);
      }
      if ((p.cmd === 'SELECT' || p.cmd === 'ALL') && p.using === 'true' && !entry?.openSelect) {
        report('open-select-declared', key, `${p.cmd} policy "${p.name}" is USING (true), and the table is not declared openSelect`, {
          unreviewed: entry?.kind === 'unreviewed',
        });
      }
    }
  }

  // ── Views ───────────────────────────────────────────────────────────────────
  const liveViews = new Set<string>();
  for (const v of snapshot.views) {
    const readers = clientRoles.filter((r) => v.readableBy[r]);
    if (readers.length === 0) continue;
    const key = configKey(v.schema, v.name);
    liveViews.add(key);
    const entry = config.views.get(key);
    if (!entry) {
      report('views-closed', key, `${v.kind} readable by ${readers.join(', ')}, and not listed under views:`, {
        fix: `REVOKE SELECT ON ${v.schema}.${v.name} FROM ${readers.join(', ')};`,
      });
    } else if (v.kind === 'view' && !v.securityInvoker && !entry.bypassesRls) {
      report('views-closed', key, 'runs as its owner, so it skips the RLS of every table it reads', {
        fix: `ALTER VIEW ${v.schema}.${v.name} SET (security_invoker = true); — or declare bypassesRls: true if that is the point`,
      });
    }
  }

  // ── SECURITY DEFINER functions ──────────────────────────────────────────────
  const callable = (f: FunctionSnapshot) => clientRoles.some((r) => f.callableBy[r]);
  const signature = (f: FunctionSnapshot) => `${f.schema}.${f.name}(${f.args})`;
  const liveDefiners = new Set<string>();
  for (const f of snapshot.functions) {
    if (!f.definer) continue;
    const key = configKey(f.schema, f.name);
    if (f.grantedToPublic) {
      report('definer-not-public', key, 'granted EXECUTE to PUBLIC, which reaches every role, including ones created later. REVOKE … FROM anon alone leaves it in place', {
        fix: `REVOKE ALL ON FUNCTION ${signature(f)} FROM public, anon, authenticated;`,
      });
    }
    if (!callable(f)) continue;
    liveDefiners.add(key);
    const entry = config.functions.get(key);
    const callers = clientRoles.filter((r) => f.callableBy[r]);
    if (!entry) {
      report('definers-classified', key, `callable by ${callers.join(', ')} and bypasses RLS, but not classified — decide whose rows it may touch, enforce that in the body, and list it`, {
        fix: f.callableBy.anon
          ? `if nothing signed-out needs it: REVOKE ALL ON FUNCTION ${signature(f)} FROM public, anon, authenticated; then GRANT EXECUTE to the one role that does`
          : undefined,
      });
    } else if (entry.scope === 'unreviewed') {
      report('definers-classified', key, 'still unreviewed', { unreviewed: true });
    } else if (f.callableBy.anon && entry.scope !== 'pre-login') {
      report('definer-anon-pre-login', key, `anon can call it, but it is classified ${entry.scope}. Anyone holding your anon key — i.e. anyone with your app — can call it`, {
        fix: `REVOKE ALL ON FUNCTION ${signature(f)} FROM public, anon, authenticated; GRANT EXECUTE ON FUNCTION ${signature(f)} TO authenticated;`,
      });
    }
    if (!f.pinsSearchPath) {
      report('definer-search-path', key, 'does not pin search_path, so a caller can make its unqualified names resolve to their own objects, run as the owner', {
        fix: `ALTER FUNCTION ${signature(f)} SET search_path = '';  (then schema-qualify every name in the body)`,
      });
    }
  }

  if (config.issuePattern) {
    for (const [name, entry] of config.functions) {
      if (entry.openIssue !== undefined && !config.issuePattern.test(entry.openIssue)) {
        report('open-issue-format', name, `openIssue "${entry.openIssue}" does not match ${config.issuePattern}`);
      }
    }
  }

  // ── Extra roles ─────────────────────────────────────────────────────────────
  for (const [role, entry] of config.roles) {
    const parent = entry.inherits;
    for (const t of snapshot.tables) {
      const key = configKey(t.schema, t.name);
      const parentHeld = parent ? held(t.privileges[parent]) : new Set<Privilege>();
      const extra = new Set([...held(t.privileges[role])].filter((p) => !parentHeld.has(p)));
      const allowed = entry.tables.get(key) ?? new Set<Privilege>();
      for (const p of extra) {
        if (!allowed.has(p)) {
          report('role-privileges', key, `${role} holds ${p.toUpperCase()}${parent ? ` beyond ${parent}` : ''}, and roles.${role}.tables does not list it`);
        }
      }
      for (const p of allowed) {
        if (!extra.has(p)) {
          report('role-privileges', key, `${role} lost ${p.toUpperCase()}, which roles.${role}.tables says it needs`);
        }
      }
    }
    const extraFns = new Set<string>();
    for (const f of snapshot.functions) {
      if (f.callableBy[role] && !(parent && f.callableBy[parent])) {
        extraFns.add(configKey(f.schema, f.name));
      }
    }
    for (const fn of extraFns) {
      if (!entry.functions.has(fn)) {
        report('role-functions', fn, `callable by ${role}${parent ? ` but not ${parent}` : ''}, and roles.${role}.functions does not list it`);
      }
    }
    for (const fn of entry.functions.keys()) {
      if (!extraFns.has(fn)) {
        report('role-functions', fn, `listed under roles.${role}.functions, but ${role} cannot call it${parent ? ` (or ${parent} can too)` : ''}`);
      }
    }
    for (const table of entry.tables.keys()) {
      if (!liveTables.has(table)) {
        report('no-stale-entries', `roles.${role}.tables.${table}`, 'no such table');
      }
    }
  }

  // ── Stale entries ───────────────────────────────────────────────────────────
  for (const name of config.tables.keys()) {
    if (!liveTables.has(name)) {
      report('no-stale-entries', `tables.${name}`, 'no such table — remove the entry so the list stays true');
    }
  }
  for (const name of config.views.keys()) {
    if (!liveViews.has(name)) {
      report('no-stale-entries', `views.${name}`, 'no client-readable view by this name');
    }
  }
  for (const name of config.functions.keys()) {
    if (!liveDefiners.has(name)) {
      report('no-stale-entries', `functions.${name}`, 'no longer a SECURITY DEFINER function any client role can call');
    }
  }

  const openIssues = [...config.functions]
    .filter(([, e]) => e.openIssue !== undefined)
    .map(([subject, e]) => ({ subject, issue: e.openIssue as string }));

  return {
    findings,
    openIssues,
    counted: {
      tables: snapshot.tables.length,
      views: liveViews.size,
      definers: liveDefiners.size,
    },
  };
}
