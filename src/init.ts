import { configKey } from './rules.js';
import { PRIVILEGES, type Snapshot, type TableSnapshot } from './snapshot.js';

/**
 * Writes a starting config that lists every table and client-callable
 * SECURITY DEFINER function as `unreviewed`, with a comment describing what
 * each looks like today.
 *
 * It deliberately does not classify anything. Classifying from the current
 * state would bless whatever leak is already there: a table anon can read
 * through `USING (true)` "looks like" public reference data. The point of the
 * config is that a person decided.
 */
export function generateConfig(snapshot: Snapshot, schemas: string[], extraRoles: string[]): string {
  const lines = [
    '# supabase-security-posture config. https://github.com/BrianLandes/supabase-security-posture',
    '#',
    '# Everything below starts as `unreviewed`. Replace each with what the object is',
    "# meant to be. The comment says what it looks like today, which isn't necessarily",
    '# what it should be. `check` fails until nothing is unreviewed; pass',
    '# --allow-unreviewed to adopt it gradually.',
    '',
    `schemas: [${schemas.join(', ')}]`,
    '',
  ];

  if (extraRoles.length > 0) {
    lines.push(
      '# Extra client roles, e.g. one set by a custom access-token hook. List what',
      '# each may do beyond the role it inherits.',
      'roles:',
    );
    for (const role of extraRoles) {
      lines.push(`  ${yamlKey(role)}:`, '    inherits: anon', '    tables: {}', '    functions: {}');
    }
    lines.push('');
  }

  lines.push(
    '# Kinds: internal, scoped, signed-in-read, public-read, anon-insert, custom.',
    'tables:',
  );
  if (snapshot.tables.length === 0) lines.push('  {}');
  for (const t of snapshot.tables) {
    lines.push(`  ${yamlKey(configKey(t.schema, t.name))}: unreviewed  # ${describeTable(t, snapshot.roles)}`);
  }
  lines.push('');

  const definers = snapshot.functions.filter(
    (f) => f.definer && snapshot.roles.some((r) => f.callableBy[r]),
  );
  lines.push(
    '# Every SECURITY DEFINER function a client can call, by how its body limits',
    '# whose rows it touches: self, membership, relationship, staff, open,',
    '# policy-helper, pre-login. Use the object form to add a reason:',
    '#   get_my_profile: { scope: self, reason: returns the caller\'s own row }',
    'functions:',
  );
  const seen = new Set<string>();
  for (const f of definers) {
    const key = configKey(f.schema, f.name);
    if (seen.has(key)) continue;
    seen.add(key);
    const callers = snapshot.roles.filter((r) => f.callableBy[r]);
    const notes = [`callable by ${callers.join(', ')}`];
    if (!f.pinsSearchPath) notes.push('no search_path');
    if (f.grantedToPublic) notes.push('granted to PUBLIC');
    lines.push(`  ${yamlKey(key)}: unreviewed  # ${notes.join('; ')}`);
  }
  if (seen.size === 0) lines.push('  {}');

  const readableViews = snapshot.views.filter((v) => snapshot.roles.some((r) => v.readableBy[r]));
  if (readableViews.length > 0) {
    lines.push(
      '',
      '# These views are readable by clients. Revoke them, or uncomment the entries',
      '# you mean to expose (add `bypassesRls: true` to one without security_invoker',
      '# only if skipping RLS is the point).',
      '# views:',
    );
    for (const v of readableViews) {
      const key = configKey(v.schema, v.name);
      const note = v.kind === 'view' && !v.securityInvoker ? '  # runs as owner, skips RLS' : '';
      lines.push(`#   ${yamlKey(key)}: <reason>${note}`);
    }
  }

  return `${lines.join('\n')}\n`;
}

function describeTable(t: TableSnapshot, roles: string[]): string {
  if (!t.rls) return 'RLS IS OFF';
  const anon = PRIVILEGES.filter((p) => t.privileges.anon?.[p]);
  const anyClientGrant = roles.some((r) => PRIVILEGES.some((p) => t.privileges[r]?.[p]));
  const openSelect = t.policies.some(
    (p) => (p.cmd === 'SELECT' || p.cmd === 'ALL') && p.using === 'true',
  );
  let looks: string;
  if (t.policies.length === 0 && !anyClientGrant) looks = 'internal';
  else if (t.policies.length === 0) looks = 'no policies, so clients see nothing';
  else if (openSelect && anon.includes('select')) looks = 'public-read';
  else if (openSelect) looks = 'signed-in-read';
  else if (anon.length === 1 && anon[0] === 'insert') looks = 'anon-insert';
  else looks = 'scoped';
  const anonNote = anon.length > 0 ? `; anon holds ${anon.map((p) => p.toUpperCase()).join(', ')}` : '';
  return `looks ${looks}${anonNote}`;
}

function yamlKey(key: string): string {
  return /^[A-Za-z_][\w.]*$/.test(key) ? key : JSON.stringify(key);
}
