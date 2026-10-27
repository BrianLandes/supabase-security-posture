import { readFile } from 'node:fs/promises';
import { parse } from 'yaml';
import { PRIVILEGES, type Privilege } from './snapshot.js';

export const DEFAULT_CONFIG_PATH = 'supabase-security-posture.yaml';

/**
 * What a table is, and so what anon may do to it. Each kind is a decision
 * someone made on purpose; `unreviewed` is the placeholder `init` writes until
 * they do.
 */
export const TABLE_KINDS = {
  /** RLS on, no policies, no client grants. service_role and definer functions only. */
  internal: { anon: [], openSelect: false },
  /** Rows scoped to the caller by policy. anon has no business here. */
  scoped: { anon: [], openSelect: false },
  /** Readable by every signed-in user (`USING (true)` for authenticated), not by anon. */
  'signed-in-read': { anon: [], openSelect: true },
  /** Public reference data. anon may SELECT, and nothing else. */
  'public-read': { anon: ['select'], openSelect: true },
  /** Pre-sign-in writes (analytics, error reports). anon may INSERT, and nothing else. */
  'anon-insert': { anon: ['insert'], openSelect: false },
  /** Spell out `anon:` and `openSelect:` yourself. */
  custom: { anon: [], openSelect: false },
  /** Not yet classified. Fails `check` unless `--allow-unreviewed`. */
  unreviewed: { anon: [], openSelect: false },
} as const satisfies Record<string, { anon: Privilege[]; openSelect: boolean }>;

export type TableKind = keyof typeof TABLE_KINDS;

/**
 * How a SECURITY DEFINER function limits whose rows it touches. A definer body
 * bypasses RLS, so the body is the only thing between a caller and everyone
 * else's data.
 */
export const BUILT_IN_SCOPES = [
  /** Acts only on, or returns only, the caller's own rows (`auth.uid()`). */
  'self',
  /** Requires the caller to be a member of the team/group/org it touches. */
  'membership',
  /** Requires a relationship (contact, follower, thread) with the other user. */
  'relationship',
  /** Checks a staff or admin flag on the caller before acting. */
  'staff',
  /** Deliberately open to any signed-in user: shared, non-personal data only. */
  'open',
  /** A boolean helper used inside RLS policies, answering about `auth.uid()`. */
  'policy-helper',
  /** Granted to anon on purpose: used before sign-in. */
  'pre-login',
  /** Not yet classified. Fails `check` unless `--allow-unreviewed`. */
  'unreviewed',
] as const;

export const RULE_IDS = [
  'rls-enabled',
  'tables-classified',
  'anon-privileges',
  'internal-closed',
  'no-permissive-writes',
  'no-public-policies',
  'open-select-declared',
  'views-closed',
  'definers-classified',
  'definer-anon-pre-login',
  'definer-not-public',
  'definer-search-path',
  'role-privileges',
  'role-functions',
  'open-issue-format',
  'no-stale-entries',
] as const;

export type RuleId = (typeof RULE_IDS)[number];
export type Severity = 'error' | 'warn' | 'off';

export interface TableEntry {
  kind: TableKind;
  anon: Set<Privilege>;
  openSelect: boolean;
  reason?: string;
}

export interface FunctionEntry {
  scope: string;
  reason?: string;
  openIssue?: string;
}

export interface ViewEntry {
  reason?: string;
  /** Declares that the view deliberately runs as its owner, skipping RLS. */
  bypassesRls: boolean;
}

/** An extra client role, e.g. a `guest` role set by a custom access-token hook. */
export interface RoleEntry {
  /** The role it is a member of. Only privileges beyond that role's are checked. */
  inherits?: string;
  tables: Map<string, Set<Privilege>>;
  functions: Map<string, string>;
}

export interface Config {
  schemas: string[];
  /** Every role checked: anon, authenticated, then the extra roles. */
  clientRoles: string[];
  roles: Map<string, RoleEntry>;
  tables: Map<string, TableEntry>;
  views: Map<string, ViewEntry>;
  functions: Map<string, FunctionEntry>;
  scopes: Set<string>;
  issuePattern?: RegExp;
  rules: Map<RuleId, Severity>;
}

export class ConfigError extends Error {}

export async function loadConfig(path: string): Promise<Config> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    throw new ConfigError(
      `No config at ${path}. Run \`supabase-security-posture init\` to generate one.`,
    );
  }
  let raw: unknown;
  try {
    raw = parse(text);
  } catch (e) {
    throw new ConfigError(`${path}: ${(e as Error).message}`);
  }
  return parseConfig(raw ?? {}, path);
}

/** Validates a parsed config. Every mistake is reported, not just the first. */
export function parseConfig(raw: unknown, source = 'config'): Config {
  const errors: string[] = [];
  const root = asObject(raw, source, errors) ?? {};

  const schemas = stringList(root.schemas, 'schemas', errors) ?? ['public'];
  const scopes = new Set<string>([
    ...BUILT_IN_SCOPES,
    ...(stringList(root.scopes, 'scopes', errors) ?? []),
  ]);

  let issuePattern: RegExp | undefined;
  if (root.issuePattern !== undefined) {
    if (typeof root.issuePattern !== 'string') {
      errors.push('issuePattern: must be a string (a regular expression)');
    } else {
      try {
        issuePattern = new RegExp(root.issuePattern);
      } catch (e) {
        errors.push(`issuePattern: ${(e as Error).message}`);
      }
    }
  }

  const rules = new Map<RuleId, Severity>(RULE_IDS.map((id) => [id, 'error']));
  for (const [id, value] of Object.entries(asObject(root.rules, 'rules', errors) ?? {})) {
    if (!(RULE_IDS as readonly string[]).includes(id)) {
      errors.push(`rules.${id}: unknown rule (known: ${RULE_IDS.join(', ')})`);
    } else if (value !== 'error' && value !== 'warn' && value !== 'off') {
      errors.push(`rules.${id}: must be error, warn or off`);
    } else {
      rules.set(id as RuleId, value);
    }
  }

  const tables = new Map<string, TableEntry>();
  for (const [name, value] of Object.entries(asObject(root.tables, 'tables', errors) ?? {})) {
    const entry = parseTable(value, `tables.${name}`, errors);
    if (entry) tables.set(name, entry);
  }

  const views = new Map<string, ViewEntry>();
  for (const [name, value] of Object.entries(asObject(root.views, 'views', errors) ?? {})) {
    const path = `views.${name}`;
    if (typeof value === 'string' || value === null) {
      views.set(name, { reason: value ?? undefined, bypassesRls: false });
      continue;
    }
    const obj = asObject(value, path, errors);
    if (!obj) continue;
    views.set(name, {
      reason: optionalString(obj.reason, `${path}.reason`, errors),
      bypassesRls: optionalBool(obj.bypassesRls, `${path}.bypassesRls`, errors) ?? false,
    });
  }

  const functions = new Map<string, FunctionEntry>();
  for (const [name, value] of Object.entries(asObject(root.functions, 'functions', errors) ?? {})) {
    const path = `functions.${name}`;
    if (typeof value === 'string') {
      checkScope(value, path, scopes, errors);
      functions.set(name, { scope: value });
      continue;
    }
    const obj = asObject(value, path, errors);
    if (!obj) continue;
    const scope = obj.scope;
    if (typeof scope !== 'string') {
      errors.push(`${path}.scope: required (one of ${[...scopes].join(', ')})`);
      continue;
    }
    checkScope(scope, `${path}.scope`, scopes, errors);
    functions.set(name, {
      scope,
      reason: optionalString(obj.reason, `${path}.reason`, errors),
      openIssue: optionalString(obj.openIssue, `${path}.openIssue`, errors),
    });
  }

  const roles = new Map<string, RoleEntry>();
  for (const [name, value] of Object.entries(asObject(root.roles, 'roles', errors) ?? {})) {
    const path = `roles.${name}`;
    if (name === 'anon' || name === 'authenticated') {
      errors.push(`${path}: anon and authenticated are always checked; list only extra roles`);
      continue;
    }
    const obj = asObject(value ?? {}, path, errors);
    if (!obj) continue;
    const roleTables = new Map<string, Set<Privilege>>();
    for (const [table, privs] of Object.entries(
      asObject(obj.tables, `${path}.tables`, errors) ?? {},
    )) {
      const set = privilegeSet(privs, `${path}.tables.${table}`, errors);
      if (set) roleTables.set(table, set);
    }
    const roleFunctions = new Map<string, string>();
    for (const [fn, reason] of Object.entries(
      asObject(obj.functions, `${path}.functions`, errors) ?? {},
    )) {
      roleFunctions.set(fn, typeof reason === 'string' ? reason : '');
    }
    roles.set(name, {
      inherits: optionalString(obj.inherits, `${path}.inherits`, errors),
      tables: roleTables,
      functions: roleFunctions,
    });
  }

  for (const [name, entry] of roles) {
    const known = ['anon', 'authenticated', ...roles.keys()].filter((r) => r !== name);
    if (entry.inherits !== undefined && !known.includes(entry.inherits)) {
      errors.push(`roles.${name}.inherits: "${entry.inherits}" is not a checked role (known: ${known.join(', ')})`);
    }
  }

  if (errors.length > 0) {
    throw new ConfigError(`Invalid ${source}:\n  ${errors.join('\n  ')}`);
  }

  return {
    schemas,
    clientRoles: ['anon', 'authenticated', ...roles.keys()],
    roles,
    tables,
    views,
    functions,
    scopes,
    issuePattern,
    rules,
  };
}

function parseTable(value: unknown, path: string, errors: string[]): TableEntry | undefined {
  // Shorthand: `profiles: scoped`.
  if (typeof value === 'string') {
    if (!isKind(value)) {
      errors.push(`${path}: unknown kind "${value}" (known: ${Object.keys(TABLE_KINDS).join(', ')})`);
      return undefined;
    }
    if (value === 'custom') {
      errors.push(`${path}: kind custom needs the object form, with anon: and openSelect:`);
      return undefined;
    }
    const defaults = TABLE_KINDS[value];
    return { kind: value, anon: new Set(defaults.anon), openSelect: defaults.openSelect };
  }
  const obj = asObject(value, path, errors);
  if (!obj) return undefined;
  const kind = obj.kind;
  if (typeof kind !== 'string' || !isKind(kind)) {
    errors.push(`${path}.kind: required (one of ${Object.keys(TABLE_KINDS).join(', ')})`);
    return undefined;
  }
  const defaults = TABLE_KINDS[kind];
  if (kind === 'custom' && obj.anon === undefined) {
    errors.push(`${path}.anon: required for kind custom (a list, possibly empty)`);
  }
  if (kind === 'internal' && (obj.anon !== undefined || obj.openSelect !== undefined)) {
    errors.push(`${path}: an internal table has no client access; drop anon/openSelect`);
  }
  return {
    kind,
    anon:
      obj.anon === undefined
        ? new Set(defaults.anon)
        : (privilegeSet(obj.anon, `${path}.anon`, errors) ?? new Set()),
    openSelect: optionalBool(obj.openSelect, `${path}.openSelect`, errors) ?? defaults.openSelect,
    reason: optionalString(obj.reason, `${path}.reason`, errors),
  };
}

function isKind(value: string): value is TableKind {
  return Object.hasOwn(TABLE_KINDS, value);
}

function checkScope(scope: string, path: string, scopes: Set<string>, errors: string[]) {
  if (!scopes.has(scope)) {
    errors.push(
      `${path}: unknown scope "${scope}" (known: ${[...scopes].join(', ')}; add your own under scopes:)`,
    );
  }
}

function asObject(
  value: unknown,
  path: string,
  errors: string[],
): Record<string, unknown> | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'object' || Array.isArray(value)) {
    errors.push(`${path}: must be a mapping`);
    return undefined;
  }
  return value as Record<string, unknown>;
}

function stringList(value: unknown, path: string, errors: string[]): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) {
    errors.push(`${path}: must be a list of strings`);
    return undefined;
  }
  return value;
}

function privilegeSet(value: unknown, path: string, errors: string[]): Set<Privilege> | undefined {
  const list = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(list)) {
    errors.push(`${path}: must be a list of privileges (${PRIVILEGES.join(', ')})`);
    return undefined;
  }
  const set = new Set<Privilege>();
  for (const p of list) {
    if (typeof p !== 'string' || !(PRIVILEGES as readonly string[]).includes(p.toLowerCase())) {
      errors.push(`${path}: unknown privilege ${JSON.stringify(p)} (known: ${PRIVILEGES.join(', ')})`);
    } else {
      set.add(p.toLowerCase() as Privilege);
    }
  }
  return set;
}

function optionalString(value: unknown, path: string, errors: string[]): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') {
    errors.push(`${path}: must be a string`);
    return undefined;
  }
  return value;
}

function optionalBool(value: unknown, path: string, errors: string[]): boolean | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'boolean') {
    errors.push(`${path}: must be true or false`);
    return undefined;
  }
  return value;
}
