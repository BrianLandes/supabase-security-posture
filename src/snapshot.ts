import pg from 'pg';

/** Table-level privileges a client role can hold. */
export type Privilege = 'select' | 'insert' | 'update' | 'delete';
export const PRIVILEGES: readonly Privilege[] = ['select', 'insert', 'update', 'delete'];

export type PrivilegeSet = Record<Privilege, boolean>;

export interface Policy {
  name: string;
  cmd: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'ALL';
  /** Role names, or `["PUBLIC"]` for a policy written without `TO`. */
  roles: string[];
  using: string | null;
  check: string | null;
}

export interface TableSnapshot {
  schema: string;
  name: string;
  rls: boolean;
  /**
   * What each client role can do, counting column-level grants: a role that
   * can SELECT one column can read the table through PostgREST.
   */
  privileges: Record<string, PrivilegeSet>;
  policies: Policy[];
}

export interface ViewSnapshot {
  schema: string;
  name: string;
  kind: 'view' | 'materialized view' | 'foreign table';
  /** A view without `security_invoker` runs as its owner and skips RLS. */
  securityInvoker: boolean;
  readableBy: Record<string, boolean>;
}

export interface FunctionSnapshot {
  schema: string;
  name: string;
  /** Identity arguments, to tell overloads apart in messages. */
  args: string;
  definer: boolean;
  /** Whether the function pins `search_path` (`SET search_path = ...`). */
  pinsSearchPath: boolean;
  /** Granted EXECUTE to the PUBLIC pseudo-role, explicitly or by default ACL. */
  grantedToPublic: boolean;
  callableBy: Record<string, boolean>;
}

export interface Snapshot {
  /** The client roles checked, in the order given. */
  roles: string[];
  tables: TableSnapshot[];
  views: ViewSnapshot[];
  functions: FunctionSnapshot[];
}

/**
 * One query that reads everything the rules need from the catalog.
 *
 * Privileges come from `has_table_privilege` / `has_function_privilege`, never
 * from parsing ACLs: those resolve PUBLIC, role inheritance and default ACLs
 * the way Postgres does at call time. Pattern-matching `proacl` for `anon=X`
 * misses every function reachable through PUBLIC.
 *
 * Objects owned by an extension (PostGIS's `spatial_ref_sys`, say) are
 * skipped: you can't change their posture from a migration anyway.
 */
export const SNAPSHOT_SQL = `
WITH roles AS (SELECT unnest($1::text[]) AS r),
ext AS (
  SELECT objid FROM pg_catalog.pg_depend WHERE deptype = 'e'
)
SELECT jsonb_build_object(
  'tables', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'schema', ns.nspname,
      'name',   c.relname,
      'rls',    c.relrowsecurity,
      'privileges', (
        SELECT jsonb_object_agg(r, jsonb_build_object(
          'select', has_table_privilege(r, c.oid, 'SELECT') OR has_any_column_privilege(r, c.oid, 'SELECT'),
          'insert', has_table_privilege(r, c.oid, 'INSERT') OR has_any_column_privilege(r, c.oid, 'INSERT'),
          'update', has_table_privilege(r, c.oid, 'UPDATE') OR has_any_column_privilege(r, c.oid, 'UPDATE'),
          'delete', has_table_privilege(r, c.oid, 'DELETE')))
        FROM roles),
      'policies', (
        SELECT coalesce(jsonb_agg(jsonb_build_object(
          'name',  p.polname,
          'cmd',   CASE p.polcmd WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT'
                                 WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE'
                                 ELSE 'ALL' END,
          'roles', CASE WHEN p.polroles = '{0}'::oid[] THEN '["PUBLIC"]'::jsonb
                        ELSE (SELECT jsonb_agg(rolname ORDER BY rolname)
                                FROM pg_catalog.pg_roles WHERE oid = ANY (p.polroles)) END,
          'using', pg_catalog.pg_get_expr(p.polqual, p.polrelid),
          'check', pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid)
        ) ORDER BY p.polname), '[]'::jsonb)
        FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid)
    ) ORDER BY ns.nspname, c.relname), '[]'::jsonb)
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace ns ON ns.oid = c.relnamespace
    WHERE ns.nspname = ANY ($2::text[])
      AND c.relkind IN ('r', 'p')
      AND c.oid NOT IN (SELECT objid FROM ext)
  ),
  'views', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'schema', ns.nspname,
      'name',   c.relname,
      'kind',   CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized view'
                               ELSE 'foreign table' END,
      'securityInvoker', coalesce(c.reloptions @> ARRAY['security_invoker=true']
                                  OR c.reloptions @> ARRAY['security_invoker=on'], false),
      'readableBy', (
        SELECT jsonb_object_agg(r, has_table_privilege(r, c.oid, 'SELECT')
                                   OR has_any_column_privilege(r, c.oid, 'SELECT'))
        FROM roles)
    ) ORDER BY ns.nspname, c.relname), '[]'::jsonb)
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace ns ON ns.oid = c.relnamespace
    WHERE ns.nspname = ANY ($2::text[])
      AND c.relkind IN ('v', 'm', 'f')
      AND c.oid NOT IN (SELECT objid FROM ext)
  ),
  'functions', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'schema',  ns.nspname,
      'name',    p.proname,
      'args',    pg_catalog.pg_get_function_identity_arguments(p.oid),
      'definer', p.prosecdef,
      'pinsSearchPath', EXISTS (
        SELECT 1 FROM unnest(coalesce(p.proconfig, '{}'::text[])) cfg
        WHERE cfg LIKE 'search_path=%'),
      'grantedToPublic', EXISTS (
        SELECT 1 FROM pg_catalog.aclexplode(
          coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
        WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'),
      'callableBy', (
        SELECT jsonb_object_agg(r, has_function_privilege(r, p.oid, 'EXECUTE'))
        FROM roles)
    ) ORDER BY ns.nspname, p.proname, p.oid), '[]'::jsonb)
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace ns ON ns.oid = p.pronamespace
    WHERE ns.nspname = ANY ($2::text[])
      AND p.prokind = 'f'
      -- Postgres refuses to call trigger functions directly.
      AND p.prorettype NOT IN ('pg_catalog.trigger'::pg_catalog.regtype,
                               'pg_catalog.event_trigger'::pg_catalog.regtype)
      AND p.oid NOT IN (SELECT objid FROM ext)
  )
) AS snapshot
`;

const ROLES_EXIST_SQL = `
SELECT r FROM unnest($1::text[]) AS r
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r)
`;

export class SnapshotError extends Error {}

/** Reads the posture of `schemas` as seen by each of `roles`. */
export async function takeSnapshot(
  dbUrl: string,
  roles: string[],
  schemas: string[],
): Promise<Snapshot> {
  const client = new pg.Client({ connectionString: dbUrl });
  try {
    await client.connect();
  } catch (e) {
    throw new SnapshotError(`Could not connect to ${redact(dbUrl)}: ${(e as Error).message}`);
  }
  try {
    const missing = await client.query<{ r: string }>(ROLES_EXIST_SQL, [roles]);
    if (missing.rows.length > 0) {
      throw new SnapshotError(
        `Role(s) not found in the database: ${missing.rows.map((row) => row.r).join(', ')}. ` +
          'Remove them from `roles:` in the config, or check you are connected to the right database.',
      );
    }
    const result = await client.query<{ snapshot: Omit<Snapshot, 'roles'> }>(SNAPSHOT_SQL, [
      roles,
      schemas,
    ]);
    const snapshot = result.rows[0]?.snapshot;
    if (!snapshot) throw new SnapshotError('The snapshot query returned no rows.');
    return { roles, ...snapshot };
  } finally {
    await client.end();
  }
}

/** Hides the password in a connection string before it goes in a message. */
export function redact(dbUrl: string): string {
  try {
    const url = new URL(dbUrl);
    if (url.password) url.password = '***';
    return url.toString();
  } catch {
    return '<database url>';
  }
}
