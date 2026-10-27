# supabase-security-posture

**Fail CI when your Supabase database drifts from the security posture you declared.**

Supabase puts your Postgres database on the internet behind one shared key, the anon key, which ships inside every copy of your app. Row level security, grants and `SECURITY DEFINER` functions are what stand between that key and your users' data. When one of them is wrong, nothing warns you. The app works, every test passes, and anyone can read the table.

`supabase-security-posture` makes you write down what each table and function is *meant* to be, then checks the live database against that on every push. A new table or function fails the build until someone decides who may touch it, and says why.

```text
$ npx supabase-security-posture check
Checked 84 tables, 0 client-readable views and 139 client-callable SECURITY DEFINER functions.

✗ tables-classified  Every table is classified in the config.
    drafts: not classified — decide what it is and say why
      fix: add `drafts: <kind>` under tables:

✗ definer-anon-pre-login  anon can call a definer function only if it is classified pre-login.
    whoami: anon can call it, but it is classified self. Anyone holding your anon key — i.e. anyone with your app — can call it
      fix: REVOKE ALL ON FUNCTION public.whoami() FROM public, anon, authenticated; GRANT EXECUTE ON FUNCTION public.whoami() TO authenticated;

2 errors, 0 warnings.
Fix the migration, not the config, unless the new posture is deliberate. Then classify it and say why.
```

## Why this exists

This was built for a production Flutter + Supabase app, after audits there found:

- **116 `SECURITY DEFINER` functions callable by anyone with the anon key.** Every one had been "locked down" with `REVOKE ALL ... FROM PUBLIC`. That doesn't work on Supabase, because new functions in `public` are granted to `anon` and `authenticated` by name, and revoking `PUBLIC` leaves those grants in place.
- **Three tables readable by anyone.** One was the user directory. Each one came from a permissive default nobody noticed: a `USING (true)` policy, or a new table still carrying Supabase's default grants to `anon`.
- **Definer functions granted to exactly the right role whose bodies touched any user's rows.** The grant was fine, but the function trusted a user id it was handed.

A one-off audit goes stale with the next migration. Run as a test, it stays true. This is that test, pulled out of the app so any Supabase project can use it.

## Quick start

You need Node 20+ and a database to point at. By default that's the local stack from `supabase start`.

```bash
# 1. Generate a config listing every table and callable definer function as `unreviewed`.
npx supabase-security-posture init

# 2. Classify each entry in supabase-security-posture.yaml (see below).

# 3. Check. Exits 1 on any error.
npx supabase-security-posture check
```

`init` deliberately classifies nothing. Each entry gets a comment saying what it *looks like* today, but a table anon can read through `USING (true)` "looks like" public reference data, and copying that into the config would sign off on the leak. While you work through a large schema, `check --allow-unreviewed` reports unclassified entries as warnings. Real problems, like RLS being off or a function granted to `PUBLIC`, still fail.

## What it checks

| Rule | Fails when |
|---|---|
| `rls-enabled` | A table has row level security off. |
| `tables-classified` | A table isn't in the config, or is still `unreviewed`. |
| `anon-privileges` | anon holds a privilege the table's kind doesn't allow, or lost one it needs. Column grants count. |
| `internal-closed` | An `internal` table has any policy, or any client role holds any privilege on it. |
| `no-permissive-writes` | An INSERT/UPDATE/DELETE/ALL policy is `USING (true)` or `WITH CHECK (true)`. |
| `no-public-policies` | A policy has no `TO`, so it applies to every role, including ones you add later. |
| `open-select-declared` | A SELECT policy is `USING (true)` on a table not declared `openSelect`. |
| `views-closed` | A view, materialized view or foreign table is client-readable and not listed, or it runs as its owner (no `security_invoker`), which bypasses RLS. |
| `definers-classified` | A `SECURITY DEFINER` function any client role can call isn't classified by how it scopes its caller. |
| `definer-anon-pre-login` | anon can call a definer function that isn't classified `pre-login`. |
| `definer-not-public` | A definer function is granted to `PUBLIC`. |
| `definer-search-path` | A client-callable definer function doesn't pin `search_path`. |
| `role-privileges` | An extra client role (e.g. `guest`) holds table privileges beyond the role it inherits that its list doesn't name. |
| `role-functions` | The same, for functions. |
| `open-issue-format` | An `openIssue` doesn't match `issuePattern`. |
| `no-stale-entries` | A config entry names something that no longer exists, so the list would quietly stop being true. |

Each finding comes with the SQL to fix it where there's one obvious fix. `npx supabase-security-posture rules` lists the rules.

## The config

```yaml
# supabase-security-posture.yaml
schemas: [public]          # the schemas PostgREST exposes
issuePattern: '^SEC-\d+$'  # optional: the shape of an openIssue id

tables:
  profiles: scoped                         # shorthand: just the kind
  countries: public-read
  audit_log: internal
  error_logs:
    kind: anon-insert
    reason: Pre-sign-in error reports. The policy admits only a null user_id.
  feature_flags:
    kind: custom
    anon: [select]
    openSelect: false
    reason: Read before sign-in, filtered by policy.

functions:
  get_my_profile: { scope: self, reason: Returns the caller's own row }
  join_team_by_code:
    scope: membership
    reason: The code authorizes joining that one team, as auth.uid()
  delete_team:
    scope: membership
    reason: Owner only
    openIssue: SEC-12   # a known gap, listed on every run until fixed

views:
  public_leaderboard:
    reason: Aggregates only, no user ids
    bypassesRls: true   # runs as owner on purpose

roles:                  # extra client roles, e.g. set by a custom access-token hook
  guest:
    inherits: anon      # only privileges beyond anon's are checked
    tables:
      rooms: [select]
    functions:
      join_room: The guest's way in; held to the room's token

rules:                  # every rule is `error` unless you say otherwise
  definer-search-path: warn
```

Objects outside `public` are written schema-qualified (`api.items`).

### Table kinds

| Kind | anon may | `USING (true)` on SELECT |
|---|---|---|
| `internal` | nothing, and neither may any client role; no policies | no |
| `scoped` | nothing | no |
| `signed-in-read` | nothing | yes |
| `public-read` | SELECT only | yes |
| `anon-insert` | INSERT only | no |
| `custom` | what you list in `anon:` | what you set in `openSelect:` |

Any kind takes `anon:` and `openSelect:` to override its defaults.

### Function scopes

A `SECURITY DEFINER` body bypasses RLS, so the body is the only thing standing between a signed-in caller and every other user's rows. Every function a client can call gets a scope that says which rows it may touch:

| Scope | The body… |
|---|---|
| `self` | acts only on the caller's own rows (`auth.uid()`), and fails closed when that's NULL |
| `membership` | requires the caller to belong to the team/group/org it touches |
| `relationship` | requires a relationship (contact, follower, thread) with the other user |
| `staff` | checks a staff or admin flag on the caller before acting |
| `open` | touches only shared, non-personal data. Don't use it just to get the check passing |
| `policy-helper` | is a boolean used inside RLS policies, answering about `auth.uid()` |
| `pre-login` | is granted to anon on purpose, and returns the minimum |

Add your own with `scopes: [party]`.

## In CI

```yaml
# .github/workflows/security-posture.yml
name: Security posture
on: [push, pull_request]
jobs:
  posture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: supabase/setup-cli@v1
      - run: supabase db start   # just Postgres, with your migrations applied
      - run: npx supabase-security-posture check
```

On GitHub Actions the output switches to annotations automatically (`--format github`), so each finding shows on the run summary. `--format json` is there for anything else.

The tool only reads the system catalog, so you can also point it at a hosted project to check what's really deployed:

```bash
SUPABASE_DB_URL='postgresql://postgres.<ref>:<password>@<pooler-host>:5432/postgres' \
  npx supabase-security-posture check
```

## How it works

One query reads every table, view, policy and function in the configured schemas. Privileges come from `has_table_privilege`, `has_any_column_privilege` and `has_function_privilege`, never from parsing ACLs. Those functions resolve `PUBLIC`, role inheritance and default ACLs the way Postgres does at call time. Looking for `anon=X` in `proacl` reports a function reachable through `PUBLIC` as locked down, which is how the first version of the audit behind this tool missed 43 of them.

Objects owned by an extension (PostGIS's `spatial_ref_sys`, for instance) are skipped, because a migration can't change them.

## What it doesn't do

It checks the *shape* of your security model: grants, RLS flags, the policies that are always true, and whether every hole has been signed off. It doesn't read the logic of a policy like `owner = auth.uid()`, and it can't prove a function classified `self` really is. For that, pair each definer function with a test that calls it as a signed-in stranger and asserts nothing changed. The classification tells you which tests to write.

## Development

```bash
npm install
npm test                                   # unit tests; the database tests skip

docker run -d --rm -p 54399:5432 -e POSTGRES_PASSWORD=postgres postgres:17
POSTGRES_URL=postgresql://postgres:postgres@127.0.0.1:54399/postgres npm test
```

The database tests build a fresh database with Supabase's roles and default privileges, plant one of each mistake (`test/fixtures/leaky.sql`), and assert that each is found, that nothing else is, and that the check passes once they're fixed.

## License

MIT
