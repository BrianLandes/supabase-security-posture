-- A small schema with one of each mistake the rules exist to catch, on a
-- database set up the way a fresh Supabase project is.

-- ── Supabase's roles and defaults ──────────────────────────────────────────
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN CREATE ROLE service_role NOLOGIN BYPASSRLS; END IF;
  -- A custom client role, as a custom access-token hook would set.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'guest') THEN CREATE ROLE guest NOLOGIN; END IF;
END $$;
GRANT anon TO guest;
GRANT USAGE ON SCHEMA public TO anon, authenticated, guest;

-- The trap: every new table and function in public is granted to anon and
-- authenticated, so RLS is all that stands between a table and the internet.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO anon, authenticated, service_role;

CREATE SCHEMA IF NOT EXISTS auth;
CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
  AS $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
GRANT USAGE ON SCHEMA auth TO anon, authenticated, guest;

-- ── Tables ─────────────────────────────────────────────────────────────────

-- Scoped by policy, but still carrying the default anon grants.
CREATE TABLE public.notes (id int PRIMARY KEY, owner uuid NOT NULL, body text);
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_own ON public.notes FOR SELECT TO authenticated USING (owner = auth.uid());

-- Public reference data, done right.
CREATE TABLE public.countries (code text PRIMARY KEY);
ALTER TABLE public.countries ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.countries FROM anon, authenticated;
GRANT SELECT ON public.countries TO anon, authenticated;
CREATE POLICY countries_read ON public.countries FOR SELECT TO anon, authenticated USING (true);

-- Meant to be internal, but RLS was never turned on.
CREATE TABLE public.api_keys (id int PRIMARY KEY, secret text);

-- Internal, done right.
CREATE TABLE public.audit_log (id int PRIMARY KEY, event text);
ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.audit_log FROM anon, authenticated;

-- Writable by anyone signed in, and a policy with no TO clause.
CREATE TABLE public.comments (id int PRIMARY KEY, author uuid, body text);
ALTER TABLE public.comments ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.comments FROM anon;
CREATE POLICY comments_insert ON public.comments FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY comments_read ON public.comments FOR SELECT USING (true);

-- Nobody has classified this one yet.
CREATE TABLE public.drafts (id int PRIMARY KEY, owner uuid);
ALTER TABLE public.drafts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.drafts FROM anon;
CREATE POLICY drafts_own ON public.drafts FOR ALL TO authenticated USING (owner = auth.uid());

-- What the guest role may touch.
CREATE TABLE public.rooms (id int PRIMARY KEY);
ALTER TABLE public.rooms ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.rooms FROM anon;
GRANT SELECT, UPDATE ON public.rooms TO guest;
CREATE POLICY rooms_read ON public.rooms FOR SELECT TO authenticated, guest USING (id > 0);

-- ── Views ──────────────────────────────────────────────────────────────────

-- Readable by clients through the default grants, and it runs as its owner.
CREATE VIEW public.note_counts AS SELECT owner, count(*) AS n FROM public.notes GROUP BY owner;

-- ── SECURITY DEFINER functions ─────────────────────────────────────────────

-- Correct: pinned search_path, granted to authenticated only.
CREATE FUNCTION public.my_notes() RETURNS SETOF public.notes
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
  AS $$ SELECT * FROM public.notes WHERE owner = auth.uid() $$;
REVOKE ALL ON FUNCTION public.my_notes() FROM public, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.my_notes() TO authenticated;

-- The classic shape: "locked down" with REVOKE FROM PUBLIC, which leaves the
-- default grant to anon in place.
CREATE FUNCTION public.whoami() RETURNS uuid
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
  AS $$ SELECT auth.uid() $$;
REVOKE ALL ON FUNCTION public.whoami() FROM PUBLIC;

-- Takes the caller's identity as a parameter, pins no search_path, and keeps
-- Postgres's default grant to PUBLIC. Never classified.
CREATE FUNCTION public.notes_for(p_owner uuid) RETURNS SETOF public.notes
  LANGUAGE sql STABLE SECURITY DEFINER
  AS $$ SELECT * FROM notes WHERE owner = p_owner $$;

-- Guest-only, and on the guest's list.
CREATE FUNCTION public.join_room(p_room int) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = ''
  AS $$ SELECT $$;
REVOKE ALL ON FUNCTION public.join_room(int) FROM public, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.join_room(int) TO guest;
