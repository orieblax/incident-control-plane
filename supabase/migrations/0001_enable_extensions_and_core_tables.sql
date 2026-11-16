-- 0001_enable_extensions_and_core_tables.sql
-- Provision pgvector in extensions schema, core incident/runbook/postmortem/event tables,
-- HNSW + GIN indexes, append-only audit immutability, and strict RLS policies.

create extension if not exists vector with schema extensions;

grant usage on schema extensions to authenticated, service_role;

-- 1. Incidents (state machine + severity + JSONB telemetry)
create table if not exists public.incidents (
    id uuid primary key default gen_random_uuid(),
    title text not null,
    description text not null,
    status text not null default 'triggered'
        check (status in ('triggered', 'investigating', 'mitigated', 'resolved')),
    severity text not null
        check (severity in ('sev1', 'sev2', 'sev3', 'sev4')),
    service_name text not null,
    telemetry jsonb not null default '{}'::jsonb,
    owner_id uuid not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    resolved_at timestamptz
);

create index if not exists incidents_owner_id_idx
    on public.incidents (owner_id);
create index if not exists incidents_status_severity_created_idx
    on public.incidents (status, severity, created_at desc);
create index if not exists incidents_service_name_idx
    on public.incidents (service_name);
create index if not exists incidents_telemetry_gin_idx
    on public.incidents using gin (telemetry jsonb_path_ops);

-- 2. Runbooks (structured remediation steps + pgvector embeddings)
create table if not exists public.runbooks (
    id uuid primary key default gen_random_uuid(),
    slug text not null unique,
    title text not null,
    service_name text not null,
    symptom_summary text not null,
    steps jsonb not null default '[]'::jsonb,
    embedding extensions.vector(1536),
    is_shared boolean not null default false,
    owner_id uuid not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists runbooks_owner_id_idx
    on public.runbooks (owner_id);
create index if not exists runbooks_service_name_idx
    on public.runbooks (service_name);
create index if not exists runbooks_embedding_hnsw_idx
    on public.runbooks using hnsw (embedding extensions.vector_cosine_ops)
    with (m = 16, ef_construction = 64);

-- 3. Postmortems (historical root-cause & resolution embeddings)
create table if not exists public.postmortems (
    id uuid primary key default gen_random_uuid(),
    incident_id uuid references public.incidents (id) on delete set null,
    title text not null,
    service_name text not null,
    root_cause text not null,
    resolution_summary text not null,
    action_items jsonb not null default '[]'::jsonb,
    embedding extensions.vector(1536),
    is_shared boolean not null default false,
    owner_id uuid not null,
    published_at timestamptz not null default now()
);

create index if not exists postmortems_owner_id_idx
    on public.postmortems (owner_id);
create index if not exists postmortems_incident_id_idx
    on public.postmortems (incident_id);
create index if not exists postmortems_service_name_idx
    on public.postmortems (service_name);
create index if not exists postmortems_embedding_hnsw_idx
    on public.postmortems using hnsw (embedding extensions.vector_cosine_ops)
    with (m = 16, ef_construction = 64);

-- 4. Incident Events (immutable append-only audit log)
create table if not exists public.incident_events (
    id uuid primary key default gen_random_uuid(),
    incident_id uuid not null references public.incidents (id) on delete cascade,
    event_type text not null,
    from_status text,
    to_status text,
    actor_id uuid not null,
    actor_type text not null check (actor_type in ('human', 'mcp_agent', 'system')),
    payload jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create index if not exists incident_events_incident_created_idx
    on public.incident_events (incident_id, created_at desc);
create index if not exists incident_events_actor_id_idx
    on public.incident_events (actor_id);
create unique index if not exists incident_events_unique_approval_jti_idx
    on public.incident_events ((payload ->> 'token_jti'))
    where event_type = 'runbook_step_executed' and payload ? 'token_jti';

-- Trigger helpers with locked search_path
create or replace function public.set_updated_at()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

drop trigger if exists trg_incidents_updated_at on public.incidents;
create trigger trg_incidents_updated_at
    before update on public.incidents
    for each row execute function public.set_updated_at();

drop trigger if exists trg_runbooks_updated_at on public.runbooks;
create trigger trg_runbooks_updated_at
    before update on public.runbooks
    for each row execute function public.set_updated_at();

create or replace function public.prevent_incident_event_mutation()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
    raise exception 'incident_events is an append-only immutable audit log'
        using errcode = '42501';
end;
$$;

drop trigger if exists trg_incident_events_immutable on public.incident_events;
create trigger trg_incident_events_immutable
    before update or delete on public.incident_events
    for each row execute function public.prevent_incident_event_mutation();

-- Privileges & Row-Level Security
revoke all on public.incidents, public.runbooks, public.postmortems, public.incident_events from anon, public;
grant select, insert, update, delete on public.incidents, public.runbooks, public.postmortems to authenticated;
grant select, insert on public.incident_events to authenticated;

alter table public.incidents enable row level security;
alter table public.runbooks enable row level security;
alter table public.postmortems enable row level security;
alter table public.incident_events enable row level security;

-- Incidents RLS policies
create policy "incidents_select_own"
    on public.incidents for select
    to authenticated
    using ((select auth.uid()) = owner_id);

create policy "incidents_insert_own"
    on public.incidents for insert
    to authenticated
    with check ((select auth.uid()) = owner_id);

create policy "incidents_update_own"
    on public.incidents for update
    to authenticated
    using ((select auth.uid()) = owner_id)
    with check ((select auth.uid()) = owner_id);

create policy "incidents_delete_own"
    on public.incidents for delete
    to authenticated
    using ((select auth.uid()) = owner_id);

-- Runbooks RLS policies
create policy "runbooks_select_own_or_shared"
    on public.runbooks for select
    to authenticated
    using ((select auth.uid()) = owner_id or is_shared = true);

create policy "runbooks_insert_own"
    on public.runbooks for insert
    to authenticated
    with check ((select auth.uid()) = owner_id);

create policy "runbooks_update_own"
    on public.runbooks for update
    to authenticated
    using ((select auth.uid()) = owner_id)
    with check ((select auth.uid()) = owner_id);

create policy "runbooks_delete_own"
    on public.runbooks for delete
    to authenticated
    using ((select auth.uid()) = owner_id);

-- Postmortems RLS policies
create policy "postmortems_select_own_or_shared"
    on public.postmortems for select
    to authenticated
    using ((select auth.uid()) = owner_id or is_shared = true);

create policy "postmortems_insert_own"
    on public.postmortems for insert
    to authenticated
    with check ((select auth.uid()) = owner_id);

create policy "postmortems_update_own"
    on public.postmortems for update
    to authenticated
    using ((select auth.uid()) = owner_id)
    with check ((select auth.uid()) = owner_id);

create policy "postmortems_delete_own"
    on public.postmortems for delete
    to authenticated
    using ((select auth.uid()) = owner_id);

-- Incident Events RLS policies (append-only, scoped to incident owner)
create policy "incident_events_select_owner"
    on public.incident_events for select
    to authenticated
    using (
        exists (
            select 1 from public.incidents i
            where i.id = incident_id
              and i.owner_id = (select auth.uid())
        )
    );

create policy "incident_events_insert_owner"
    on public.incident_events for insert
    to authenticated
    with check (
        exists (
            select 1 from public.incidents i
            where i.id = incident_id
              and i.owner_id = (select auth.uid())
        )
    );
