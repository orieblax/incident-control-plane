-- 0002_incident_events_statement_immutability.sql
-- Enforce statement-level immutability on incident_events so UPDATE/DELETE
-- fails loudly with SQLSTATE 42501 even when RLS filters zero rows.

create trigger trg_incident_events_immutable_stmt
    before update or delete on public.incident_events
    for each statement execute function public.prevent_incident_event_mutation();
