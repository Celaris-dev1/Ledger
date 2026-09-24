-- Security review: the row triggers on `anchors` and `audit_events` reject UPDATE/DELETE, but
-- TRUNCATE is a statement-level operation that row triggers never see, so the app role could
-- still wipe either table in one statement. Match `records` and `anchor_receipts`.
DROP TRIGGER IF EXISTS anchors_no_truncate ON anchors;
CREATE TRIGGER anchors_no_truncate BEFORE TRUNCATE ON anchors
    FOR EACH STATEMENT EXECUTE FUNCTION ledger_reject_mutation();
DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION ledger_reject_mutation();
