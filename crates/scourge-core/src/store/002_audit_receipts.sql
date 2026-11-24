-- Locate an object's most recent transition without scanning other objects.
CREATE INDEX audit_receipts ON audit_events (operation, subject, revision);
