ALTER TABLE accounts
  ADD COLUMN guard_address char(42),
  ADD COLUMN module_address char(42),
  ADD COLUMN verified_at timestamptz;

-- Existing ACTIVE rows were created before the API checked the paired Safe guards.
-- Keep them non-executable until the on-chain verifier explicitly enrolls them.
UPDATE accounts SET status = 'PAUSED' WHERE status = 'ACTIVE';

ALTER TABLE accounts ADD CONSTRAINT accounts_active_requires_verified_enrollment
  CHECK (status <> 'ACTIVE' OR (guard_address IS NOT NULL AND module_address IS NOT NULL AND verified_at IS NOT NULL));
