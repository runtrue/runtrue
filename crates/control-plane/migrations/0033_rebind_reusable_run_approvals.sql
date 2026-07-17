-- Reusable privileged-execution approvals are selected using a stable
-- repository capability digest. The authorization attached to a run must,
-- however, carry the exact Capsule subject digest so the scheduler can prove
-- that the approved capability admitted this particular execution plan.
--
-- Schema 32 accidentally stored the capability digest in both places. Repair
-- those reusable rows in place; one-shot approvals were already exact-bound.
UPDATE run_approval_authorizations
SET subject_digest = (
    SELECT metadata.approval_subject_digest
    FROM runs
    JOIN capsule_api_metadata AS metadata
      ON metadata.capsule_id = runs.capsule_id
    WHERE runs.id = run_approval_authorizations.run_id
)
WHERE kind = 'privileged-execution'
  AND one_shot = 0
  AND EXISTS (
      SELECT 1
      FROM runs
      JOIN capsule_api_metadata AS metadata
        ON metadata.capsule_id = runs.capsule_id
      WHERE runs.id = run_approval_authorizations.run_id
        AND metadata.approval_subject_digest <> run_approval_authorizations.subject_digest
  );

PRAGMA user_version = 33;
