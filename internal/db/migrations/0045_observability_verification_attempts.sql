-- +goose Up
-- A retry is distinct evidence and must be able to replace the prior attempt.
ALTER TABLE observability_verification_results DROP CONSTRAINT observability_verification_results_pkey;
ALTER TABLE observability_verification_results
    ADD PRIMARY KEY (companion_id, generation, run_id, attempt, suite_digest);
UPDATE observability_companions AS companion
SET latest_verification_id = concat(companion.generation, ':', result.run_id, ':', result.attempt, ':', result.suite_digest)
FROM observability_verification_results AS result
WHERE companion.id = result.companion_id
  AND companion.generation = result.generation
  AND companion.latest_verification_id = concat(companion.generation, ':', result.run_id, ':', result.suite_digest);

-- +goose Down
UPDATE observability_companions AS companion
SET latest_verification_id = concat(companion.generation, ':', result.run_id, ':', result.suite_digest)
FROM observability_verification_results AS result
WHERE companion.id = result.companion_id
  AND companion.generation = result.generation
  AND companion.latest_verification_id = concat(companion.generation, ':', result.run_id, ':', result.attempt, ':', result.suite_digest);
DELETE FROM observability_verification_results
WHERE ctid IN (
    SELECT ctid FROM (
        SELECT ctid,
               row_number() OVER (
                   PARTITION BY companion_id, generation, run_id, suite_digest
                   ORDER BY attempt DESC, received_at DESC
               ) AS position
        FROM observability_verification_results
    ) AS ranked
    WHERE position > 1
);
ALTER TABLE observability_verification_results DROP CONSTRAINT observability_verification_results_pkey;
ALTER TABLE observability_verification_results
    ADD PRIMARY KEY (companion_id, generation, run_id, suite_digest);
