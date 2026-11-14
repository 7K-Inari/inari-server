package catalog

import (
	"context"
	"errors"
	"fmt"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
	"github.com/jackc/pgx/v5"
)

type SourceReplacement struct {
	Kind             string
	Source           trustedsource.Source
	Fingerprint      string
	Items            []*types.CatalogItem
	Versions         []*types.CatalogItemVersion
	LastGoodIndexRef string
	IndexDigest      string
	Now              time.Time
}

// ReplaceSource atomically activates one complete source generation. The
// caller supplies the transaction; any error leaves the previous generation
// and every other source untouched.
func (s *Store) ReplaceSource(ctx context.Context, q db.Querier, replacement SourceReplacement) error {
	if replacement.Kind != "catalog" && replacement.Kind != "template" {
		return fmt.Errorf("catalog: invalid trusted source kind %q", replacement.Kind)
	}
	if replacement.Source.ID == "" || replacement.Fingerprint == "" {
		return errors.New("catalog: source ID and policy fingerprint are required")
	}
	previous := map[string]string{}
	rows, err := q.Query(ctx, `SELECT v.item_id, v.version, v.artifact_digest
		FROM catalog_item_versions v JOIN catalog_items i ON i.id = v.item_id
		WHERE i.source_id = $1 AND v.artifact_digest <> ''`, replacement.Source.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var itemID, version, digest string
		if err := rows.Scan(&itemID, &version, &digest); err != nil {
			rows.Close()
			return err
		}
		previous[itemID+"@"+version] = digest
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, version := range replacement.Versions {
		if version == nil || version.ItemID == "" || version.Version == "" {
			return errors.New("catalog: snapshot contains an empty version")
		}
		if old := previous[version.ItemID+"@"+version.Version]; old != "" && version.ArtifactDigest != "" && old != version.ArtifactDigest {
			return fmt.Errorf("catalog: immutable artifact violation for %s: digest changed from %s to %s", version.ItemID+"@"+version.Version, old, version.ArtifactDigest)
		}
	}

	var generation int64
	err = q.QueryRow(ctx, `SELECT generation FROM trusted_source_states WHERE kind=$1 AND source_id=$2`, replacement.Kind, replacement.Source.ID).Scan(&generation)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	generation++
	if _, err := q.Exec(ctx, `UPDATE catalog_item_versions SET snapshot_present=false
		WHERE item_id IN (SELECT id FROM catalog_items WHERE source_id=$1)`, replacement.Source.ID); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE catalog_items SET snapshot_present=false WHERE source_id=$1`, replacement.Source.ID); err != nil {
		return err
	}
	for _, item := range replacement.Items {
		if item == nil {
			return errors.New("catalog: snapshot contains a nil item")
		}
		item.SourceID = replacement.Source.ID
		item.TrustTier = string(replacement.Source.TrustTier)
		item.Unsigned = replacement.Source.AllowUnsigned != ""
		item.SourceFingerprint = replacement.Fingerprint
		item.SourceGeneration = generation
		item.SnapshotPresent = true
		if err := s.UpsertItem(ctx, q, item); err != nil {
			return err
		}
	}
	for _, version := range replacement.Versions {
		version.SnapshotPresent = true
		if err := s.UpsertVersion(ctx, q, version); err != nil {
			return err
		}
	}
	now := replacement.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err = q.Exec(ctx, `INSERT INTO trusted_source_states
		(kind, source_id, fingerprint, state, generation, item_count, last_attempt_at, last_success_at, last_good_index_ref, last_good_index_digest, last_error_code, last_error, updated_at)
		VALUES ($1,$2,$3,'ready',$4,$5,$6,$6,$7,$8,'','',$6)
		ON CONFLICT (kind, source_id) DO UPDATE SET
		  fingerprint=EXCLUDED.fingerprint, state='ready', generation=EXCLUDED.generation,
		  item_count=EXCLUDED.item_count, last_attempt_at=EXCLUDED.last_attempt_at,
		  last_success_at=EXCLUDED.last_success_at, last_good_index_ref=EXCLUDED.last_good_index_ref,
		  last_good_index_digest=EXCLUDED.last_good_index_digest, last_error_code='', last_error='', updated_at=EXCLUDED.updated_at`,
		replacement.Kind, replacement.Source.ID, replacement.Fingerprint, generation, len(replacement.Items), now, replacement.LastGoodIndexRef, replacement.IndexDigest)
	return err
}

func (s *Store) RecordSourceFailure(ctx context.Context, q db.Querier, kind string, source trustedsource.Source, fingerprint, code string, syncErr error, now time.Time) error {
	if kind != "catalog" && kind != "template" {
		return fmt.Errorf("catalog: invalid trusted source kind %q", kind)
	}
	if code == "" {
		code = "sync_failed"
	}
	message := "unknown sync failure"
	if syncErr != nil {
		message = syncErr.Error()
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	now = now.UTC()
	_, err := q.Exec(ctx, `INSERT INTO trusted_source_states
		(kind, source_id, fingerprint, state, generation, item_count, last_attempt_at, last_error_code, last_error, updated_at)
		VALUES ($1,$2,$3,'failed',0,0,$4,$5,$6,$4)
		ON CONFLICT (kind, source_id) DO UPDATE SET
		  fingerprint=EXCLUDED.fingerprint,
		  state=CASE WHEN trusted_source_states.last_success_at IS NULL THEN 'failed' ELSE 'stale' END,
		  last_attempt_at=EXCLUDED.last_attempt_at, last_error_code=EXCLUDED.last_error_code,
		  last_error=EXCLUDED.last_error, updated_at=EXCLUDED.updated_at`,
		kind, source.ID, fingerprint, now, code, message)
	return err
}

func (s *Store) ListTrustedSourceStates(ctx context.Context, q db.Querier, kind string, now time.Time) ([]types.TrustedSourceStatus, error) {
	where := ""
	args := []any{}
	if kind != "" {
		where = " WHERE kind = $1"
		args = append(args, kind)
	}
	rows, err := q.Query(ctx, `SELECT kind, source_id, fingerprint, state, generation, item_count,
		last_attempt_at, last_success_at, last_good_index_ref, last_good_index_digest, last_error_code, last_error
		FROM trusted_source_states`+where+` ORDER BY source_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.TrustedSourceStatus
	for rows.Next() {
		var status types.TrustedSourceStatus
		if err := rows.Scan(&status.Kind, &status.SourceID, &status.Fingerprint, &status.State, &status.Generation, &status.ItemCount,
			&status.LastAttemptAt, &status.LastSuccessAt, &status.LastGoodIndexRef, &status.LastGoodIndexDigest, &status.LastErrorCode, &status.LastError); err != nil {
			return nil, err
		}
		if status.LastSuccessAt != nil {
			age := int64(now.Sub(status.LastSuccessAt.UTC()).Seconds())
			if age < 0 {
				age = 0
			}
			status.SnapshotAgeSeconds = age
		}
		out = append(out, status)
	}
	return out, rows.Err()
}

// ReconcileSourcePolicies disables snapshots whose configured source was
// removed or whose trust binding changed. A valid later sync is required to
// reactivate content; re-adding an ID alone never restores it.
func (s *Store) ReconcileSourcePolicies(ctx context.Context, q db.Querier, kind string, expected map[string]string) error {
	if kind != "catalog" && kind != "template" {
		return fmt.Errorf("catalog: invalid trusted source kind %q", kind)
	}
	rows, err := q.Query(ctx, `SELECT source_id, fingerprint FROM trusted_source_states WHERE kind=$1`, kind)
	if err != nil {
		return err
	}
	existing := map[string]string{}
	for rows.Next() {
		var id, fingerprint string
		if err := rows.Scan(&id, &fingerprint); err != nil {
			rows.Close()
			return err
		}
		existing[id] = fingerprint
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for id, fingerprint := range existing {
		expectedFingerprint, configured := expected[id]
		switch {
		case !configured:
			if _, err := q.Exec(ctx, `UPDATE trusted_source_states SET state='unconfigured', updated_at=now() WHERE kind=$1 AND source_id=$2`, kind, id); err != nil {
				return err
			}
			if err := s.tombstoneSource(ctx, q, id); err != nil {
				return err
			}
		case fingerprint != expectedFingerprint:
			if _, err := q.Exec(ctx, `UPDATE trusted_source_states SET state='policy-changed', fingerprint=$3, updated_at=now() WHERE kind=$1 AND source_id=$2`, kind, id, expectedFingerprint); err != nil {
				return err
			}
			if err := s.tombstoneSource(ctx, q, id); err != nil {
				return err
			}
		}
	}
	for id, fingerprint := range expected {
		if _, found := existing[id]; found {
			continue
		}
		if _, err := q.Exec(ctx, `INSERT INTO trusted_source_states (kind, source_id, fingerprint, state)
			VALUES ($1,$2,$3,'never-synced') ON CONFLICT (kind, source_id) DO NOTHING`, kind, id, fingerprint); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) tombstoneSource(ctx context.Context, q db.Querier, sourceID string) error {
	if _, err := q.Exec(ctx, `UPDATE catalog_item_versions SET snapshot_present=false WHERE item_id IN (SELECT id FROM catalog_items WHERE source_id=$1)`, sourceID); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE catalog_items SET snapshot_present=false WHERE source_id=$1`, sourceID)
	return err
}
