// Package testutil provides sync.Once-guarded shared testcontainers helpers
// (Postgres, Redis, NATS, OpenFGA) for integration tests. A TestMain in each
// integration test package pre-warms the containers it needs and terminates
// them after m.Run() via TerminateShared; per-test skip behavior stays with
// the existing t.Skipf("testcontainers unavailable: ...") pattern.
package testutil

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	pgOnce      sync.Once
	pgShared    *SharedPG
	pgErr       error
	redisOnce   sync.Once
	redisCtr    testcontainers.Container
	redisAddr   string
	redisErr    error
	natsOnce    sync.Once
	natsSrv     *server.Server
	natsURL     string
	natsErr     error
	fgaOnce     sync.Once
	fgaCtr      testcontainers.Container
	fgaEndpoint string
	fgaErr      error
)

// SharedPostgres is the process-wide shared Postgres container.
type SharedPG struct {
	adminDSN string
}

// SharedPostgres starts (once per test binary) a shared Postgres container
// and returns it. Subsequent calls return the same instance.
func SharedPostgres(ctx context.Context) (*SharedPG, error) {
	pgOnce.Do(func() {
		pg, err := postgres.Run(ctx, "postgres:16-alpine",
			postgres.WithDatabase("inari"),
			postgres.WithUsername("inari"),
			postgres.WithPassword("inari"),
			testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
		)
		if err != nil {
			pgErr = err
			return
		}
		base, err := pg.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			pgErr = err
			_ = pg.Terminate(ctx)
			return
		}
		keepPgContainer = pg
		pgShared = &SharedPG{adminDSN: base}
	})
	return pgShared, pgErr
}

// keepPgContainer retains the container handle for TerminateShared (the
// exported surface only exposes the DSN-bearing SharedPostgres).
var keepPgContainer *postgres.PostgresContainer

// AdminDSN returns a connection string for the container's maintenance
// database ("inari").
func (s *SharedPG) AdminDSN() string { return s.adminDSN }

// DSN returns a connection string for the given database name inside the
// shared container.
func (s *SharedPG) DSN(dbName string) string {
	u, err := url.Parse(s.adminDSN)
	if err != nil {
		// Unreachable: the DSN comes from a started container.
		panic(err)
	}
	u.Path = "/" + dbName
	return u.String()
}

// CreateDatabase creates a fresh empty database on the shared container and
// returns its connection string. Test binaries that need a migrated *db.DB
// should use internal/testutil/testdb.NewDatabase instead.
func (s *SharedPG) CreateDatabase(ctx context.Context, name string) (string, error) {
	admin, err := pgx.Connect(ctx, s.adminDSN)
	if err != nil {
		return "", err
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s TEMPLATE template0", quoteIdent(name))); err != nil {
		return "", err
	}
	return s.DSN(name), nil
}

func quoteIdent(name string) string {
	out := make([]byte, 0, len(name)+2)
	out = append(out, '"')
	for i := 0; i < len(name); i++ {
		if name[i] == '"' {
			out = append(out, '"')
		}
		out = append(out, name[i])
	}
	out = append(out, '"')
	return string(out)
}

// SharedRedis starts (once per test binary) a shared redis:7-alpine
// container and returns its "host:port" address.
func SharedRedis(ctx context.Context) (string, error) {
	redisOnce.Do(func() {
		ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "redis:7-alpine",
				ExposedPorts: []string{"6379/tcp"},
				WaitingFor:   wait.ForLog("Ready to accept connections"),
			},
			Started: true,
		})
		if err != nil {
			redisErr = err
			return
		}
		endpoint, err := ctr.Endpoint(ctx, "")
		if err != nil {
			redisErr = err
			_ = ctr.Terminate(ctx)
			return
		}
		redisCtr = ctr
		redisAddr = endpoint
	})
	return redisAddr, redisErr
}

// KillSharedRedis terminates the shared Redis container. It exists for
// outage-simulation tests; TerminateShared tolerates an already-terminated
// container.
func KillSharedRedis(ctx context.Context) error {
	if redisCtr == nil {
		return errors.New("testutil: shared redis not started")
	}
	return redisCtr.Terminate(ctx)
}

// SharedNATS starts (once per test binary) an embedded nats-server with
// JetStream enabled (no Docker container) and returns its client URL.
func SharedNATS(ctx context.Context) (string, error) {
	natsOnce.Do(func() {
		dir, err := os.MkdirTemp("", "inari-testutil-nats-*")
		if err != nil {
			natsErr = err
			return
		}
		s, err := server.NewServer(&server.Options{
			JetStream: true,
			StoreDir:  dir,
			Host:      "127.0.0.1",
			Port:      -1,
		})
		if err != nil {
			natsErr = err
			return
		}
		go s.Start()
		if !s.ReadyForConnections(5 * time.Second) {
			natsErr = errors.New("embedded nats-server did not become ready")
			s.Shutdown()
			return
		}
		natsSrv = s
		natsURL = s.ClientURL()
	})
	return natsURL, natsErr
}

// SharedOpenFGA starts (once per test binary) a shared openfga/openfga
// container and returns its "host:port" API endpoint.
func SharedOpenFGA(ctx context.Context) (string, error) {
	fgaOnce.Do(func() {
		ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "openfga/openfga:latest",
				Cmd:          []string{"run"},
				ExposedPorts: []string{"8080/tcp"},
				WaitingFor:   wait.ForHTTP("/healthz").WithPort("8080/tcp"),
			},
			Started: true,
		})
		if err != nil {
			fgaErr = err
			return
		}
		endpoint, err := ctr.Endpoint(ctx, "")
		if err != nil {
			fgaErr = err
			_ = ctr.Terminate(ctx)
			return
		}
		fgaCtr = ctr
		fgaEndpoint = endpoint
	})
	return fgaEndpoint, fgaErr
}

// TerminateShared tears down every shared container/server that was started.
// It is idempotent and safe to call when nothing was started.
func TerminateShared(ctx context.Context) error {
	var firstErr error
	if keepPgContainer != nil {
		if err := keepPgContainer.Terminate(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		keepPgContainer = nil
	}
	if redisCtr != nil {
		if err := redisCtr.Terminate(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		redisCtr = nil
	}
	if fgaCtr != nil {
		if err := fgaCtr.Terminate(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		fgaCtr = nil
	}
	if natsSrv != nil {
		natsSrv.Shutdown()
		natsSrv = nil
	}
	return firstErr
}
