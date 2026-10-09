module github.com/7K-Inari/inari-server

go 1.26.3

require (
	connectrpc.com/connect v1.21.0
	github.com/7K-Inari/inari-api v0.6.1-0.20261009102856-23396effdec3
	github.com/aws/aws-sdk-go-v2 v1.47.2
	github.com/aws/aws-sdk-go-v2/config v1.33.8
	github.com/aws/aws-sdk-go-v2/credentials v1.20.8
	github.com/aws/aws-sdk-go-v2/service/iam v1.64.3
	github.com/aws/aws-sdk-go-v2/service/organizations v1.61.2
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.3
	github.com/blang/semver v3.5.1+incompatible
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/danielgtaylor/huma/v2 v2.39.1
	github.com/go-chi/chi/v5 v5.3.2
	github.com/go-git/go-git/v5 v5.19.3
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/go-containerregistry v0.22.1
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.11.0
	github.com/nats-io/nats-server/v2 v2.15.1
	github.com/nats-io/nats.go v1.54.0
	github.com/open-feature/go-sdk v1.19.0
	github.com/open-feature/go-sdk-contrib/providers/ofrep v0.1.7
	github.com/open-policy-agent/opa v1.21.1
	github.com/openfga/go-sdk v0.8.3
	github.com/pressly/goose/v3 v3.28.0
	github.com/prometheus/client_golang v1.25.0
	github.com/redis/go-redis/v9 v9.23.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	github.com/sigstore/cosign/v2 v2.6.5
	github.com/testcontainers/testcontainers-go v0.44.0
	github.com/testcontainers/testcontainers-go/modules/postgres v0.44.0
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/exporters/prometheus v0.69.0
	go.opentelemetry.io/otel/metric v1.47.0
	go.opentelemetry.io/otel/sdk/metric v1.47.0
	golang.org/x/net v0.60.0
	golang.org/x/sync v0.23.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
	sigs.k8s.io/yaml v1.6.0
)

require (
	dario.cat/mergo v1.0.2 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.6 // indirect
	github.com/agnivade/levenshtein v1.2.1 // indirect
	github.com/antithesishq/antithesis-sdk-go v0.8.0-default-no-op // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.53.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.3 // indirect
	github.com/aws/smithy-go v1.28.4 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/cpuguy83/dockercfg v0.3.2 // indirect
	github.com/cyberphone/json-canonicalization v0.0.0-20241213102144-19d51d7fe467 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20230818184609-3a137a874352 // indirect
	github.com/digitorus/timestamp v0.0.0-20231217203849-220c5c2851b7 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v29.7.2+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.5 // indirect
	github.com/docker/go-connections v0.8.1 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ebitengine/purego v0.10.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/analysis v0.25.5 // indirect
	github.com/go-openapi/errors v0.22.8 // indirect
	github.com/go-openapi/jsonpointer v1.0.0 // indirect
	github.com/go-openapi/jsonreference v1.0.0 // indirect
	github.com/go-openapi/loads v0.25.0 // indirect
	github.com/go-openapi/runtime v0.33.0 // indirect
	github.com/go-openapi/runtime/server-middleware v0.30.0 // indirect
	github.com/go-openapi/spec v0.22.9 // indirect
	github.com/go-openapi/strfmt v0.27.0 // indirect
	github.com/go-openapi/swag v0.28.0 // indirect
	github.com/go-openapi/swag/cmdutils v0.28.0 // indirect
	github.com/go-openapi/swag/conv v0.28.0 // indirect
	github.com/go-openapi/swag/fileutils v0.28.0 // indirect
	github.com/go-openapi/swag/jsonutils v0.28.0 // indirect
	github.com/go-openapi/swag/loading v0.28.0 // indirect
	github.com/go-openapi/swag/mangling v0.28.0 // indirect
	github.com/go-openapi/swag/netutils v0.28.0 // indirect
	github.com/go-openapi/swag/pools v0.28.0 // indirect
	github.com/go-openapi/swag/stringutils v0.28.0 // indirect
	github.com/go-openapi/swag/typeutils v0.28.0 // indirect
	github.com/go-openapi/swag/yamlutils v0.28.0 // indirect
	github.com/go-openapi/validate v0.26.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/gobwas/glob v1.0.0 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/certificate-transparency-go v1.3.3 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/in-toto/attestation v1.2.0 // indirect
	github.com/in-toto/in-toto-golang v0.11.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jedisct1/go-minisign v0.0.0-20230811132847-661be99b8267 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/jwx/v3 v3.3.0 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/letsencrypt/boulder v0.20260309.0 // indirect
	github.com/lib/pq v1.12.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20260330125221-c963978e514e // indirect
	github.com/magiconair/properties v1.8.10 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/go-archive v0.2.0 // indirect
	github.com/moby/moby/api v1.55.0 // indirect
	github.com/moby/moby/client v0.5.1 // indirect
	github.com/moby/patternmatcher v0.6.1 // indirect
	github.com/moby/sys/sequential v0.7.0 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nats-io/jwt/v2 v2.8.2 // indirect
	github.com/nats-io/nkeys v0.4.16 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/nozzle/throttler v0.0.0-20180817012639-2ea982251481 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pjbgf/sha1cd v0.7.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/otlptranslator v1.0.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9 // indirect
	github.com/sassoftware/relic v7.2.1+incompatible // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.11.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/sethvargo/go-retry v0.4.0 // indirect
	github.com/shibumi/go-pathspec v1.3.0 // indirect
	github.com/shirou/gopsutil/v4 v4.26.6 // indirect
	github.com/sigstore/protobuf-specs v0.5.1 // indirect
	github.com/sigstore/rekor v1.5.3 // indirect
	github.com/sigstore/rekor-tiles/v2 v2.3.0 // indirect
	github.com/sigstore/sigstore v1.10.8 // indirect
	github.com/sigstore/sigstore-go v1.2.2 // indirect
	github.com/sigstore/timestamp-authority/v2 v2.1.2 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20220721030215-126854af5e6d // indirect
	github.com/tchap/go-patricia/v2 v2.3.3 // indirect
	github.com/theupdateframework/go-tuf v0.7.0 // indirect
	github.com/theupdateframework/go-tuf/v2 v2.4.2 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/transparency-dev/formats v0.1.1 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	github.com/vektah/gqlparser/v2 v2.5.37 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.71.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/sdk v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.step.sm/crypto v0.81.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	google.golang.org/api v0.284.0 // indirect
	google.golang.org/genproto v0.0.0-20260406210006-6f92a3bedf2d // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260831171406-18b4a7587f8a // indirect
	google.golang.org/grpc v1.84.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
)

replace github.com/go-openapi/testify/v2 => github.com/go-openapi/testify/v2 v2.8.0
