module github.com/safedep/vet/v2

go 1.26.3

require (
	buf.build/gen/go/safedep/api/grpc/go v1.6.2-20261001145028-14c0defb961c.1
	buf.build/gen/go/safedep/api/protocolbuffers/go v1.36.12-20261001145028-14c0defb961c.2
	github.com/BurntSushi/toml v1.6.0
	github.com/CycloneDX/cyclonedx-go v0.11.0
	github.com/charmbracelet/x/ansi v0.11.7
	github.com/github/go-spdx/v2 v2.4.0
	github.com/go-git/go-git/v5 v5.19.2
	github.com/google/cel-go v0.28.0
	github.com/google/go-cmp v0.7.0
	github.com/google/go-containerregistry v0.21.2
	github.com/google/go-github/v70 v70.0.0
	github.com/google/osv-scalibr v0.5.3
	github.com/google/uuid v1.6.0
	github.com/hashicorp/hcl/v2 v2.24.0
	github.com/invopop/jsonschema v0.13.0
	github.com/moby/moby/client v0.5.0
	github.com/package-url/packageurl-go v0.1.5
	github.com/posthog/posthog-go v1.10.0
	github.com/rogpeppe/go-internal v1.16.0
	github.com/safedep/code v0.0.0-20261003074956-ca03c078c5bb
	github.com/safedep/dry v0.0.0-20261002073351-d0ae33065533
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/stretchr/testify v1.11.1
	github.com/tidwall/gjson v1.19.0
	github.com/tidwall/jsonc v0.3.3
	github.com/wk8/go-ordered-map/v2 v2.1.8
	github.com/zclconf/go-cty v1.18.0
	golang.org/x/mod v0.38.0
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	al.essio.dev/pkg/shellescape v1.5.1 // indirect
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260415201107-50325440f8f2.1 // indirect
	buf.build/go/protovalidate v1.2.0 // indirect
	cel.dev/expr v0.25.2 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	dario.cat/mergo v1.0.2 // indirect
	deps.dev/api/v3 v3.0.0-20260422013440-90c27f84dd6f // indirect
	deps.dev/util/maven v0.0.0-20260528042559-b92437de09fd // indirect
	deps.dev/util/resolve v0.0.0-20260422013440-90c27f84dd6f // indirect
	deps.dev/util/semver v0.0.0-20260529052642-cf1e78d92744 // indirect
	github.com/MakeNowJust/heredoc v1.0.0 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.3.0 // indirect
	github.com/a-h/parse v0.0.0-20250122154542-74294addb73e // indirect
	github.com/a-h/templ v0.3.1001 // indirect
	github.com/aead/serpent v0.0.0-20160714141033-fba169763ea6 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/alecthomas/repr v0.5.2 // indirect
	github.com/alessio/shellescape v1.4.1 // indirect
	github.com/anchore/go-lzo v0.1.0 // indirect
	github.com/anchore/go-struct-converter v0.1.0 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/aymanbagabas/go-udiff v0.3.1 // indirect
	github.com/ayoubfaouzi/pkcs7 v0.2.3 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/bazelbuild/buildtools v0.0.0-20260319080235-05d2ebe49b0f // indirect
	github.com/briandowns/spinner v1.23.2 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/caarlos0/env/v11 v11.3.1 // indirect
	github.com/canonical/chisel-manifest v1.2.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/lipgloss v1.1.1-0.20250404203927-76690c660834 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/exp/golden v0.0.0-20241011142426-46044092ad91 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/cli/browser v1.3.0 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/compose-spec/compose-go/v2 v2.10.2 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.18.2 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/deitch/magic v0.0.0-20240306090643-c67ab88f10cb // indirect
	github.com/diskfs/go-diskfs v1.7.0 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/djherbis/times v1.6.0 // indirect
	github.com/dlclark/regexp2 v1.11.5 // indirect
	github.com/docker/cli v29.2.1+incompatible // indirect
	github.com/docker/distribution v2.8.3+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.5 // indirect
	github.com/docker/go-connections v0.7.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dsoprea/go-exfat v0.0.0-20190906070738-5e932fbdb589 // indirect
	github.com/dsoprea/go-logging v0.0.0-20200710184922-b02d349568dd // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/edsrzf/mmap-go v1.2.0 // indirect
	github.com/elliotwutingfeng/asciiset v0.0.0-20260129054604-cfde2086bc57 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/erikvarga/go-rpmdb v0.0.0-20250523120114-a15a62cd4593 // indirect
	github.com/evilmartians/lefthook v1.13.6 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20250910080747-cc2cfa0554c3 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.28.0 // indirect
	github.com/go-restruct/restruct v1.2.0-alpha // indirect
	github.com/go-test/deep v1.1.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-github/v74 v74.0.0 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/pprof v0.0.0-20260302011040-a15ffb7f9dcc // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/icholy/digest v1.1.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jedib0t/go-pretty/v6 v6.7.9 // indirect
	github.com/kaptinlin/go-i18n v0.1.7 // indirect
	github.com/kaptinlin/jsonschema v0.4.14 // indirect
	github.com/kaptinlin/messageformat-go v0.4.0 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/knadh/koanf/maps v0.1.2 // indirect
	github.com/knadh/koanf/parsers/json v1.0.0 // indirect
	github.com/knadh/koanf/parsers/toml/v2 v2.2.0 // indirect
	github.com/knadh/koanf/parsers/yaml v1.1.0 // indirect
	github.com/knadh/koanf/providers/fs v1.0.0 // indirect
	github.com/knadh/koanf/v2 v2.3.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.0 // indirect
	github.com/lunixbochs/struc v0.0.0-20241101090106-8d528fa2c543 // indirect
	github.com/mailru/easyjson v0.9.1 // indirect
	github.com/masahiro331/go-ext4-filesystem v0.0.0-20260423010602-fe51f5b5e52b // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/mattn/go-runewidth v0.0.23 // indirect
	github.com/mattn/go-shellwords v1.0.13 // indirect
	github.com/mattn/go-tty v0.0.7 // indirect
	github.com/micromdm/plist v0.2.2 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/buildkit v0.26.3 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/moby/api v1.55.0 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/natefinch/atomic v1.0.1 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/ossf/osv-schema/bindings/go v0.0.0-20260424063704-83285ce2a866 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/pjbgf/sha1cd v0.6.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/xattr v0.4.12 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rust-secure-code/go-rustaudit v0.0.0-20250226111315-e20ec32e963c // indirect
	github.com/saferwall/pe v1.6.4 // indirect
	github.com/schollz/progressbar/v3 v3.18.0 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82 // indirect
	github.com/spdx/gordf v0.0.0-20250128162952-000978ccd6fb // indirect
	github.com/spdx/tools-golang v0.5.7 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tink-crypto/tink-go/v2 v2.6.0 // indirect
	github.com/tonistiigi/go-csvvalue v0.0.0-20240814133006-030d3b2625d0 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/vbatts/tar-split v0.12.3 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/zalando/go-keyring v0.2.6 // indirect
	go.etcd.io/bbolt v1.4.3 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.68.0 // indirect
	go.opentelemetry.io/otel v1.45.0 // indirect
	go.opentelemetry.io/otel/metric v1.45.0 // indirect
	go.opentelemetry.io/otel/sdk v1.45.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.45.0 // indirect
	go.opentelemetry.io/otel/trace v1.45.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.4 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/exp v0.0.0-20260508232706-74f9aab9d74a // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	gopkg.in/ini.v1 v1.67.2 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.50.1 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
	www.velocidex.com/golang/go-ntfs v0.2.0 // indirect
)

tool (
	github.com/a-h/templ/cmd/templ
	github.com/evilmartians/lefthook
)
