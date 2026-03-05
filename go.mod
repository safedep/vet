module github.com/safedep/vet

go 1.26.0

require (
	buf.build/gen/go/safedep/api/grpc/go v1.6.1-20260225163230-1a8a369418c0.1
	buf.build/gen/go/safedep/api/protocolbuffers/go v1.36.11-20260225163230-1a8a369418c0.1
	entgo.io/ent v0.14.6-0.20260218064135-ab0540611e15
	github.com/AlecAivazis/survey/v2 v2.3.7
	github.com/BurntSushi/toml v1.6.0
	github.com/CycloneDX/cyclonedx-go v0.10.0
	github.com/a-h/templ v0.3.1001
	github.com/anchore/syft v1.40.0
	github.com/bmatcuk/doublestar/v4 v4.10.0
	github.com/cayleygraph/cayley v0.7.7-0.20240706181042-81dcd7d73e45
	github.com/cayleygraph/quad v1.3.0
	github.com/charmbracelet/bubbles v1.0.0
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/charmbracelet/colorprofile v0.4.2
	github.com/charmbracelet/glamour v0.10.0
	github.com/charmbracelet/lipgloss v1.1.1-0.20250404203927-76690c660834
	github.com/cli/oauth v1.2.2
	github.com/cloudwego/eino v0.7.37
	github.com/cloudwego/eino-ext/components/model/claude v0.1.15
	github.com/cloudwego/eino-ext/components/model/gemini v0.1.28
	github.com/cloudwego/eino-ext/components/model/openai v0.1.8
	github.com/cloudwego/eino-ext/components/tool/mcp v0.0.8
	github.com/deepmap/oapi-codegen v1.16.3
	github.com/docker/docker v28.5.2+incompatible
	github.com/fatih/color v1.18.0
	github.com/github/go-spdx/v2 v2.4.0
	github.com/go-resty/resty/v2 v2.17.2
	github.com/gofri/go-github-ratelimit v1.1.1
	github.com/gojek/heimdall v5.0.2+incompatible
	github.com/gojek/heimdall/v7 v7.1.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/golang/protobuf v1.5.4
	github.com/google/cel-go v0.27.0
	github.com/google/go-github/v70 v70.0.0
	github.com/google/osv-scalibr v0.4.4
	github.com/google/osv-scanner v1.9.2
	github.com/google/uuid v1.6.0
	github.com/hashicorp/hcl/v2 v2.24.0
	github.com/jedib0t/go-pretty/v6 v6.7.8
	github.com/kubescape/go-git-url v0.0.31
	github.com/mark3labs/mcp-go v0.44.1
	github.com/mattn/go-sqlite3 v1.14.34
	github.com/muesli/termenv v0.16.0
	github.com/oklog/ulid/v2 v2.1.1
	github.com/ossf/osv-schema/bindings/go v0.0.0-20260304051245-ec3272c283e4
	github.com/owenrumney/go-sarif/v2 v2.3.3
	github.com/package-url/packageurl-go v0.1.4
	github.com/pandatix/go-cvss v0.6.2
	github.com/pkg/errors v0.9.1
	github.com/posthog/posthog-go v1.10.0
	github.com/safedep/code v0.0.0-20260224174612-abe896956bc1
	github.com/safedep/dry v0.0.0-20260223065605-2df2a7f6d703
	github.com/sirupsen/logrus v1.9.4
	github.com/smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82
	github.com/spdx/tools-golang v0.5.7
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	golang.org/x/oauth2 v0.35.0
	golang.org/x/term v0.40.0
	google.golang.org/genai v1.48.0
	google.golang.org/grpc v1.79.1
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	ariga.io/atlas v1.1.0 // indirect
	bitbucket.org/creachadair/stringset v0.0.14 // indirect
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.11-20260209202127-80ab13bee0bf.1 // indirect
	buf.build/go/protovalidate v1.1.3 // indirect
	cel.dev/expr v0.25.1 // indirect
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.18.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.5.3 // indirect
	cloud.google.com/go/monitoring v1.24.3 // indirect
	cloud.google.com/go/storage v1.60.0 // indirect
	cyphar.com/go-pathrs v0.2.4 // indirect
	dario.cat/mergo v1.0.2 // indirect
	deps.dev/api/v3 v3.0.0-20260225225317-765e10b45d5b // indirect
	deps.dev/api/v3alpha v0.0.0-20260225225317-765e10b45d5b // indirect
	deps.dev/util/maven v0.0.0-20260225225317-765e10b45d5b // indirect
	deps.dev/util/pypi v0.0.0-20260225225317-765e10b45d5b // indirect
	deps.dev/util/resolve v0.0.0-20260225225317-765e10b45d5b // indirect
	deps.dev/util/semver v0.0.0-20260225225317-765e10b45d5b // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20250520111509-a70c2aa677fa // indirect
	github.com/CloudyKit/fastprinter v0.0.0-20251202014920-1725d2651bd4 // indirect
	github.com/CloudyKit/jet/v6 v6.3.1 // indirect
	github.com/DataDog/datadog-go v4.8.3+incompatible // indirect
	github.com/GehirnInc/crypt v0.0.0-20230320061759-8cc1b52080c5 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.31.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.55.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.55.0 // indirect
	github.com/Joker/jade v1.1.3 // indirect
	github.com/MakeNowJust/heredoc v1.0.0 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.14.0-rc.1 // indirect
	github.com/STARRY-S/zip v0.2.3 // indirect
	github.com/Shopify/goreferrer v0.0.0-20250617153402-88c1d9a79b05 // indirect
	github.com/a-h/parse v0.0.0-20250122154542-74294addb73e // indirect
	github.com/acobaugh/osrelease v0.1.0 // indirect
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/aead/serpent v0.0.0-20160714141033-fba169763ea6 // indirect
	github.com/afex/hystrix-go v0.0.0-20180502004556-fa1af6a1f4f5 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/alecthomas/chroma/v2 v2.23.1 // indirect
	github.com/alessio/shellescape v1.4.1 // indirect
	github.com/anchore/clio v0.0.0-20260302164412-3ffbbe8c23a9 // indirect
	github.com/anchore/fangs v0.0.0-20260302165001-7b3d34e1cfff // indirect
	github.com/anchore/go-homedir v0.0.0-20250319154043-c29668562e4d // indirect
	github.com/anchore/go-logger v0.0.0-20260217144723-3bb369b8046c // indirect
	github.com/anchore/go-lzo v0.1.0 // indirect
	github.com/anchore/go-macholibre v0.0.0-20260303191308-266b511890b2 // indirect
	github.com/anchore/go-struct-converter v0.1.0 // indirect
	github.com/anchore/go-sync v0.0.0-20260122203928-582959aeb913 // indirect
	github.com/anchore/packageurl-go v0.1.1-0.20250220190351-d62adb6e1115 // indirect
	github.com/anchore/stereoscope v0.1.17 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/anthropics/anthropic-sdk-go v1.26.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aws/aws-sdk-go-v2 v1.41.3 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.6 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.11 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.11 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.96.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.8 // indirect
	github.com/aws/smithy-go v1.24.2 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/ayoubfaouzi/pkcs7 v0.2.2 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/bazelbuild/buildtools v0.0.0-20260211083412-859bfffeef82 // indirect
	github.com/becheran/wildmatch-go v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d // indirect
	github.com/bmatcuk/doublestar v1.3.4 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/sevenzip v1.6.1 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/boltdb/bolt v1.3.1 // indirect
	github.com/briandowns/spinner v1.23.2 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/caarlos0/env/v11 v11.4.0 // indirect
	github.com/cactus/go-statsd-client/statsd v0.0.0-20200423205355-cb0885a1018c // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chainguard-dev/git-urls v1.0.2 // indirect
	github.com/charmbracelet/x/ansi v0.11.6 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/exp/slice v0.0.0-20260304084025-7dd5c0ab408e // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/cli/browser v1.3.0 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/cloudwego/eino-ext/libs/acl/openai v0.1.13 // indirect
	github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2 // indirect
	github.com/compose-spec/compose-go/v2 v2.10.1 // indirect
	github.com/containerd/cgroups/v3 v3.1.0 // indirect
	github.com/containerd/containerd v1.7.30 // indirect
	github.com/containerd/containerd/api v1.10.0 // indirect
	github.com/containerd/continuity v0.4.5 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.2 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.18.2 // indirect
	github.com/containerd/ttrpc v1.2.7 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/deitch/magic v0.0.0-20240306090643-c67ab88f10cb // indirect
	github.com/diskfs/go-diskfs v1.7.0 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/djherbis/times v1.6.0 // indirect
	github.com/dlclark/regexp2 v1.11.5 // indirect
	github.com/docker/cli v29.2.1+incompatible // indirect
	github.com/docker/distribution v2.8.3+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.5 // indirect
	github.com/docker/go-connections v0.6.0 // indirect
	github.com/docker/go-events v0.0.0-20250808211157-605354379745 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dop251/goja v0.0.0-20250114131315-46d383d606d3 // indirect
	github.com/dsnet/compress v0.0.2-0.20230904184137-39efe44ab707 // indirect
	github.com/dsoprea/go-exfat v0.0.0-20190906070738-5e932fbdb589 // indirect
	github.com/dsoprea/go-logging v0.0.0-20200710184922-b02d349568dd // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/edsrzf/mmap-go v1.2.0 // indirect
	github.com/eino-contrib/jsonschema v1.0.3 // indirect
	github.com/elliotwutingfeng/asciiset v0.0.0-20260129054604-cfde2086bc57 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.37.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.3 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/erikvarga/go-rpmdb v0.0.0-20250523120114-a15a62cd4593 // indirect
	github.com/evanphx/json-patch v0.5.2 // indirect
	github.com/evilmartians/lefthook v1.13.6 // indirect
	github.com/facebookincubator/nvdtools v0.1.5 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/felixge/fgprof v0.9.5 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/flosch/pongo2/v4 v4.0.2 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/gin-gonic/gin v1.12.0 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.8.0 // indirect
	github.com/go-git/go-git/v5 v5.17.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.3 // indirect
	github.com/go-json-experiment/json v0.0.0-20250910080747-cc2cfa0554c3 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/inflect v0.21.5 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.1 // indirect
	github.com/go-restruct/restruct v1.2.0-alpha // indirect
	github.com/go-sourcemap/sourcemap v2.1.4+incompatible // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/gohugoio/hashstructure v0.6.0 // indirect
	github.com/gojek/valkyrie v0.0.0-20190210220504-8f62c1e7ba45 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/gomarkdown/markdown v0.0.0-20260217112301-37c66b85d6ab // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-containerregistry v0.21.2 // indirect
	github.com/google/go-github/v74 v74.0.0 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/licensecheck v0.3.1 // indirect
	github.com/google/pprof v0.0.0-20260302011040-a15ffb7f9dcc // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.13 // indirect
	github.com/googleapis/gax-go/v2 v2.17.0 // indirect
	github.com/gookit/color v1.6.0 // indirect
	github.com/goph/emperror v0.17.2 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/hashicorp/aws-sdk-go-base/v2 v2.0.0-beta.71 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-getter v1.8.4 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-version v1.8.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/hidal-go/hidalgo v0.3.0 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/ianlancetaylor/demangle v0.0.0-20251118225945-96ee0021ea0f // indirect
	github.com/icholy/digest v1.1.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/invopop/jsonschema v0.13.0 // indirect
	github.com/iris-contrib/schema v0.0.6 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jinzhu/copier v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kaptinlin/go-i18n v0.1.7 // indirect
	github.com/kaptinlin/jsonschema v0.4.14 // indirect
	github.com/kaptinlin/messageformat-go v0.4.0 // indirect
	github.com/kataras/blocks v0.0.12 // indirect
	github.com/kataras/golog v0.1.12 // indirect
	github.com/kataras/iris/v12 v12.2.11 // indirect
	github.com/kataras/pio v0.0.13 // indirect
	github.com/kataras/sitemap v0.0.6 // indirect
	github.com/kataras/tunnel v0.0.4 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/klauspost/compress v1.18.4 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/knadh/koanf/maps v0.1.2 // indirect
	github.com/knadh/koanf/parsers/json v1.0.0 // indirect
	github.com/knadh/koanf/parsers/toml/v2 v2.2.0 // indirect
	github.com/knadh/koanf/parsers/yaml v1.1.0 // indirect
	github.com/knadh/koanf/providers/fs v1.0.0 // indirect
	github.com/knadh/koanf/v2 v2.3.0 // indirect
	github.com/labstack/echo/v4 v4.15.1 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/lunixbochs/struc v0.0.0-20241101090106-8d528fa2c543 // indirect
	github.com/mailgun/raymond/v2 v2.0.48 // indirect
	github.com/mailru/easyjson v0.9.1 // indirect
	github.com/masahiro331/go-ext4-filesystem v0.0.0-20240620024024-ca14e6327bbd // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.2-0.20220822084749-2491eb6c1c75 // indirect
	github.com/mattn/go-runewidth v0.0.20 // indirect
	github.com/mattn/go-shellwords v1.0.12 // indirect
	github.com/mattn/go-tty v0.0.7 // indirect
	github.com/meguminnnnnnnnn/go-openai v0.1.1 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mholt/archives v0.1.5 // indirect
	github.com/microcosm-cc/bluemonday v1.0.27 // indirect
	github.com/micromdm/plist v0.2.2 // indirect
	github.com/mikelolasagasti/xz v1.0.1 // indirect
	github.com/minio/minlz v1.0.1 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/buildkit v0.26.3 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/natefinch/atomic v1.0.1 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/nikolalohinski/gonja v1.5.3 // indirect
	github.com/nwaples/rardecode/v2 v2.2.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/opencontainers/runtime-spec v1.2.1 // indirect
	github.com/opencontainers/selinux v1.13.1 // indirect
	github.com/pborman/indent v1.2.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.25 // indirect
	github.com/piprate/json-gold v0.5.0 // indirect
	github.com/pkg/profile v1.7.0 // indirect
	github.com/pkg/xattr v0.4.12 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/pquerna/cachecontrol v0.2.0 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/rust-secure-code/go-rustaudit v0.0.0-20250226111315-e20ec32e963c // indirect
	github.com/saferwall/pe v1.5.9 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/schollz/closestmatch v2.1.0+incompatible // indirect
	github.com/schollz/progressbar/v3 v3.18.0 // indirect
	github.com/scylladb/go-set v1.0.3-0.20200225121959-cc7b2070d91e // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/slongfield/pyfmt v0.0.0-20220222012616-ea85ff4c361f // indirect
	github.com/sorairolake/lzip-go v0.3.8 // indirect
	github.com/spdx/gordf v0.0.0-20250128162952-000978ccd6fb // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/spiffe/go-spiffe/v2 v2.6.0 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/sylabs/squashfs v1.0.6 // indirect
	github.com/tdewolff/minify/v2 v2.24.10 // indirect
	github.com/tdewolff/parse/v2 v2.8.10 // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/thoas/go-funk v0.9.3 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/jsonc v0.3.2 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/tink-crypto/tink-go/v2 v2.6.0 // indirect
	github.com/tklauser/go-sysconf v0.3.16 // indirect
	github.com/tklauser/numcpus v0.11.0 // indirect
	github.com/tonistiigi/go-csvvalue v0.0.0-20240814133006-030d3b2625d0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/tylertreat/BoomFilters v0.0.0-20210315201527-1a82519a3e43 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/vbatts/tar-split v0.12.2 // indirect
	github.com/vifraa/gopom v1.0.0 // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/wagoodman/go-partybus v0.0.0-20230516145632-8ccac152c651 // indirect
	github.com/wagoodman/go-progress v0.0.0-20260303201901-10176f79b2c0 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/yargevad/filepathx v1.0.0 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	github.com/yosssi/ace v0.0.5 // indirect
	github.com/yuin/goldmark v1.7.16 // indirect
	github.com/yuin/goldmark-emoji v1.0.6 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zclconf/go-cty v1.18.0 // indirect
	github.com/zclconf/go-cty-yaml v1.2.0 // indirect
	go.etcd.io/bbolt v1.4.3 // indirect
	go.mongodb.org/mongo-driver/v2 v2.5.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.41.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.66.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.66.0 // indirect
	go.opentelemetry.io/otel v1.41.0 // indirect
	go.opentelemetry.io/otel/metric v1.41.0 // indirect
	go.opentelemetry.io/otel/sdk v1.41.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.41.0 // indirect
	go.opentelemetry.io/otel/trace v1.41.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.4 // indirect
	go4.org v0.0.0-20260112195520-a5071408f32f // indirect
	golang.org/x/arch v0.24.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20260218203240-3dfff04db8fa // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/telemetry v0.0.0-20260304144227-18da59047661 // indirect
	golang.org/x/text v0.34.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.42.0 // indirect
	golang.org/x/vuln v1.1.4 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/api v0.269.0 // indirect
	google.golang.org/genproto v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	gopkg.in/ini.v1 v1.67.1 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	k8s.io/utils v0.0.0-20260210185600-b8788abfbbc2 // indirect
	modernc.org/libc v1.69.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.46.1 // indirect
	osv.dev/bindings/go v0.0.0-20260304060910-4fcedbd3c18b // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
	www.velocidex.com/golang/go-ntfs v0.2.0 // indirect
	www.velocidex.com/golang/regparser v0.0.0-20250203141505-31e704a67ef7 // indirect
)

tool (
	github.com/a-h/templ/cmd/templ
	github.com/evilmartians/lefthook
)
