module github.com/safedep/vet

go 1.23.2

require (
	buf.build/gen/go/safedep/api/grpc/go v1.5.1-20250120081932-370c5c54f7c9.2
	buf.build/gen/go/safedep/api/protocolbuffers/go v1.36.3-20250120081932-370c5c54f7c9.1
	github.com/AlecAivazis/survey/v2 v2.3.7
	github.com/CycloneDX/cyclonedx-go v0.9.2
	github.com/anchore/syft v1.18.1
	github.com/cayleygraph/cayley v0.7.7-0.20240706181042-81dcd7d73e45
	github.com/cayleygraph/quad v1.3.0
	github.com/cli/oauth v1.2.0
	github.com/deepmap/oapi-codegen v1.16.3
	github.com/github/go-spdx/v2 v2.3.2
	github.com/gofri/go-github-ratelimit v1.1.0
	github.com/gojek/heimdall v5.0.2+incompatible
	github.com/gojek/heimdall/v7 v7.0.3
	github.com/golang/protobuf v1.5.4
	github.com/google/cel-go v0.22.1
	github.com/google/go-github/v54 v54.0.0
	github.com/google/osv-scanner v1.9.2
	github.com/hashicorp/hcl/v2 v2.23.0
	github.com/jedib0t/go-pretty/v6 v6.6.5
	github.com/kubescape/go-git-url v0.0.30
	github.com/oklog/ulid/v2 v2.1.0
	github.com/owenrumney/go-sarif/v2 v2.3.3
	github.com/package-url/packageurl-go v0.1.3
	github.com/safedep/dry v0.0.0-20250106055453-e0772cda4a25
	github.com/sirupsen/logrus v1.9.3
	github.com/smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82
	github.com/spdx/tools-golang v0.5.5
	github.com/spf13/cobra v1.8.1
	github.com/stretchr/testify v1.10.0
	golang.org/x/oauth2 v0.25.0
	google.golang.org/grpc v1.69.4
	google.golang.org/protobuf v1.36.3
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/owenrumney/go-sarif/v2 v2.3.1 => github.com/safedep/go-sarif/v2 v2.3.1

// https://github.com/cli/oauth/pull/68
replace github.com/cli/oauth v1.0.1 => github.com/abhisek/oauth v1.0.1-audience

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.3-20241127180247-a33202765966.1 // indirect
	cel.dev/expr v0.19.1 // indirect
	dario.cat/mergo v1.0.1 // indirect
	github.com/BurntSushi/toml v1.4.0 // indirect
	github.com/CloudyKit/fastprinter v0.0.0-20200109182630-33d98a066a53 // indirect
	github.com/CloudyKit/jet/v6 v6.2.0 // indirect
	github.com/DataDog/datadog-go v4.8.3+incompatible // indirect
	github.com/Joker/jade v1.1.3 // indirect
	github.com/Masterminds/semver/v3 v3.3.1 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.5 // indirect
	github.com/Shopify/goreferrer v0.0.0-20240724165105-aceaa0259138 // indirect
	github.com/acobaugh/osrelease v0.1.0 // indirect
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/afex/hystrix-go v0.0.0-20180502004556-fa1af6a1f4f5 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/anchore/archiver/v3 v3.5.3-0.20241210171143-5b1d8d1c7c51 // indirect
	github.com/anchore/clio v0.0.0-20250115173119-036c31e4dfd7 // indirect
	github.com/anchore/fangs v0.0.0-20241125225345-c73f048692d3 // indirect
	github.com/anchore/go-logger v0.0.0-20241205183533-4fc29b5832e7 // indirect
	github.com/anchore/go-macholibre v0.0.0-20241219195549-70b0e607b241 // indirect
	github.com/anchore/go-struct-converter v0.0.0-20240925125616-a0883641c664 // indirect
	github.com/anchore/packageurl-go v0.1.1-0.20241018175412-5c22e6360c4f // indirect
	github.com/anchore/stereoscope v0.0.12 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/becheran/wildmatch-go v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bmatcuk/doublestar/v4 v4.8.0 // indirect
	github.com/boltdb/bolt v1.3.1 // indirect
	github.com/bytedance/sonic v1.12.7 // indirect
	github.com/bytedance/sonic/loader v0.2.3 // indirect
	github.com/cactus/go-statsd-client/statsd v0.0.0-20200423205355-cb0885a1018c // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chainguard-dev/git-urls v1.0.2 // indirect
	github.com/cloudflare/circl v1.5.0 // indirect
	github.com/cloudwego/base64x v0.1.5 // indirect
	github.com/cloudwego/iasm v0.2.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dlclark/regexp2 v1.11.4 // indirect
	github.com/docker/cli v27.5.0+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.8.2 // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/dop251/goja v0.0.0-20250114131315-46d383d606d3 // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/facebookincubator/nvdtools v0.1.5 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/felixge/fgprof v0.9.5 // indirect
	github.com/flosch/pongo2/v4 v4.0.2 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.8 // indirect
	github.com/gin-contrib/sse v1.0.0 // indirect
	github.com/gin-gonic/gin v1.10.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.24.0 // indirect
	github.com/go-restruct/restruct v1.2.0-alpha // indirect
	github.com/go-sourcemap/sourcemap v2.1.4+incompatible // indirect
	github.com/goccy/go-json v0.10.4 // indirect
	github.com/gojek/valkyrie v0.0.0-20190210220504-8f62c1e7ba45 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gomarkdown/markdown v0.0.0-20241205020045-f7e15b2f3e62 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/go-containerregistry v0.20.3 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/licensecheck v0.3.1 // indirect
	github.com/google/pprof v0.0.0-20250121033306-997b0b79cac0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gookit/color v1.5.4 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hidal-go/hidalgo v0.3.0 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/iris-contrib/schema v0.0.6 // indirect
	github.com/jinzhu/copier v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kataras/blocks v0.0.11 // indirect
	github.com/kataras/golog v0.1.12 // indirect
	github.com/kataras/iris/v12 v12.2.11 // indirect
	github.com/kataras/pio v0.0.13 // indirect
	github.com/kataras/sitemap v0.0.6 // indirect
	github.com/kataras/tunnel v0.0.4 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/labstack/echo/v4 v4.13.3 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/magiconair/properties v1.8.9 // indirect
	github.com/mailgun/raymond/v2 v2.0.48 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mholt/archiver/v3 v3.5.1 // indirect
	github.com/microcosm-cc/bluemonday v1.0.27 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nwaples/rardecode v1.1.3 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pborman/indent v1.2.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/piprate/json-gold v0.5.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/profile v1.7.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/pquerna/cachecontrol v0.2.0 // indirect
	github.com/prometheus/client_golang v1.20.5 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/schollz/closestmatch v2.1.0+incompatible // indirect
	github.com/scylladb/go-set v1.0.3-0.20200225121959-cc7b2070d91e // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.19.0 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/sylabs/squashfs v1.0.4 // indirect
	github.com/tdewolff/minify/v2 v2.21.3 // indirect
	github.com/tdewolff/parse/v2 v2.7.19 // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/tylertreat/BoomFilters v0.0.0-20210315201527-1a82519a3e43 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/vifraa/gopom v1.0.0 // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/wagoodman/go-partybus v0.0.0-20230516145632-8ccac152c651 // indirect
	github.com/wagoodman/go-progress v0.0.0-20230925121702-07e42b3cdba0 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/yosssi/ace v0.0.5 // indirect
	github.com/zclconf/go-cty v1.16.1 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.59.0 // indirect
	go.opentelemetry.io/otel v1.34.0 // indirect
	go.opentelemetry.io/otel/metric v1.34.0 // indirect
	go.opentelemetry.io/otel/trace v1.34.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/arch v0.13.0 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/exp v0.0.0-20250106191152-7588d65b2ba8 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/term v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/time v0.9.0 // indirect
	golang.org/x/tools v0.29.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250115164207-1a7da9e5054f // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/utils v0.0.0-20241210054802-24370beab758 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)
