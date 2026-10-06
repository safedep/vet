# resolve.jq lists the vet releases that the action can install, newest
# first. Each line holds the tag and the latest of the publish time and the
# asset update times. A time that is missing counts as now.
# internal/github.Choice has the same rule, and the tests of both read
# action/testdata/resolve-cases.json.
#
# Input: the release list of the GitHub releases API.
# Arguments: major (such as v2), channel (stable or prerelease),
# cooldown_hours, min_version ("" for none) and now (RFC 3339 in UTC).

def v: if startswith("v") then . else "v" + . end;

# semver reads a version in the form of golang.org/x/mod/semver, or gives
# nothing.
def semver:
  (capture("^v(?<major>0|[1-9][0-9]*)\\.(?<minor>0|[1-9][0-9]*)\\.(?<patch>0|[1-9][0-9]*)(-(?<pre>[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*))?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$") // empty)
  | select(.pre == null or (.pre | split(".") | all(test("^(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)$"))));

# key orders versions by semantic version. A release sorts after its
# pre-releases. A numeric identifier sorts before a text identifier, and
# by length first, so a long number never loses precision.
def key:
  [(.major, .minor, .patch | tonumber),
   if .pre == null then [1]
   else [0] + (.pre | split(".") | map(if test("^[0-9]+$") then [0, length, .] else [1, .] end))
   end];

def pseudo:
  test("^v[0-9]+\\.(0\\.0-|[0-9]+\\.[0-9]+-([^+]*\\.)?0\\.)[0-9]{14}-[A-Za-z0-9]+(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$");

($now | fromdateiso8601) as $now
| ($cooldown_hours | tonumber * 3600) as $cooldown
| (if $min_version == "" then null
   else ($min_version | v | semver | key) // error("min_version \($min_version) is not a version")
   end) as $min
| [ .[]
    | select(.draft != true and .immutable == true)
    | .tag_name as $tag
    | ($tag | v) as $ver
    | ($ver | semver) as $s
    | select(($ver | pseudo) | not)
    | select("v" + $s.major == $major)
    | select($channel == "prerelease" or (.prerelease != true and $s.pre == null))
    | ($s | key) as $k
    | select($min == null or $k >= $min)
    | ([.published_at] + [.assets[]?.updated_at] | map(if . == null then $now else fromdateiso8601 end) | max) as $young
    | select($now - $young >= $cooldown)
    | {tag: $tag, key: $k, young: $young}
  ]
| sort_by(.key) | reverse | .[]
| "\(.tag)\t\(.young | todate)"
