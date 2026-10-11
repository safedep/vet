# Evasion corpus coverage

`go test ./test/evasion/` writes this file. Run it with `UPDATE_GOLDEN=1` after you change a case or a
detection, and commit the diff. See README.md.

## commands

| Case | Expected | Actual | Result |
| --- | --- | --- | --- |
| `abs-path`: A download piped to /bin/sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `args-split`: A download piped to sh in the args of bash -c | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `backslash`: A download piped to \sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `base64-pipe`: A base64 payload decoded and piped to sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `curl-pipe-sh`: A download piped to sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `dynamic-no-shell`: Near miss: a command name built at run time with no pipe into a shell | `editor-task-command` | `editor-task-command` | pass |
| `echo-sh`: Near miss: echo piped to sh with no download | `editor-task-command` | `editor-task-command` | pass |
| `env-prefix`: A download piped to env sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `export-var`: A download piped to a shell in an exported variable | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `hook-download`: A git hook in .githooks that pipes a download to sh | `agent-hook-command`, `suspicious-command` | `agent-hook-command`, `suspicious-command` | pass |
| `ifs`: A download piped to sh, with ${IFS} in place of spaces | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `nested-c`: A download piped to sh inside bash -c inside sh -c | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `node-font`: node runs a fake font | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `node-fromcharcode`: An inline node script that builds a payload from char codes | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `node-svg`: node runs a .svg file | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `npm-dev`: Near miss: a folder-open task that starts the dev server | `editor-task-command` | `editor-task-command` | pass |
| `padded-command`: A download after 80 spaces in the command | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `pipe-all`: A download piped to sh with \|& | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `printf-hex`: A download by a tool name that printf writes from hex | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `quote-split`: A download piped to s''h, with the shell name split by quotes | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `sudo-flags`: A download piped to sudo -u root -E bash | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `variable-shell`: A download piped to a shell in a variable | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `variable-tool`: A download by a tool name in a variable | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `wget-pipe-bash`: A download with wget piped to bash | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |

## disguise

| Case | Expected | Actual | Result |
| --- | --- | --- | --- |
| `binary-header-eval`: The woff2 signature, binary header bytes and then a script that decodes and runs a payload | `disguised-script` | `disguised-script` | pass |
| `binary-header-hex`: The woff2 signature, binary header bytes and then a hex payload | `font-payload` | `font-payload` | pass |
| `binary-header-loader`: The woff2 signature, binary header bytes and then a loader with no strong token | `font-payload` | `font-payload` | pass |
| `cff-glyph-names`: Near miss: a font whose glyph names run with no separator, as in a CFF font | none | none | pass |
| `css`: A script in a .css file | `disguised-script` | `disguised-script` | pass |
| `dict`: A script in a .dict file, one statement on each line | `disguised-script` | `disguised-script` | pass |
| `font-hex`: A hex payload in a .woff file with no script token | `disguised-script` | `disguised-script` | pass |
| `font-tabs`: A script after 273 tabs in a .woff2 file | `disguised-script` | `disguised-script` | pass |
| `font-text`: A script in a .ttf file with no pad | `disguised-script` | `disguised-script` | pass |
| `fuzz-dict`: Near miss: a fuzz dictionary of JavaScript keywords | none | none | pass |
| `lfs-pointer`: Near miss: a Git LFS pointer in place of a font | none | none | pass |
| `magic-then-text`: The woff2 magic bytes and then a script, with no NUL byte | `disguised-script` | `disguised-script` | pass |
| `png-comment`: A .png file that starts with a JavaScript comment, which node runs | `disguised-script` | `disguised-script` | pass |
| `real-css`: Near miss: a style sheet with an embedded base64 font and a var() call | none | none | pass |
| `real-font`: Near miss: a font that starts with the woff2 signature and holds only binary data | none | none | pass |
| `real-source-map`: Near miss: a source map that holds the source of the code that it maps | none | none | pass |
| `source-map`: A script in a .map file | `disguised-script` | `disguised-script` | pass |
| `svg-script-element`: Near miss: an SVG image with a script element | none | none | pass |
| `svg`: A script in a .svg file | `disguised-script` | `disguised-script` | pass |
| `xssi-source-map`: Near miss: a source map with the XSSI prefix | none | none | pass |

## padding

| Case | Expected | Actual | Result |
| --- | --- | --- | --- |
| `aligned-comment`: Near miss: a config that aligns a short comment after 120 spaces | none | none | pass |
| `blank-lines`: A loader 300 blank lines below the export | `dynamic-code` | `dynamic-code` | pass |
| `hangul-filler`: A loader after 280 Hangul fillers | `padded-code` | `padded-code` | pass |
| `ideographic`: A loader after 280 ideographic spaces | `padded-code` | `padded-code` | pass |
| `mixed`: A loader after a pad of spaces, tabs and no-break spaces in turn | `padded-code` | `padded-code` | pass |
| `nbsp`: A loader after 280 no-break spaces | `padded-code` | `padded-code` | pass |
| `no-pad`: A loader on the line of the export with no pad | `padded-code` | `padded-code` | pass |
| `short-runs`: A loader after five runs of 60 spaces, each run cut by a semicolon | `padded-code` | `padded-code` | pass |
| `snapshot`: Near miss: a test that aligns a short value after a long run of spaces | none | none | pass |
| `spaces`: A loader after the export and 280 spaces | `padded-code` | `padded-code` | pass |
| `tabs`: A loader after the export and 70 tabs | `padded-code` | `padded-code` | pass |
| `zero-width`: A loader after 280 zero-width spaces | `invisible-unicode`, `padded-code` | `invisible-unicode`, `padded-code` | pass |

## placement

| Case | Expected | Actual | Result |
| --- | --- | --- | --- |
| `app-js`: A loader after 280 spaces in App.js | `padded-code` | `padded-code` | pass |
| `before-export`: A loader after 280 spaces on a line before the export | `padded-code` | `padded-code` | pass |
| `export-object`: A loader after an export of an object literal, with no pad | `dynamic-code` | `dynamic-code` | pass |
| `git-hash-config`: Near miss: a config that reads the git hash with a literal command and loads a local plugin | none | none | pass |
| `in-comment`: A loader after a pad that a block comment holds | `padded-code` | `padded-code` | pass |
| `inert-loader`: Near miss: obfuscated code in a config that runs no dynamic code, loads no module and sets no global | none | none | pass |
| `nested-function`: A loader inside a plugin function of the config, with no pad | `dynamic-code` | `dynamic-code` | pass |
| `next-line`: A loader on the line after the export, with no pad | `dynamic-code` | `dynamic-code` | pass |
| `npm-cli-padded`: A loader after 280 spaces in the npm entry script | `padded-code` | `padded-code` | pass |
| `npm-cli-real`: Near miss: the npm entry script as npm ships it | none | none | pass |
| `npm-cli-small`: A small loader on its own line in the npm entry script | `dynamic-code` | `dynamic-code` | pass |
| `plugin-require`: Near miss: a webpack config that loads a plugin by a computed path | none | none | pass |
| `truffle`: A loader after 280 spaces in truffle-config.js | `padded-code` | `padded-code` | pass |

## unicode

| Case | Expected | Actual | Result |
| --- | --- | --- | --- |
| `bidi`: A bidi override in code, as in Trojan Source | `invisible-unicode` | `invisible-unicode` | pass |
| `emoji`: Near miss: emoji with variation selectors, and a keycap | none | none | pass |
| `flag`: Near miss: the flag of England, which spells its region in tag characters | none | none | pass |
| `rtl-instructions`: Near miss: an agent instruction file with one right-to-left mark gives no Unicode finding | `agent-instruction-change` | `agent-instruction-change` | pass |
| `selectors-few-split`: Near miss: two files with 3 stray selectors each | none | none | pass |
| `selectors-no-decoder`: A payload in 30 variation selectors with no decoder in the file | `unicode-payload` | `unicode-payload` | pass |
| `selectors-split-files`: A payload in variation selectors, split across two files of 15 each | `invisible-unicode`, `split-unicode-payload` | `invisible-unicode`, `split-unicode-payload` | pass |
| `selectors-split-spread`: A payload in variation selectors split across two files, with a letter before each selector so no file has a run | `split-unicode-payload` | `split-unicode-payload` | pass |
| `selectors-spread`: A payload in variation selectors, one on each line | `unicode-payload` | `unicode-payload` | pass |
| `selectors`: A payload in 30 variation selectors after ASCII, with a decoder | `unicode-payload` | `unicode-payload` | pass |
| `tags-in-instructions`: Hidden text in tag characters in an agent instruction file | `agent-instruction-change`, `unicode-payload` | `agent-instruction-change`, `unicode-payload` | pass |
| `tags`: Hidden text in 30 tag characters | `unicode-payload` | `unicode-payload` | pass |
| `zero-width-run`: A run of 8 zero-width characters in code | `invisible-unicode` | `invisible-unicode` | pass |

## variants

| Case | Expected | Actual | Result |
| --- | --- | --- | --- |
| `amend-alias`: Near miss: a developer script that amends the last commit and force-pushes it | none | none | pass |
| `glassworm`: GlassWorm: a payload in variation selectors that a short decoder runs | `unicode-payload` | `unicode-payload` | pass |
| `polinrider-config`: PolinRider: a loader after spaces in a build config, and the push script hidden by .gitignore | `dynamic-code`, `history-rewrite-script`, `padded-code` | `dynamic-code`, `history-rewrite-script`, `padded-code` | pass |
| `polinrider-os-task`: PolinRider: a folder-open task with a command for each OS, the bad one only on Linux | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | pass |
| `polinrider-renamed-rewrite`: PolinRider: the push script under a new name, hidden by .gitignore | `history-rewrite-script` | `history-rewrite-script` | pass |
| `polinrider-rewrite`: PolinRider: a script that amends the last commit, keeps its date and force-pushes it | `history-rewrite-script` | `history-rewrite-script` | pass |
| `polinrider-task`: PolinRider: a hidden folder-open task runs node on a fake font | `disguised-script`, `editor-autorun-enabled`, `editor-task-command`, `suspicious-command` | `disguised-script`, `editor-autorun-enabled`, `editor-task-command`, `suspicious-command` | pass |

Total: 89 cases, 89 pass, 0 fail, 0 known misses.
