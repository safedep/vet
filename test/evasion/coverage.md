# Evasion corpus coverage

`go test ./test/evasion/` writes this file. Run it with `UPDATE_GOLDEN=1` after you change a case or a
detection, and commit the diff. See README.md.

## commands

| Case | Expected | Actual | Gate | Result |
| --- | --- | --- | --- | --- |
| `abs-path`: A download piped to /bin/sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `args-split`: A download piped to sh in the args of bash -c | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `backslash`: A download piped to \sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `base64-pipe`: A base64 payload decoded and piped to sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `bash-lc`: A download piped to /bin/sh inside bash -lc | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `command-subst`: A download piped to /bin/sh inside a command substitution of echo | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `curl-pipe-sh`: A download piped to sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `dynamic-no-shell`: Near miss: a command name built at run time with no pipe into a shell | `editor-task-command` | `editor-task-command` | passes | pass |
| `echo-sh`: Near miss: echo piped to sh with no download | `editor-task-command` | `editor-task-command` | passes | pass |
| `env-prefix`: A download piped to env sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `eval-printf`: eval of a command that printf builds | `editor-task-command`, `suspicious-command` | `editor-task-command` | passes | miss: the walk does not run printf to read the text that eval gets |
| `export-var`: A download piped to a shell in an exported variable | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `function-wrapper`: A download by a shell function that wraps curl | `editor-task-command`, `suspicious-command` | `editor-task-command` | passes | miss: the walk does not read the body of a function at its call |
| `glob-shell`: A download piped to /bin/ba?h, a glob that the shell expands | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `here-string`: A shell that reads a download through a here-string | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `hook-download`: A git hook in .githooks that pipes a download to sh | `agent-hook-command`, `suspicious-command` | `agent-hook-command`, `suspicious-command` | fails | pass |
| `ifs`: A download piped to sh, with ${IFS} in place of spaces | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `login-shell`: A download piped to the login shell in $SHELL | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `nested-c`: A download piped to sh inside bash -c inside sh -c | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `node-font`: node runs a fake font | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `node-fromcharcode`: An inline node script that builds a payload from char codes | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `node-svg`: node runs a .svg file | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `npm-dev`: Near miss: a folder-open task that starts the dev server | `editor-task-command` | `editor-task-command` | passes | pass |
| `padded-command`: A download after 80 spaces in the command | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `pipe-all`: A download piped to sh with \|& | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `printf-hex`: A download by a tool name that printf writes from hex | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `process-subst`: A shell that reads a download through a process substitution | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `quote-split`: A download piped to s''h, with the shell name split by quotes | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `source-subst`: source of a download through a process substitution | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `sudo-flags`: A download piped to sudo -u root -E bash | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `sudo-long`: A download piped to sudo --user root bash, with a long option that takes a value | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `sudo-n`: A download piped to sudo -n bash, where -n takes no value | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `sudo-s`: A download piped to sudo -s, which runs a shell | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `time-p`: A download piped to time -p sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `timeout`: A download piped to timeout 30 sh | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `tool-path`: Near miss: a tool at a run-time path writes shell code that a shell runs | `editor-task-command` | `editor-task-command` | passes | pass |
| `two-step`: A download to a file by a redirect, then sh runs the file | `editor-task-command`, `suspicious-command` | `editor-task-command` | passes | miss: the patterns do not join a redirect to a file and a later run of the file |
| `variable-shell`: A download piped to a shell in a variable | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `variable-tool`: A download by a tool name in a variable | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `wget-pipe-bash`: A download with wget piped to bash | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |

## disguise

| Case | Expected | Actual | Gate | Result |
| --- | --- | --- | --- | --- |
| `binary-header-eval`: The woff2 signature, binary header bytes and then a script that decodes and runs a payload | `disguised-script` | `disguised-script` | fails | pass |
| `binary-header-hex`: The woff2 signature, binary header bytes and then a hex payload | `font-payload` | `font-payload` | passes | pass |
| `binary-header-loader`: The woff2 signature, binary header bytes and then a loader with no strong token | `font-payload` | `font-payload` | passes | pass |
| `cff-glyph-names`: Near miss: a font whose glyph names run with no separator, as in a CFF font | none | none | passes | pass |
| `css-comment-example`: Near miss: a style sheet whose header comment shows how to load it | none | none | passes | pass |
| `css-ie-expression`: Near miss: old IE style sheet hacks that call eval in expression() | none | none | passes | pass |
| `css-modules`: Near miss: a CSS Modules sheet with :import rules and .constructor class names | none | none | passes | pass |
| `css-nul-comment`: A script in a .css file with a NUL byte in a comment, so the file looks binary | `disguised-script` | `disguised-script` | fails | pass |
| `css-stager`: A short stager in a .css file that decodes and runs a payload | `disguised-script` | `disguised-script` | fails | pass |
| `css`: A script in a .css file | `disguised-script` | `disguised-script` | fails | pass |
| `dict`: A script in a .dict file, one statement on each line | `disguised-script` | `disguised-script` | fails | pass |
| `font-hex`: A hex payload in a .woff file with no script token | `disguised-script` | `disguised-script` | fails | pass |
| `font-tabs`: A script after 273 tabs in a .woff2 file | `disguised-script` | `disguised-script` | fails | pass |
| `font-text`: A script in a .ttf file with no pad | `disguised-script` | `disguised-script` | fails | pass |
| `fuzz-dict`: Near miss: a fuzz dictionary of JavaScript keywords | none | none | passes | pass |
| `lfs-pointer`: Near miss: a Git LFS pointer in place of a font | none | none | passes | pass |
| `linker-map`: Near miss: a linker map file with C++ symbols | none | none | passes | pass |
| `magic-then-text`: The woff2 magic bytes and then a script, with no NUL byte | `disguised-script` | `disguised-script` | fails | pass |
| `png-comment`: A .png file that starts with a JavaScript comment, which node runs | `disguised-script` | `disguised-script` | fails | pass |
| `real-css`: Near miss: a style sheet with an embedded base64 font and a var() call | none | none | passes | pass |
| `real-font`: Near miss: a font that starts with the woff2 signature and holds only binary data | none | none | passes | pass |
| `real-source-map`: Near miss: a source map that holds the source of the code that it maps | none | none | passes | pass |
| `sass-function`: Near miss: a style sheet with Sass functions | none | none | passes | pass |
| `source-map-empty-object`: A script in a .map file that starts with {} | `disguised-script` | `disguised-script` | fails | pass |
| `source-map`: A script in a .map file | `disguised-script` | `disguised-script` | fails | pass |
| `svg-html-comment`: A script in a .svg file that starts with an HTML-like comment, which node reads as a comment | `disguised-script` | `disguised-script` | fails | pass |
| `svg-in-xml-comment`: A script in an XML comment of a well-formed .svg file, which node runs | `disguised-script` | `disguised-script` | fails | pass |
| `svg-script-element`: Near miss: an SVG image with a script element | none | none | passes | pass |
| `svg`: A script in a .svg file | `disguised-script` | `disguised-script` | fails | pass |
| `xssi-source-map`: Near miss: a source map with the XSSI prefix | none | none | passes | pass |

## padding

| Case | Expected | Actual | Gate | Result |
| --- | --- | --- | --- | --- |
| `aligned-comment`: Near miss: a config that aligns a short comment after 120 spaces | none | none | passes | pass |
| `blank-lines`: A loader 300 blank lines below the export | `dynamic-code` | `dynamic-code` | passes | pass |
| `hangul-filler`: A loader after 280 Hangul fillers | `padded-code` | `padded-code` | fails | pass |
| `ideographic`: A loader after 280 ideographic spaces | `padded-code` | `padded-code` | fails | pass |
| `mixed`: A loader after a pad of spaces, tabs and no-break spaces in turn | `padded-code` | `padded-code` | fails | pass |
| `nbsp`: A loader after 280 no-break spaces | `padded-code` | `padded-code` | fails | pass |
| `no-pad`: A loader on the line of the export with no pad | `padded-code` | `padded-code` | fails | pass |
| `short-runs`: A loader after five runs of 60 spaces, each run cut by a semicolon | `padded-code` | `padded-code` | fails | pass |
| `snapshot`: Near miss: a test that aligns a short value after a long run of spaces | none | none | passes | pass |
| `spaces`: A loader after the export and 280 spaces | `padded-code` | `padded-code` | fails | pass |
| `tabs`: A loader after the export and 70 tabs | `padded-code` | `padded-code` | fails | pass |
| `zero-width`: A loader after 280 zero-width spaces | `invisible-unicode`, `padded-code` | `invisible-unicode`, `padded-code` | fails | pass |

## placement

| Case | Expected | Actual | Gate | Result |
| --- | --- | --- | --- | --- |
| `app-js`: A loader after 280 spaces in App.js | `padded-code` | `padded-code` | fails | pass |
| `before-export`: A loader after 280 spaces on a line before the export | `padded-code` | `padded-code` | fails | pass |
| `export-object`: A loader after an export of an object literal, with no pad | `dynamic-code` | `dynamic-code` | passes | pass |
| `git-hash-config`: Near miss: a config that reads the git hash with a literal command and loads a local plugin | none | none | passes | pass |
| `in-comment`: A loader after a pad that a block comment holds | `padded-code` | `padded-code` | fails | pass |
| `inert-loader`: Near miss: obfuscated code in a config that runs no dynamic code, loads no module and sets no global | none | none | passes | pass |
| `nested-function`: A loader inside a plugin function of the config, with no pad | `dynamic-code` | `dynamic-code` | passes | pass |
| `next-line`: A loader on the line after the export, with no pad | `dynamic-code` | `dynamic-code` | passes | pass |
| `npm-cli-padded`: A loader after 280 spaces in the npm entry script | `padded-code` | `padded-code` | fails | pass |
| `npm-cli-real`: Near miss: the npm entry script as npm ships it | none | none | passes | pass |
| `npm-cli-small`: A small loader on its own line in the npm entry script | `dynamic-code` | `dynamic-code` | passes | pass |
| `plugin-require`: Near miss: a webpack config that loads a plugin by a computed path | none | none | passes | pass |
| `truffle`: A loader after 280 spaces in truffle-config.js | `padded-code` | `padded-code` | fails | pass |

## unicode

| Case | Expected | Actual | Gate | Result |
| --- | --- | --- | --- | --- |
| `bidi`: A bidi override in code, as in Trojan Source | `invisible-unicode` | `invisible-unicode` | passes | pass |
| `emoji`: Near miss: emoji with variation selectors, and a keycap | none | none | passes | pass |
| `flag`: Near miss: the flag of England, which spells its region in tag characters | none | none | passes | pass |
| `rtl-instructions`: Near miss: an agent instruction file with one right-to-left mark gives no Unicode finding | `agent-instruction-change` | `agent-instruction-change` | passes | pass |
| `selectors-few-split`: Near miss: two files with 3 stray selectors each | none | none | passes | pass |
| `selectors-no-decoder`: A payload in 30 variation selectors with no decoder in the file | `unicode-payload` | `unicode-payload` | fails | pass |
| `selectors-split-files`: A payload in variation selectors, split across two files of 15 each | `invisible-unicode`, `split-unicode-payload` | `invisible-unicode`, `split-unicode-payload` | passes | pass |
| `selectors-split-spread`: A payload in variation selectors split across two files, with a letter before each selector so no file has a run | `split-unicode-payload` | `split-unicode-payload` | passes | pass |
| `selectors-spread`: A payload in variation selectors, one on each line | `unicode-payload` | `unicode-payload` | fails | pass |
| `selectors`: A payload in 30 variation selectors after ASCII, with a decoder | `unicode-payload` | `unicode-payload` | fails | pass |
| `tags-in-instructions`: Hidden text in tag characters in an agent instruction file | `agent-instruction-change`, `unicode-payload` | `agent-instruction-change`, `unicode-payload` | fails | pass |
| `tags`: Hidden text in 30 tag characters | `unicode-payload` | `unicode-payload` | fails | pass |
| `zero-width-run`: A run of 8 zero-width characters in code | `invisible-unicode` | `invisible-unicode` | passes | pass |

## variants

| Case | Expected | Actual | Gate | Result |
| --- | --- | --- | --- | --- |
| `amend-alias`: Near miss: a developer script that amends the last commit and force-pushes it | none | none | passes | pass |
| `dynamic-eval-call`: eval through Function.prototype.call in a build config | `dynamic-code` | `dynamic-code` | passes | pass |
| `dynamic-folded-eval`: eval by a key that a sum of strings builds, on globalThis | `dynamic-code` | `dynamic-code` | passes | pass |
| `dynamic-global-alias`: require put on an alias of globalThis | `dynamic-code` | `dynamic-code` | passes | pass |
| `dynamic-local-require`: Near miss: a local named require in a function of the config | none | none | passes | pass |
| `dynamic-reassigned-module`: child_process bound by a later assignment and called by a string key | `dynamic-code` | `dynamic-code` | passes | pass |
| `dynamic-require-call`: Near miss: require through call with a plain module name | none | none | passes | pass |
| `dynamic-value-limit`: child_process hidden behind 16 earlier values of the same name | `dynamic-code` | `dynamic-code` | passes | pass |
| `dynamic-window-key`: Near miss: a computed key on window in a browser config | none | none | passes | pass |
| `glassworm`: GlassWorm: a payload in variation selectors that a short decoder runs | `unicode-payload` | `unicode-payload` | fails | pass |
| `polinrider-config`: PolinRider: a loader after spaces in a build config, and the push script hidden by .gitignore | `dynamic-code`, `history-rewrite-script`, `padded-code` | `dynamic-code`, `history-rewrite-script`, `padded-code` | fails | pass |
| `polinrider-os-task`: PolinRider: a folder-open task with a command for each OS, the bad one only on Linux | `editor-task-command`, `suspicious-command` | `editor-task-command`, `suspicious-command` | fails | pass |
| `polinrider-renamed-rewrite`: PolinRider: the push script under a new name, hidden by .gitignore | `history-rewrite-script` | `history-rewrite-script` | fails | pass |
| `polinrider-rewrite`: PolinRider: a script that amends the last commit, keeps its date and force-pushes it | `history-rewrite-script` | `history-rewrite-script` | fails | pass |
| `polinrider-task`: PolinRider: a hidden folder-open task runs node on a fake font | `disguised-script`, `editor-autorun-enabled`, `editor-task-command`, `suspicious-command` | `disguised-script`, `editor-autorun-enabled`, `editor-task-command`, `suspicious-command` | fails | pass |

Total: 123 cases, 120 pass, 0 fail, 3 known misses.
