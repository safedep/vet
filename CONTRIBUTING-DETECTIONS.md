# Contribute a detection

The unit of a detection contribution is a technique, not an indicator. A technique is a Go detector,
the MITRE ATT&CK ids that it maps to, and the evasion cases that it must catch. vet does not take a
list of string signatures, such as a campaign marker or a hash, because an attacker changes them in
one release.

## Steps

1. **Write the detector.** Add a control to a control plugin under `internal/plugins/controls/`, or a
   new plugin. Read the shape of the file, not one string of one sample. Describe the control in
   `Controls()`. A new detection starts as a control that warns. It has no `Attack: true`.
2. **Add the evasion cases.** Add cases to a group of [test/evasion/cases](test/evasion/cases), or start
   a group. Add the hits that the detector must catch, and the shapes that an attacker can change to
   get past it. Add near misses too. A near miss is a clean file that looks like the attack and gives no attack finding.
   [test/evasion/README.md](test/evasion/README.md) has the case format.
3. **Register the technique.** Add a `Technique` to [internal/technique](internal/technique) with its
   name, its MITRE ATT&CK ids and its corpus groups. Name it in the `Technique` field of the control
   info.
4. **Run the checks.** Run `make check`. `TestTechniqueRegistry` fails when the technique has no ATT&CK
   id, no case that it must catch, or no near miss. `TestEvasionCorpus` fails when a case that passed
   starts to fail. Run `make golden` and commit the diff of `test/evasion/coverage.md` and
   `docs/controls.md`.
5. **Read the false-positive run.** The pull request runs the
   [false-positive run](test/falsepositive/README.md) on clean projects. It is advisory. Put its
   table in the pull request body. A detection outside the `paths` of `false-positive.yml` needs its
   folder in that list. A control becomes an attack control, with `Attack: true`, only in
   a change that shows a clean run.

## Rules for fixtures

- Use synthetic fixtures only. Do not copy a live payload. Use a host such as
  `https://x.example/...` and a payload such as `console.log(1)`.
- A fixture that holds a credential URL uses a reserved host, such as `example.com` or a name under
  `.invalid`. The secret scan of a pull request then does not fail on it.

## Out of scope

- vet does not load a detector at run time. A technique is Go code in the binary.
- A policy rule tunes a finding by its control id, family or severity. A technique needs no policy
  option of its own.
