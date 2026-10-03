# vet config get

Print one config value.

## Synopsis

```text
vet config get KEY [-o table|plain|json|jsonl]
```

## Description

`vet config get` prints the effective value of one key on stdout, with no other text, so a script
can read it. `-o json` prints the key, the value and its source. An unknown key exits 2 and names the closest known key.

## Examples

```text
vet config get policy.fail_on
vet config get scan.concurrency -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet printed the value. |
| 2 | The key is not a config key, or the config is not valid. |
