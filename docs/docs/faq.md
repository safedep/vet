---
sidebar_position: 20
title: 🙋 FAQ
---

# 🙋 FAQ - Vet

### How do I disable the stupid banner?

- Set environment variable `VET_DISABLE_BANNER=1`

### Something is wrong! How do I debug this thing?

- Run without the eye candy UI and enable log to file or to `stdout`.

Log to `stdout`:

```bash
vet scan -D /path/to/repo -s -l- -v
```

Log to file:

```bash
vet scan -D /path/to/repo -l /tmp/vet.log -v
```
