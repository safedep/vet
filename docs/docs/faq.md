---
sidebar_position: 20
title: 🙋 FAQ
---

# 🙋 FAQ - Vet

### How do I disable the stupid banner?

- Set environment variable `VET_DISABLE_BANNER=1`

### Can I use this tool without an API Key for Insight Service?

- Probably no. All useful data (enrichments) for a detected package comes from
a backend service. The service is rate limited with quotas to prevent abuse.

- Look at `api/insights-v1.yml`. It contains the contract expected for Insights
API. You can perhaps consider rolling out your own to avoid dependency with our
backend.

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
