# Contributing

1. Work on lab targets only (`127.0.0.1`, RFC1918, `example.*`). Never add tests hitting public sites.
2. New probes must: use safe payloads, carry timeout, go through `safety.validate_target`,
   emit `Finding` with severity + evidence + remediation + references.
3. Keep runtime deps minimal (`requests` + stdlib). No new network deps without discussion.
4. Run before pushing: `pytest --cov=toolkit -q`, `ruff check src tests`.
5. Do not commit secrets, baselines with real paths, or scan output of third-party sites.
