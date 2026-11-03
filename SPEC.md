# CertAgent — Specification of what is built

Status as of **2026-10-31**, after the demo-case-3 change (see §2). This file describes everything implemented so far, the decisions
behind it, how the pieces behave, and what is still open. `CLAUDE.md` is the plan and the rules; this file is
the as-built record. Where the two differ, the difference is called out in §12.

---

## 1. Summary

CertAgent is a Spring Boot service that checks the TLS certificate served by each configured endpoint,
works out what is wrong in deterministic code, lets Muse Spark (Meta Model API; or Muse Glimmer via local Ollama) decide what to do
through three tools, applies changes only if policy allows, verifies the result strictly, and rolls back
automatically if the change did not take. Every step is appended to a timeline (`data/events.jsonl`) exposed
over a REST API.

| Area | State |
|---|---|
| Docker lab (step-ca + nginx, init/break scripts) | Written, **not yet run** (Docker not installed) |
| Endpoint scanner + risk rules | Done, tested against real local TLS servers |
| Trust bundle (JVM roots + lab root) | Done |
| Event log (memory + JSONL) | Done, tested |
| Policy gate (ALLOW / DRY_RUN / DENY, action budget) | Done, tested |
| Tools: `verify_handshake`, `renew_certificate`, `rollback` | Done, tested |
| ACME client (acme4j, http-01 via webroot) | Done, **not yet run against step-ca** |
| nginx installer (backup, install, reload, restore) | Done, tested with a file-backed TLS server |
| Agent runner (scan → diagnose → model → outcome → summary → notify) | Done, tested with a scripted model |
| Webhook notifier | Done, not tested against a real webhook |
| REST API | Done, smoke-tested on a running app |
| Real Glimmer run | **Not done** (Ollama not installed) |
| Timeline UI (`static/index.html`) | Done, checked in a browser with sample events (desktop, 375px, light/dark, live state); not yet seen with a real run |
| README | Done |
| Public repo | Pushed to github.com/eversamurai/meta-certificate-solver-hc (`main`) |
| Demo video | **Not started** |

Totals: 14 Java files in `src/main`, 8 in `src/test`, ~2,470 lines of Java, **23 tests, all passing**.

---

## 2. Change history

| Commit | What changed |
|---|---|
| — | `CALUDE.md` renamed to `CLAUDE.md` so Claude Code loads it automatically. Git repo initialised on `main`. |
| `2b91299` | Maven project with wrapper, Spring Boot 3.5 skeleton, typed configuration (`AgentProperties`), data records (`CertRecord`, `Event`), `application.yml` with two targets and a lab/prod policy, docker lab (`docker-compose.yml`, `nginx.conf`, `init.sh`, `break.sh`, `lib.sh`), `.gitignore`, `.gitattributes`. `CLAUDE.md` commands updated to `./mvnw`, the `:8444` prod site and the `notification` key. |
| `39c4c8d` | `TrustConfig` (trust bundle) and `EndpointScanner` with all risk rules; test PKI helper and 10 scanner tests using real handshakes. Optional config blocks get defaults. |
| `acb3fa4` | `EventLog`, `PolicyGate`, `CertTools` (verify real, renew/rollback gated but stubbed), `CertAgentRunner` with system prompt, `Notifier`, `EventsController`; scripted fake model for tests; context-load test. Fixed two bugs found by a smoke run (§11). |
| `1d750ac` | `AcmeClient` and `NginxInstaller`; real renew flow with automatic rollback; `rollback` tool restores the latest backup; new outcome **Failed safely**; file-backed TLS server for tests; 6 tool tests. |
| `190a21d` | This SPEC.md. |
| `f948dd6` | Demo case 3 now breaks the nginx reload instead of the ACME URL: `conf.d/` include + mount, `break.sh reload` (config that fails `nginx -t`), `init.sh` clears it, reloads run `nginx -t` first (agent and scripts), ROLLBACK events record whether the endpoint serves the backup again. CLAUDE.md §6/§10 updated. |
| `e53c40c` | Timeline UI `static/index.html` (§7.11). `.claude/launch.json` (local preview config) git-ignored. |
| after `e53c40c` | Pushed to the public repo. README.md (problem, architecture, demo scenarios, run steps, config, API, tests, roadmap). |

---

## 3. Toolchain and environment

| Item | Version / note |
|---|---|
| Java | Source/target **21**; built and tested on the installed **JDK 23.0.1** (`C:\Program Files\Java\jdk-23.0.1`, not on PATH — set `JAVA_HOME`) |
| Build | Maven **3.9.16** via the wrapper (`./mvnw`, `mvnw.cmd`); no global Maven needed |
| Spring Boot | **3.5.16** |
| Spring AI | **1.1.8** (`spring-ai-starter-model-ollama`) |
| ACME | **acme4j-client 3.5.1** (brings BouncyCastle 1.80, also used by tests) |
| Lab images | `smallstep/step-ca:0.30.2`, `nginx:1.30-alpine` |
| Not installed on the dev machine | Docker Desktop, Ollama |

Dependencies and why (as required by `CLAUDE.md` §8):
- `spring-boot-starter-web` — REST API and, later, the static timeline page.
- `spring-boot-starter-validation` — fail fast on a broken `application.yml`.
- `spring-ai-starter-model-ollama` — the model and `@Tool` support.
- `acme4j-client` — ACME renewal.
- `spring-boot-starter-test` — JUnit 5 + AssertJ.

No other dependencies were added.

---

## 4. Repository layout

```
CLAUDE.md                     rules and plan for any agent working here
SPEC.md                       this file
pom.xml, mvnw, mvnw.cmd, .mvn/wrapper/
lab/
  docker-compose.yml          step-ca (ACME) :9000 + nginx: demo.lab :8443 (lab), shop.prod :8444 (prod), http :8080
  nginx/nginx.conf            port 80 serves ACME challenges; 443 = demo.lab; 8444 = shop.prod
  lib.sh                      shared helpers (compose wrapper, issue from CA, reload nginx)
  init.sh                     start/reset lab, export root CA, issue healthy certs, start nginx
  break.sh                    expiring | untrusted | weak
src/main/java/dev/certagent/
  CertAgentApplication.java   @EnableScheduling @EnableAsync, binds AgentProperties
  config/AgentProperties.java typed view of certagent.* (records), policy decision logic
  config/TrustConfig.java     TrustBundle(SSLContext, X509TrustManager) = JVM roots + extra roots
  model/CertRecord.java       one observed cert + computed risk
  model/Event.java            one timeline entry
  scan/EndpointScanner.java   scanAll(), scan(target), verify(host, port, sni), risk rules
  acme/AcmeClient.java        issue(domains) via http-01 → Issued(chainPem, keyPem, leaf)
  exec/NginxInstaller.java    backup(), latestBackup(), install(), reload(), restore()
  policy/PolicyGate.java      decide(runId, tool, target, reasoning) → ALLOW | DRY_RUN | DENY
  tools/CertTools.java        the three @Tool methods and the renew/rollback flow
  agent/CertAgentRunner.java  the cycle, system prompt, outcome derivation, triggers
  agent/Notifier.java         webhook summary
  store/EventLog.java         append-only timeline, memory + JSONL
  web/EventsController.java   /api/events, /api/inventory, /api/status, POST /api/run
src/main/resources/static/index.html   timeline UI (single file, no framework)
src/main/resources/application.yml
src/test/java/dev/certagent/  see §10
```

Ignored by git: `target/`, `data/`, `lab/certs/`, `lab/webroot/`, `*.pem *.key *.crt *.jks *.p12`, IDE files.
`.gitattributes` forces LF for `*.sh` and `mvnw` so the scripts run in containers and Git Bash.

---

## 5. Lab

### 5.1 Services
- **ca** — step-ca initialised by the image's env vars: name "CertAgent Lab CA", DNS names `localhost,ca`,
  JWK provisioner `admin`, ACME provisioner `acme` enabled. Data in volume `ca-data`. Health check
  `step ca health`. ACME directory: `https://localhost:9000/acme/acme/directory`.
- **nginx** — network aliases `demo.lab` and `shop.prod` so the CA can reach `http://demo.lab/` for http-01.
  Mounts `nginx.conf`, `lab/certs` → `/etc/nginx/certs`, `lab/webroot` → `/var/www/acme` and `lab/conf.d` →
  `/etc/nginx/conf.d` (included by `nginx.conf`, normally empty), all read-only.
  - `:80` (host 8080): serves `/.well-known/acme-challenge/` from the webroot; everything else returns 200 text.
  - `:443` (host 8443): `demo.lab`, cert `server.crt` / `server.key`.
  - `:8444` (host 8444): `shop.prod`, cert `prod.crt` / `prod.key`.

### 5.2 Scripts
All scripts set `MSYS_NO_PATHCONV=1` so Git Bash on Windows does not rewrite container paths, and use
`docker compose exec -T` (no TTY).

| Script | Effect |
|---|---|
| `init.sh` | Remove any `conf.d/*.conf` → start CA (wait healthy) → copy root to `lab/certs/root_ca.crt` → issue 24h cert for `demo.lab` and **4h** cert for `shop.prod` (inside the 6h warn window, so prod always has something for the agent to want to fix) → (re)start nginx |
| `break.sh expiring` | Lab-CA cert valid **10 minutes** (step-ca's minimum lifetime is 5m) → CRITICAL |
| `break.sh untrusted` | Self-made "Rogue Corp Root" signs a 30-day `demo.lab` cert → CRITICAL |
| `break.sh weak` | **RSA 1024** cert signed directly with the lab intermediate key (the CA API refuses keys under 2048), bundled with the intermediate → CRITICAL |
| `break.sh reload` | Writes `conf.d/zz-legacy.conf`, an upstream with an invalid parameter, so `nginx -t` fails and every reload is refused while the running workers keep serving. Checks that `nginx -t` really fails. Used after `weak` for demo case 3 |
| `break.sh hostname` | Third site **accounts.lab** (env `lab`, host port 8445, `accounts.{crt,key}`, issued 24h by `init.sh`): installs a lab-CA cert issued for `legacy-accounts.lab`, so the chain is trusted but the hostname check fails → CRITICAL. Demo case 4; the system prompt's rule 2 lists a SAN mismatch as fixed by `renew_certificate` (without that, Spark verified and stopped at **Unresolved**) |

`expiring`, `untrusted` and `weak` rewrite `lab/certs/server.{crt,key}` and reload nginx. Every reload, in the scripts
and in the agent, runs `nginx -t -q && nginx -s reload`: a bare `nginx -s reload` exits 0 even when nginx rejects
the config, which would hide exactly the failure demo case 3 depends on.

---

## 6. Configuration (`certagent.*`)

Bound into `AgentProperties` (immutable records, validated). Shipped values:

| Key | Value | Notes |
|---|---|---|
| `targets[]` | `demo.lab` (env `lab`, localhost:8443) and `shop.prod` (env `prod`, localhost:8444) | each has `name, host, port, sni, env, domains?, cert-path, key-path`; `domains` defaults to the SNI name |
| `policy.dry-run` | `false` | `true` turns every ALLOW into DRY_RUN |
| `policy.max-actions-per-run` | `10` | counts every tool call, including verifies |
| `policy.environments` | lab: all three tools ALLOW; prod: verify ALLOW, renew/rollback DENY | tool names are written as `"[verify_handshake]"` — Spring strips `_` from bare map keys |
| `risk.warn-within` / `critical-within` | `6h` / `30m` | hours, not weeks, because the lab CA issues 24h certs; defaults if absent are `14d` / `3d` |
| `risk.min-rsa-bits` / `min-ec-bits` | `2048` / `256` | |
| `risk.forbidden-sig-algs` | default `SHA1withRSA, MD5withRSA, SHA1withECDSA` | |
| `acme.directory-url` | `https://localhost:9000/acme/acme/directory` | |
| `acme.account-key` | `data/acme-account.pem` | created on first use |
| `acme.webroot` | `lab/webroot` | challenge files written here |
| `acme.timeout` | default `60s` | per authorization/order wait |
| `trust.extra-roots` | `lab/certs/root_ca.crt` | missing file → warning, app still starts |
| `install.backup-dir` | `data/backups` | |
| `install.reload-command` | `docker compose -f lab/docker-compose.yml exec -T nginx sh -c "nginx -t -q && nginx -s reload"` | run from the working directory; config test first so a rejected config fails the reload |
| `install.settle-after-reload` | default `3s` | wait before verifying |
| `notification.webhook-url` | `${NOTIFY_WEBHOOK:}` | named `notification`, not `notify` (§11) |
| `model` | `${CERTAGENT_MODEL:spark}` | `spark` (Muse Spark, Meta Model API) or `glimmer` (local Ollama) |
| `spark.api-key` | `${MODEL_API_KEY:}` | Meta Model API key, required for `spark`; keep a local one in git-ignored `config/application.yml` |
| `spark.base-url` / `model` / `reasoning-effort` / `timeout` | `https://api.meta.ai` / `${MUSE_SPARK_MODEL:muse-spark-1.3}` / `low` / `120s` | OpenAI-compatible Chat Completions (`/v1/chat/completions`); at most 2 attempts per call |
| `schedule.cron` / `run-on-startup` | `0 0 6 * * *` / `true` | |
| `event-log` | `data/events.jsonl` | |

Spring AI: `spring.ai.ollama.base-url=${OLLAMA_URL:http://localhost:11434}`,
`chat.options.model=${OLLAMA_MODEL:muse-glimmer}`, `temperature=0.1`. Server port **8088**.

---

## 7. Components

### 7.1 TrustConfig
Builds one `TrustBundle(SSLContext, X509TrustManager)` from the JVM's default accepted issuers plus each
readable file in `trust.extra-roots`. Used by the scanner to judge chains and by the ACME client to talk to
step-ca. Nothing changes JVM-wide SSL defaults.

### 7.2 EndpointScanner
- **Handshake** with a capture-all trust manager, 5s connect/read timeout, SNI set unless the name is an IP.
  This records what a broken endpoint actually serves instead of just failing.
- **Trust** is then judged separately: `checkServerTrusted(chain, "UNKNOWN")` against the bundle
  (`UNKNOWN` is what JSSE uses for TLS 1.3 and checks the leaf is fit for server signatures).
- **Hostname**: exact match or single-label wildcard against dNSName/iPAddress SANs (no CN fallback).
- **Records**: subject, issuer, SANs, validity, SHA-256 fingerprint (hex), key type/bits (RSA modulus,
  EC order), signature algorithm, chain length, trusted, hostnameMatches, handshakeError.
- **`verify(host, port, sni)`** → `Verification(ok, summary, cert)`; `ok` = handshake worked and no CRITICAL
  finding. Summary on success: `trusted chain, hostname matches, expires <instant> (in 23h59m)`; on failure,
  the risk reasons joined by `; `.

Risk rules (pure function `assess`, model never involved):

| Finding | Level | Reason text starts with |
|---|---|---|
| Handshake/connection failed | CRITICAL | `handshake failed: <Exception>: …` |
| Past notAfter | CRITICAL | `expired 1h ago (notAfter …)` |
| Before notBefore | CRITICAL | `not yet valid` |
| Less than `critical-within` left | CRITICAL | `expires in 9m (critical window 30m)` |
| Less than `warn-within` left | WARN | `expires in 3h (renew window 6h)` |
| Chain not trusted | CRITICAL | `chain does not validate to a trusted root (issuer …): …` |
| Hostname not in SANs | CRITICAL | `hostname demo.lab not in certificate SANs […]` |
| RSA below minimum | CRITICAL | `weak key: RSA 1024 bits (minimum 2048)` |
| EC below minimum | WARN | `weak key: EC … bits` |
| Forbidden signature algorithm | CRITICAL | `forbidden signature algorithm …` |

Level is the worst finding; CRITICAL reasons are listed before WARN ones.

### 7.3 EventLog
In-memory list plus one JSON line per event appended to `event-log`; reloaded on startup so the timeline
survives restarts. `append`, `since(seq)`, `forCase(runId, target)`, and `details(k, v, …)` (a map builder that
skips nulls). Every append is also logged.

### 7.4 PolicyGate
`decide(runId, tool, target, reasoning)`:
1. Counts the call against `max-actions-per-run` for that run; over budget → DENY.
2. Otherwise looks up `environments[env][tool]`; missing env or tool → **DENY**; dry-run downgrades ALLOW.
3. Appends a POLICY event with tool, decision, env, badge (`AUTO · lab`, `DRY-RUN · lab`,
   `APPROVAL NEEDED · prod`), reason, and the model's reasoning.

### 7.5 CertTools — the tool contract
Each tool takes `target` (the target name) and `reasoning` (one paragraph), plus Spring AI `ToolContext`
carrying `runId`. Unknown target → `ERROR: unknown target … Known targets: […]`.
Every call goes through PolicyGate first. Results start with a fixed word the system prompt depends on.

| Tool | Possible results |
|---|---|
| `verify_handshake` | `OK <target>: <summary> \| served: <description>` · `FAIL <target>: <reasons> \| served: …` · `DENIED: …` |
| `renew_certificate` | `SUCCESS: renewed and installed … \| before: …` · `FAILED: ACME issuance … Nothing was changed …` · `FAILED: could not back up …` · `FAILED: the new certificate did not pass verification (…). Automatically rolled back to backup <id>; endpoint now: …` · `DENIED: … A human must approve this change. Do not retry.` · `DRY-RUN: would renew …; nothing was changed.` |
| `rollback` | `SUCCESS: restored backup <id> …` · `FAILED: restored backup <id> …; endpoint now: <reasons>` (restored cert itself is bad) · `FAIL: no backup exists …` · `ERROR: cannot read backups …` · `DENIED` · `DRY-RUN` |

**Renew flow (ALLOW):**
1. `verify` → "before" snapshot.
2. `AcmeClient.issue(domains)`. On failure: APPLY event `changed=false, stage=issue`; return; **nothing touched**.
3. `NginxInstaller.backup(target)`. On failure: APPLY `changed=false, stage=backup`; return.
4. `install` (key then cert, each temp-file + atomic move) → APPLY `changed=true` with backupId, new fingerprint,
   before snapshot → `reload`.
5. `verify` again; success requires **ok AND served fingerprint == new fingerprint**. VERIFY event
   `phase=after` with `before` and `served` snapshots (the before/after pair for the UI).
6. Any exception or failed check after step 3 → **automatic restore** (restore files, reload, verify) and a
   ROLLBACK event with backupId, reason, error, backupFingerprint, servesBackup, ok, served. This happens inside
   the tool, never at the model's discretion (CLAUDE.md invariant 4).
   The proof of a good rollback is **`servesBackup`**: the endpoint serves the backed-up certificate's
   fingerprint again. If the reload after restoring also fails (demo case 3: a config `nginx -t` rejects),
   nginx never loaded the new cert, so it still serves the backup; the event says so instead of reading as a
   second failure.

### 7.6 AcmeClient
acme4j `Session` with a custom `GenericAcmeProvider` whose `HttpConnector` builds its `HttpClient` with the
trust bundle's `SSLContext`. Flow: account (key in `data/acme-account.pem`, created once, ToS agreed) → order
for the domains → for each pending authorization write `webroot/.well-known/acme-challenge/<token>`, trigger,
`waitForCompletion(timeout)` → `waitUntilReady` → new **RSA 2048** domain key → `execute` →
`waitForCompletion` → full chain PEM + key PEM. Challenge files are deleted in `finally`.

### 7.7 NginxInstaller
- `backup` copies the target's cert/key into `backup-dir/<target>/<yyyyMMdd-HHmmss-SSS>/{cert,key}.pem`.
- `latestBackup` picks the newest folder by name.
- `install`/`restore` write via `<file>.certagent.tmp` + `ATOMIC_MOVE`, key first.
- `reload` runs `reload-command`, 30s timeout, fails with exit code and output, then sleeps `settle-after-reload`.
- Targets without `cert-path`/`key-path` are refused.

### 7.8 CertAgentRunner
Triggers: `ApplicationReadyEvent` (if `run-on-startup`), `@Scheduled(cron)`, `POST /api/run`. An
`AtomicBoolean` allows one cycle at a time; each cycle runs on a virtual thread.
Run id: `run-yyyyMMdd-HHmmss-xxxx` (random hex suffix, §11).

Cycle:
1. SCAN (run-level) → `scanAll()` → store as current inventory.
2. Per target: SCAN event (observed cert), DIAGNOSE event (level + reasons).
   - **OK → DONE "Healthy"; the model is not called.**
   - Otherwise PLAN event ("asking <model> to decide", includes the prompt) → one ChatClient call with the
     tools and `toolContext{runId}`. On exception: ERROR event and one retry with the error appended.
   - Outcome derived **from the timeline**, then DONE event with outcome and the model's final text.
3. Run summary: if every target is healthy, a code-written line; otherwise the model is asked for exactly
   3 sentences from the facts, falling back to the code line on failure.
4. Run-level DONE event (summary, counts, outcomes) → Notifier → `PolicyGate.endRun`.

Outcome rules (first match wins):

| Outcome | Condition in the case's events |
|---|---|
| Rolled back | any ROLLBACK |
| Fixed | an APPLY with `changed=true` and the last VERIFY `ok=true` |
| Needs approval | a POLICY DENY for renew/rollback |
| Dry run | a POLICY DRY_RUN for renew/rollback |
| Failed safely | an APPLY with `changed=false` |
| Unresolved | anything else |
| Healthy | set directly when the scan found nothing wrong |

Case prompt sent to the model:
```
Case: target <name> (env: <env>) at <host>:<port>, SNI <sni>
Risk: <LEVEL>
Findings:
- <reason>
Served: subject=…, issuer=…, sans=[…], notAfter=…, key=RSA 2048, sigAlg=…, trusted=…, hostnameMatches=…
```

System prompt (`CertAgentRunner.SYSTEM`) — rules in short: verify first; least invasive fix (renew covers
expiring, expired, untrusted, weak key); reasoning on every call naming the evidence; read results by first
word (OK/SUCCESS, FAIL/FAILED, DENIED → don't retry, DRY-RUN, ERROR → at most one retry); verify again after a
change; no invented targets/tools/results; max 5 tool calls per case; finish with 2–3 sentences.

**Model selection (`config/ModelConfig.java`), changed 2026-11-02.** `certagent.model` picks the one model that
decides, calls tools and writes the run summary:
- **`spark` (default): Muse Spark on Meta Model API.** Built with Spring AI's OpenAI client (`spring-ai-openai`,
  without its auto-configuration, so Ollama's auto-configured model and the single-model `ChatClient.Builder`
  are untouched) against `https://api.meta.ai/v1/chat/completions`. Uses `reasoning_effort: low` (hidden
  thinking only; the `reasoning` tool argument is still written in full), `temperature: 0.1`, 10s connect /
  120s read timeout per call, at most 2 attempts. Startup fails with a clear message if no key is set.
  - Verified live (`SparkLiveTest`, runs only when `MODEL_API_KEY` is set): real system and case prompts with
    stand-in tools. Spark called `verify_handshake` → `renew_certificate` → `verify_handshake` with a full
    reasoning sentence on each call, and answered in 3 sentences, in **14.9 s** for the whole case. Glimmer took
    12–21 min per run on the Nov 1 hardware.
  - What leaves the machine: case prompts (target, endpoint, certificate details, findings), tool results the
    model reads, and the summary facts. Never certificate files or private keys.
- **`glimmer`: Muse Glimmer through local Ollama** (`spring.ai.ollama.*`). Nothing leaves the network.

`AgentModel(chatModel, name, hosting)` is passed to the runner; the timeline label is `<name> · <hosting>`
(`muse-spark-1.3 · Meta Model API` or `muse-glimmer:30b · local`).

**Run summary.** The active model writes it from `- <target>: <outcome> — <closing note>` lines: at most 3 short
sentences and 45 words, what a human must do first, no dates, key types or fingerprints, whitespace collapsed to one
line (real runs: 33–36 words, down from about 90). No
tools attached. An empty answer or a failure appends a run-level ERROR (`summary by … failed: …; using the
rule-based line`) and the code-written line (`N target(s) checked: …`) is used; it is also used when every
target is healthy. The DONE event's `summaryBy` records which one wrote it, and the timeline shows
"summary by …" next to the pinned summary.

The earlier step on this branch (Spark writing only the summary while Glimmer decided, `SparkSummarizer`) was
replaced by this.

### 7.9 Notifier
If `notification.webhook-url` is set, POSTs `{"text": summary, "runId": …, "counts": {…}}` (Slack-compatible)
and records NOTIFY; a failure is recorded as ERROR and does not fail the run.

### 7.10 REST API (port 8088)

| Method | Path | Returns |
|---|---|---|
| GET | `/api/events?since=<seq>` | events with `seq > since` (UI polls with the last seq it has) |
| GET | `/api/inventory` | `CertRecord[]` from the latest scan |
| GET | `/api/status` | `{running, lastRunId, model, hosting}` |
| POST | `/api/run` | `202 {runId}` or `409 {error}` if a run is in progress |

### 7.11 Timeline UI (`src/main/resources/static/index.html`)
One self-contained file served at `http://localhost:8088/`: vanilla HTML/CSS/JS, no framework, no build step,
**no external requests** (system fonts only, so nothing leaves the network). Follows the system light/dark
setting; no theme toggle (CLAUDE.md §9). Layout works down to 375px wide without horizontal scrolling.

Data: polls `/api/events?since=<lastSeq>` every 1.5s and `/api/status` every 2s; **Run cycle now** posts
`/api/run` and is disabled while a run is in progress. All grouping and state is derived in the browser from
events, so the page needs no other endpoint.

Layout, in CLAUDE.md §9 priority order:
- **Top bar:** name, tagline, `<model> · local` chip, idle/running status, Run cycle now.
- **Pinned run summary:** latest run id and time, the model's 3-sentence summary (or "Run in progress"),
  and outcome count pills.
- **Runs, newest first**, each with a header (time, run id, target count, run-level error if any) and one
  **case card per target** (grouped by `runId + target`):
  - Header: target · env (prod in amber) · short fault label (from the first reason: "untrusted issuer",
    "weak key", "expires in 3h", …) · outcome pill (Fixed green, Rolled back amber, Needs approval violet,
    Failed safely blue, Healthy green, Dry run grey, Unresolved red; "In progress" while live).
  - **Stepper** Observed → Diagnosed → Decided → Policy → Applied → Verified, each with a colour and a short
    sub-label (endpoint, risk level, chosen tool, policy badge, installed/reverted/blocked, handshake result).
    Healthy cases mark the last four as "not needed" and stay compact.
  - **Decision as the headline:** the model's `reasoning` for the change tool (or its latest reasoning) in
    large text, then `model → tool` and the policy badge (`AUTO · lab`, `APPROVAL NEEDED · prod`, `DRY-RUN`).
  - **Before/after proof:** two panels with issuer, key, expiry (with relative time), short fingerprint and
    the reasons. Red = handshake fails, amber = passes with warnings, green = clean. "Before" comes from the
    renew APPLY's `before` snapshot (else the first VERIFY, else the scan); "After" from the post-change
    VERIFY, or "After rollback" from the ROLLBACK event. A denied case shows one "Current — left unchanged"
    panel.
  - **Rollback as a reversal:** `ROLLBACK  old fp → new fp (struck through) ↩ backup fp restored`, plus the
    reason (e.g. nginx's `[emerg]` line). When the restored fingerprint equals the original, the after panel
    says "Same certificate as before the change — the site stayed up on it."
  - **Failed safely:** "Stopped before any change: <error>".
  - The model's closing 2–3 sentences, then a collapsed list of every raw event for the case.
- **Live state:** while a run is in progress, the first unfinished step of each open case pulses, and
  "<model> is reasoning…" shows under the latest thought. Verifying counts as gathering evidence, so
  "Decided" keeps pulsing until a change tool is chosen.
- Scanner reasons are shown without their Java exception tail (`…: SunCertPathBuilderException: …`); the
  full text stays in the raw event list and in what the model reads.

Not built on purpose (CLAUDE.md §9): approval buttons, history charts, theme toggle.

---

## 8. Data model

`CertRecord(target, env, host, port, sni, observedAt, subject, issuer, sans, notBefore, notAfter,
fingerprintSha256, keyType, keyBits, sigAlg, chainLength, trusted, hostnameMatches, handshakeError,
risk{level: OK|WARN|CRITICAL, reasons[]})`

`Event(seq, ts, runId, target|null, kind, message, details{})` — `target=null` means run-level.

| Kind | Emitted by | `details` keys |
|---|---|---|
| SCAN | runner (run) | model, targets |
| SCAN | runner (target) | env, endpoint, sni, issuer, notAfter, fingerprint, key, trusted, handshakeError |
| DIAGNOSE | runner | level, reasons |
| PLAN | runner | model, prompt |
| POLICY | PolicyGate | tool, decision, env, badge, reason, reasoning |
| VERIFY | verify_handshake | ok, reasoning, served{ok, fingerprint, issuer, notAfter, key, reasons} |
| VERIFY | renew (post-change) | ok, phase=`after`, before{…}, served{…} |
| APPLY | renew | stage (`issue`/`backup`/`install`), changed, error?, ca?, backupId?, newFingerprint?, before? |
| ROLLBACK | renew / rollback | backupId, reason, error?, backupFingerprint, servesBackup, ok, served{…} |
| ERROR | various | (message only) |
| NOTIFY | Notifier | (message only) |
| DONE | runner (target) | outcome, summary (model's final text) |
| DONE | runner (run) | summary, summaryBy (`<model> · <hosting>` or `rule-based`), counts{outcome: n}, outcomes{target: outcome} |

---

## 9. CLAUDE.md invariants — how each is enforced

| Invariant | Where |
|---|---|
| 1. Model never touches files, sockets, processes | Model only gets the three `@Tool` methods; all I/O is in scanner/ACME/installer |
| 2. Risk computed in code | `EndpointScanner.assess`; model receives findings as text |
| 3. Every tool call through PolicyGate | First statement of every tool after target lookup |
| 4. Backup before change, strict verify after, auto-rollback inside the tool | `CertTools.renew` / `restore` |
| 5. Every tool has `reasoning`, recorded on the timeline | `@ToolParam reasoning` → POLICY (and VERIFY) details |
| 6. Nothing leaves the network (except the model call with `spark`) | `ModelConfig`: Spark gets case prompts and tool results only; `glimmer` = Ollama on localhost; ACME to the lab CA; optional webhook |

---

## 10. Tests (23, all passing)

| Class | Count | Covers |
|---|---|---|
| `CertAgentApplicationTest` | 1 | Full Spring context starts from `application.yml` (catches wiring bugs) |
| `config/AgentPropertiesTest` | 4 | Binding of targets/risk/install; policy lookup; unknown tool/env → DENY; dry-run only downgrades ALLOW |
| `scan/EndpointScannerTest` | 10 | Real handshakes: healthy, untrusted, weak 1024, expiring (critical/warn), expired, wrong hostname, closed port, verify ok/fail, wildcard rules, duration formatting |
| `tools/CertToolsTest` | 6 | Renew fixes untrusted cert + backup content; CA failure changes nothing; untrusted new cert → auto-rollback; persistent reload failure (demo case 3) → auto-rollback with `servesBackup=true`; `rollback` tool; prod DENY never reaches the CA |
| `agent/CertAgentRunnerTest` | 2 | Full cycle with a scripted model calling real tools over three targets (untrusted/lab, warn/prod, healthy); prompt contents; exact tool results seen by the model; POLICY badges + reasoning; event order; outcomes; counts; JSONL reload. Outcome rules table |

Test helpers: `TestPki` (BouncyCastle root/leaf generation, PEM writers, fixed-cert TLS server),
`FileTlsServer` (serves PEM files from disk, re-read on `reload()` — stands in for nginx),
`ScriptedChatModel` (a `ChatModel` that runs scripted tool calls through the real Spring AI `ToolCallback`s).

Run: `JAVA_HOME="C:\Program Files\Java\jdk-23.0.1" ./mvnw test`.

---

## 11. Problems found and fixed during the build

| Problem | Fix |
|---|---|
| Record component named `notify` doesn't compile (clashes with `Object.notify()`) | Renamed to `notification`; config key `certagent.notification.webhook-url` |
| Spring removes `_` from bare map keys, so `verify_handshake` would bind as `verifyhandshake` | Keys written as `"[verify_handshake]"` in YAML; test asserts lookup by real tool name |
| Healthy 24h lab certs would be flagged by a 14-day renew window | Lab windows set to 6h warn / 30m critical |
| step-ca refuses <2048-bit keys, so `break.sh weak` can't go through the CA API | Signs directly with the intermediate key inside the CA container |
| App failed to start: `EndpointScanner` had two constructors, Spring couldn't choose (unit tests didn't catch it) | `@Autowired` on the public one; added `CertAgentApplicationTest` |
| Two runs in the same second got the same run id, merging their case cards | Random 4-hex suffix on run ids |
| acme4j would otherwise only trust JVM roots, not the lab CA | Custom provider injects the trust bundle's `SSLContext` into acme4j's `HttpClient` |
| `nginx -s reload` exits 0 even when the config is invalid, so a failed reload would look like success | Reloads run `nginx -t -q` first |
| Demo case 3 as planned (bad ACME URL) could never show a rollback | Case 3 now breaks the reload (§12) |

---

## 12. Differences from CLAUDE.md and open decisions

1. **Demo case 3 changed (decided 2026-10-31).** The original plan used a bad ACME URL, but that fails before
   anything is installed, so it can only show **Failed safely**. Case 3 is now `break.sh weak` + `break.sh reload`:
   renewal succeeds, `nginx -t` rejects the config, the reload fails, and the backup is restored automatically
   → **Rolled back**. CLAUDE.md §10 updated to match; covered by `failedReloadIsRolledBackAutomatically`.
2. **Extra outcome "Failed safely"** added beyond CLAUDE.md's Fixed / Rolled back / Needs approval.
3. **Tool arguments are `target` + `reasoning`** (target name), not host/port/sni; the tool looks up the target.
4. **Prod site on port 8444** added to the lab so case 2 has a real endpoint.
5. **Action budget counts verify calls too**, so 10 per run is ~2–3 full cases; may need raising for longer demos.
6. `@EnableAsync` is present as CLAUDE.md specifies but unused; runs use a virtual thread.

---

## 13. Not yet done / not yet verified

- Install Docker Desktop and Ollama; pull Glimmer and set `OLLAMA_MODEL` to its exact tag.
- Run `./lab/init.sh` and each `break.sh` mode for real; confirm http-01 from step-ca to `demo.lab` works.
- First real run against Glimmer: check tool-calling format and whether the prompt rules are followed.
- Timeline UI with a real run (only checked against hand-made sample events so far).
- Demo video, X post.
- Webhook against a real endpoint.

---

## 14. How to run (once Docker and Ollama are installed)

```bash
ollama pull <glimmer tag>
export OLLAMA_MODEL=<glimmer tag>
export JAVA_HOME="/c/Program Files/Java/jdk-23.0.1"
./lab/init.sh
./mvnw spring-boot:run
./lab/break.sh untrusted
curl -X POST localhost:8088/api/run
curl localhost:8088/api/events
```

Reset: `./lab/init.sh` restores the lab; delete `data/` to clear the timeline, backups and ACME account.
