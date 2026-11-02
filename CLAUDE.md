# CLAUDE.md — CertAgent

Instructions for any coding agent working in this repo. Read fully before touching code.

## 1. What this is

CertAgent is an autonomous TLS certificate operator. It runs on a private network, scans endpoints on a
schedule, diagnoses what is wrong with each served certificate, decides on the right fix, applies it within
an operator-defined policy, verifies the handshake afterwards, and rolls back on its own if the fix did not
take. Every step — including the model's reasoning — is recorded on a timeline.

It is a submission to the **Meta Global AI Developer Hackathon** (Cerebral Valley, Oct 26 – Nov 4 2026),
Indie Developer track, theme **Build for Your World**. Solo builder. The model is **Muse Glimmer**
(Meta's 30B open-weight model) running locally through Ollama. We also target the bonus prizes
*Best Build on Meta Open Weights* and *Best Agentic Use-Case*.

**Hard deadline: Wednesday Nov 4, 9:00 PM ET.** Target: submitted by noon. Deliverables: public GitHub repo,
3-minute demo video showing only work done during the event, submission on the CV platform, X post.

## 2. The one sentence that must stay true

> Monitoring tells you a cert will expire. cert-manager renews certs it owns. CertAgent takes any endpoint,
> figures out what's wrong, fixes it, and proves it — or puts it back.

Every feature either makes that sentence more true or is out of scope. If a change turns the project into a
dashboard, a notifier, or a thin wrapper around a model, it is wrong.

## 3. Judging rubric (design against this)

| Criterion | Weight | What it means for us |
|---|---|---|
| Impact | 30% | Real outages from expired/misconfigured certs; on-call engineers benefit; fits the theme |
| Use of Meta AI tooling | 25% | The model must *reason and decide*, visibly. Reasoning text on the timeline is the proof |
| Technical depth | 20% | x509 handling, ACME, policy gate, verification, rollback — real engineering, not glue |
| Demo | 25% | Working demo that holds up; a video worth watching |

Anti-projects per the organizers (never drift toward these): dashboards as the main feature, basic RAG,
Streamlit apps, personality/job/nutrition/sports analyzers, AI medical advice, education chatbots.

## 4. Locked scope (do not expand without the owner's say-so)

**In:** endpoint TLS scan · risk rules in code · agent loop on Glimmer with three tools
(`verify_handshake`, `renew_certificate`, `rollback`) · ACME renewal against step-ca · nginx install + reload ·
policy gate (allow / dry-run / deny per environment) · strict post-change verification · automatic rollback ·
timeline UI · daily schedule + webhook summary · docker lab with break scripts · README · demo video.

**Out (README "Roadmap" only):** file certs over SSH (PEM/PKCS12/JKS), Kubernetes secrets, internal-CA
reissue, "add missing intermediate" fix, pull-request output, Slack approval buttons, multi-tenant/RBAC,
Vault/HSM, Windows cert store.

If the owner asks for something on the Out list, build it only after the demo video is recorded.

## 5. Architecture

```
targets + policy (application.yml)
        │
        ▼
Scanner (code)  ──▶  Inventory + risk findings (deterministic, no model)
                             │
                             ▼
                   Muse Glimmer via Ollama  ◀──▶  @Tool methods (each takes a `reasoning` arg)
                             │
                             ▼
                   PolicyGate: ALLOW / DRY_RUN / DENY
                             │
                             ▼
             Executors: AcmeClient → NginxInstaller (backup, install, reload)
                             │
                             ▼
             Verifier: strict handshake → keep, else automatic rollback
                             │
                             ▼
             EventLog (JSONL) → /api/events → static/index.html timeline → webhook
```

**Invariants — never break these:**
1. The model never touches files, sockets or processes directly. It only calls tools.
2. Risk assessment is computed in code (`EndpointScanner`), not by the model. The model reasons over findings.
3. Every tool call passes through `PolicyGate` before any executor runs.
4. Every change is preceded by a backup and followed by a strict `verify()`. Failure ⇒ automatic rollback inside
   the tool, not at the model's discretion.
5. Every tool has a `reasoning` parameter and records it on the timeline. The model's words are the product.
6. Nothing leaves the network: no cloud APIs, no telemetry. Ollama on localhost only. The one exception is the
   opt-in `fireworks` profile (owner's decision, 2026-11-01), which sends case prompts to a hosted model; it is
   never the default, and the local run stays the recorded proof for the Open Weights prize (§11).

## 6. Stack and layout

Java 21 · Spring Boot 3.5 · Spring AI (Ollama starter, `@Tool`/`@ToolParam`) · acme4j 3.x · vanilla HTML/JS.
Build with the Maven wrapper (`./mvnw`). No database: `data/events.jsonl` is the store.

```
src/main/java/dev/certagent/
  CertAgentApplication.java      @EnableScheduling @EnableAsync, binds AgentProperties
  config/AgentProperties.java    typed view of certagent.* in application.yml
  config/TrustConfig.java        JVM trust + lab root CA → TrustBundle(SSLContext, X509TrustManager)
  model/CertRecord.java          one observed cert + risk; model/Event.java one timeline entry
  scan/EndpointScanner.java      scanAll(), scan(target), verify(host, port, sni)
  acme/AcmeClient.java           http-01 via webroot; issue(domains) → Issued(certPem, keyPem, …)
  exec/NginxInstaller.java       backup(), install(), reload(), restore()
  policy/PolicyGate.java         decide(tool, target, reasoning) → ALLOW | DRY_RUN | DENY (+ POLICY event)
  tools/CertTools.java           the three @Tool methods
  agent/CertAgentRunner.java     the cycle: scan → diagnose → model → notify; cron + startup + /api/run
  agent/Notifier.java            webhook summary
  store/EventLog.java            append-only, in memory + JSONL
  web/EventsController.java      /api/events?since, /api/inventory, /api/status, POST /api/run
src/main/resources/
  application.yml                targets, policy, risk, acme, trust, install, notification, schedule
  static/index.html              the timeline UI (single file, no framework)
lab/
  docker-compose.yml             step-ca (ACME) + nginx: demo.lab (lab) :8443, shop.prod (prod) :8444, http :8080, CA :9000
  init.sh                        bring up lab, export root CA, issue healthy 24h cert
  break.sh expiring|untrusted|weak|reload   break the site for the demo (reload: config that fails nginx -t)
  nginx/nginx.conf, certs/, webroot/
```

## 7. Commands

```bash
ollama pull <glimmer tag>          # check `ollama list`; set OLLAMA_MODEL to match
./lab/init.sh                      # lab up; writes lab/certs/root_ca.crt (agent trusts it)
./mvnw spring-boot:run              # http://localhost:8088 — runs a cycle at startup, then daily 06:00
./lab/break.sh untrusted           # then click "Run cycle now" or: curl -X POST localhost:8088/api/run
openssl s_client -connect localhost:8443 -servername demo.lab </dev/null | openssl x509 -noout -subject -issuer -enddate
./mvnw -q test                     # before every commit (set JAVA_HOME to a JDK 21+)
```

Env: `OLLAMA_URL` (default http://localhost:11434), `OLLAMA_MODEL`, `NOTIFY_WEBHOOK`.

## 8. Conventions

- Small, deterministic classes; no abstractions for things we have one of. Records for data.
- Tool names are snake_case and stable: `verify_handshake`, `renew_certificate`, `rollback`. Changing them
  changes the prompt contract.
- Tool results are plain strings the model can read, starting with `OK`, `SUCCESS`, `FAIL`, `FAILED`,
  `DENIED`, `DRY-RUN` or `ERROR`. The system prompt depends on these prefixes.
- Events: `Event.Kind` ∈ SCAN, DIAGNOSE, PLAN, POLICY, APPLY, VERIFY, ROLLBACK, NOTIFY, ERROR, DONE.
  Add `details` map entries rather than new kinds where possible. The UI colours by kind.
- Never log or commit private keys. `lab/certs/`, `data/`, `*.pem|key|crt|jks|p12` are gitignored.
- System prompt lives in `CertAgentRunner.SYSTEM`. Edit it deliberately; test with all three break modes.
- Commit messages: imperative, one line, what and why. Commit often — the repo is public from commit 1 and the
  commit history is part of the "new work only" evidence.
- No new dependencies without a reason written in the commit message.

## 9. Timeline UI — what it must communicate

The timeline is where judges see "agent, not monitor." Three things must be visible at a glance:
**what it saw, what it decided and why, what it proved.** Priorities, in order:

1. **Before/after proof** on every change: the pre-change handshake result (red) and the post-change result
   (green) side by side. Store both in the APPLY/VERIFY event `details`.
2. **Case cards**: one card per target per run, header = target · fault · outcome
   (*Fixed / Rolled back / Needs approval*), steps inside as a stepper: Observed → Diagnosed → Decided →
   Policy → Applied → Verified. Group by `runId + target`.
3. **Decision as the headline**: the model's `reasoning` is the main text of the Decided step, not collapsed.
4. **Policy badges** on actions: `AUTO · lab`, `DRY-RUN`, `APPROVAL NEEDED · prod`. Keep a second target in
   `prod` in the config so the agent is seen stopping at policy.
5. Live "reasoning…" pulsing state between the PLAN event and the next event.
6. Rollback drawn as a reversal to the backup fingerprint.
7. Run summary pinned at the top: the model's 3-sentence summary + counts.

Not for the video: approval buttons, history charts, theme toggles.

## 10. Demo scenario (the video is designed backward from this)

Three cases on one screen, ~90 seconds:
1. `break.sh untrusted` → agent diagnoses rogue issuer, explains, renews via ACME, verifies → **Fixed**.
2. A `prod` target with a warning → agent diagnoses, proposes renewal, policy denies → **Needs approval**.
3. `break.sh weak` then `break.sh reload` (leaves a config snippet that fails `nginx -t`) → agent renews via ACME,
   install succeeds, reload is refused → automatic rollback, nginx still serves the old cert → **Rolled back**.
   (A bad ACME URL fails before anything is installed, so it shows **Failed safely**, not a rollback.)

Then 40s on architecture + "runs on Glimmer locally, nothing leaves the network," 20s problem framing up
front. Record the agent run once; narrate over it; never re-run live in the video.

## 11. Known risks and what to do

- **Glimmer tool-calling flaky** → keep `temperature` low, tool descriptions explicit, retry a malformed call
  once with the error fed back. If it is hopeless by Nov 2, document a Fireworks-hosted fallback but keep the
  local run recorded as proof for the Open Weights prize.
- **acme4j API mismatch** → the client was written against the 3.x API (`findChallenge` → Optional,
  `order.execute(keyPair)`, `fetch()`). Fix at the call sites; do not swap libraries.
- **step-ca password path** → `/home/step/secrets/password` per the official image; verify with
  `docker compose exec ca ls /home/step/secrets` if `init.sh` fails.
- **ACME http-01 fails in docker** → the CA must reach `http://demo.lab/` — the `demo.lab` network alias on
  nginx and port 80 serving `/var/www/acme` are what make that work. Check those first.
- **Demo breaks during recording** → the lab is reset by `./lab/init.sh`; delete `data/` to clear the timeline.

## 12. When in doubt

Ask: does this make the sentence in §2 more true, and will it be on screen in the 3-minute video? If no to
either, don't build it before Nov 4.
