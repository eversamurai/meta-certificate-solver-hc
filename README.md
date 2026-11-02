# CertAgent

**Monitoring tells you a cert will expire. cert-manager renews certs it owns. CertAgent takes any endpoint,
figures out what's wrong, fixes it, and proves it — or puts it back.**

CertAgent is a TLS certificate operator for a private network. It scans HTTPS endpoints, works out in plain
code what is wrong with each certificate, and hands the findings to **Muse Glimmer** (Meta's open-weight model,
running locally through Ollama). The model decides what to do and calls tools. A policy gate decides whether
each call may run. Every change is backed up first and strictly verified afterwards. If the verification fails,
the old certificate is restored automatically. Every step, including the model's reasoning, goes on a timeline.

Built for the Meta Global AI Developer Hackathon (Cerebral Valley, Oct 26 – Nov 4 2026), Indie Developer track,
theme *Build for Your World*.

> Status: the agent, tools, policy, rollback and timeline are built and tested (23 tests), and all three demo
> cases have run end to end against the docker lab with Glimmer running locally (see
> [Runs on-prem on open weights](#runs-on-prem-on-open-weights)). See [SPEC.md](SPEC.md) for exactly what exists.

---

## Why

Expired and misconfigured certificates still take down production services. Today's tools split the job:
monitors raise an alert, and renewers handle only the certificates they issued. Neither can look at an arbitrary
endpoint, tell why its certificate is bad, choose a fix, apply it, and *prove* the result. On-call engineers do
that by hand, often at 3 a.m.

## What it does

For each endpoint, on a schedule or on demand:

1. **Observe:** a TLS handshake that records whatever chain the server presents, even an untrusted one.
2. **Diagnose (in code, not by the model):** expired or expiring, untrusted issuer, hostname mismatch, weak key,
   forbidden signature algorithm, unreachable.
3. **Decide:** Glimmer reads the findings and calls tools, explaining its reasoning on every call.
4. **Policy:** each call gets ALLOW, DRY_RUN or DENY based on the environment (for example, lab is automatic and
   prod needs a human).
5. **Apply:** ACME renewal from your CA, backup, install, then a config-tested nginx reload.
6. **Verify:** a strict handshake, which must show the *new* certificate's fingerprint. Otherwise the backup is
   restored automatically, inside the tool, never at the model's discretion.

The model has exactly three tools: `verify_handshake`, `renew_certificate` and `rollback`.

## Architecture

```
targets + policy (application.yml)
        │
        ▼
EndpointScanner ──▶ findings + risk (deterministic, no model)
        │
        ▼
Muse Glimmer via Ollama (localhost) ◀──▶ @Tool methods, each with a `reasoning` argument
        │
        ▼
PolicyGate: ALLOW / DRY_RUN / DENY  (per environment, per tool, action budget per run)
        │
        ▼
AcmeClient (http-01) → NginxInstaller (backup → install → nginx -t && reload)
        │
        ▼
Strict verify (trusted chain + hostname + new fingerprint) → keep, or automatic rollback
        │
        ▼
EventLog (JSONL) → /api/events → timeline UI → webhook summary
```

Rules the code enforces:
- The model never touches files, sockets or processes. It can only call the three tools.
- Every tool call passes through the policy gate before anything runs.
- Every change is preceded by a backup and followed by verification. A failure triggers automatic rollback.
- **Nothing leaves the network:** the model runs on localhost, ACME goes to your own CA, and the UI loads no
  external resources.

## The timeline

`http://localhost:8088` shows one card per target per run:

- **What it saw:** the endpoint, issuer, key and expiry, plus the diagnosis.
- **What it decided and why:** the model's reasoning is the headline, next to the policy badge
  (`AUTO · lab`, `APPROVAL NEEDED · prod`).
- **What it proved:** before and after handshake panels in red and green. A rollback is drawn as a reversal back
  to the backed-up certificate's fingerprint.

## Demo scenarios

| # | Break | What the agent does | Outcome |
|---|---|---|---|
| 1 | `./lab/break.sh untrusted` (cert from "Rogue Corp Root") | verifies, renews via ACME, verifies again | **Fixed** |
| 2 | `shop.prod` inside its renew window | proposes a renewal; policy for `prod` denies it | **Needs approval** |
| 3 | `./lab/break.sh weak` then `./lab/break.sh reload` (1024-bit key, plus an nginx config that fails `nginx -t`) | renews, but the reload is refused, so the previous cert is restored automatically and the site stays up | **Rolled back** |

---

## Runs on-prem on open weights

Every decision in the demo is made by **Muse Glimmer running on one local machine**. There is no cloud API and no
telemetry. Ollama listens on localhost, ACME goes to the lab's own CA, and the endpoints are inside the docker lab.

| | |
|---|---|
| Model | `muse-glimmer:30b`: 27.9B parameters, Q4_K_M quantisation, open weights |
| Runtime | Ollama 0.40.13 on `localhost:11434` |
| Settings | `num-ctx: 8192` (Ollama's 4096 default is too small for the model's thinking plus the case prompt and tool schemas), `temperature: 0.1` |
| Hardware | One NVIDIA RTX 4070 (12 GB). About 9.3 GB of the model fits on the GPU and the rest runs on the CPU |
| Speed measured | About 6.6 tokens/s generation. Each model call took 19 s to 4 min once loaded; the first call of a fresh Ollama session took 12.5 min |

### Runs recorded on 2026-11-01

| Run | Scenario | Outcome | Proof |
|---|---|---|---|
| `run-20261101-201830-5d01` | 1 + 2 (`untrusted`, prod in renew window) | demo.lab **Fixed**, shop.prod **Needs approval** | renewed via ACME; the cert served afterwards (`ccc70ef9a8af…`) is the one the agent installed; prod renewal denied by policy |
| `run-20261101-203947-580e` | 3 (`weak` + `reload`) | demo.lab **Rolled back**, shop.prod **Needs approval** | nginx refused the reload (`[emerg] invalid parameter "max_fails=three"`); backup `3a5ed6a33e6e…` restored automatically; a client probing every 2 s never saw a failed request |
| `run-20261101-212515-4a48` | 1 + 2, with the model's thinking streamed live | demo.lab **Fixed**, shop.prod **Needs approval** | served fingerprint `14cd21034594…` matches the timeline's "After" |

Each full run took 12 to 21 minutes on this hardware, almost all of it model time. The tool calls themselves
(ACME, install, reload, verify) take seconds.

The demo environment used for these runs (Java services behind the lab's nginx, a strict-TLS traffic probe, and a
relay that shows the model's reasoning live) is in
[eversamurai/certagent-demo-apps](https://github.com/eversamurai/certagent-demo-apps).

To run the same model:

```bash
ollama pull muse-glimmer:30b
export OLLAMA_MODEL=muse-glimmer:30b    # also the default in application.yml
```

---

## Run it

### Requirements
- Java 21+ (no Maven install needed; the repo ships the Maven wrapper)
- Docker with Compose
- [Ollama](https://ollama.com) with a Muse Glimmer build pulled
- Bash (Git Bash on Windows works)

### Steps
```bash
# 1. Model
ollama pull <glimmer-tag>              # check the exact tag with: ollama list
export OLLAMA_MODEL=<glimmer-tag>

# 2. Lab: step-ca (ACME) + nginx serving demo.lab :8443 (lab) and shop.prod :8444 (prod)
./lab/init.sh                          # also writes lab/certs/root_ca.crt, which the agent trusts

# 3. Agent: runs a cycle at startup, then daily at 06:00
./mvnw spring-boot:run                 # open http://localhost:8088

# 4. Break something and watch
./lab/break.sh untrusted
curl -X POST localhost:8088/api/run    # or click "Run cycle now"
```

Reset everything: `./lab/init.sh` restores the lab. Delete `data/` to clear the timeline, backups and the ACME
account.

### Configuration
Everything lives in [`src/main/resources/application.yml`](src/main/resources/application.yml) under
`certagent.*`: targets, policy per environment and tool, risk thresholds, ACME directory, extra trusted roots,
the reload command, the webhook and the schedule. Environment variables: `OLLAMA_URL` (default
`http://localhost:11434`), `OLLAMA_MODEL`, `NOTIFY_WEBHOOK`.

Example policy:
```yaml
certagent:
  policy:
    dry-run: false            # true turns every ALLOW into DRY_RUN
    max-actions-per-run: 10
    environments:
      lab:  { "[verify_handshake]": ALLOW, "[renew_certificate]": ALLOW, "[rollback]": ALLOW }
      prod: { "[verify_handshake]": ALLOW, "[renew_certificate]": DENY,  "[rollback]": DENY }
```
A tool or environment that isn't listed is denied.

### API
| | |
|---|---|
| `GET /api/events?since=<seq>` | timeline events after `seq` |
| `GET /api/inventory` | latest scan results |
| `GET /api/status` | `{running, lastRunId, model}` |
| `POST /api/run` | start a cycle (`202`), or `409` if one is running |

### Tests
```bash
./mvnw test
```
The tests need neither Docker nor a model. They run real TLS handshakes against throwaway local servers with
generated certificates. A scripted stand-in for the model drives the real tools through Spring AI, and a
file-backed TLS server stands in for nginx, so renewal, verification and rollback all run for real.

## Stack

Java 21 · Spring Boot 3.5 · Spring AI 1.1 (Ollama, `@Tool`) · acme4j 3.5 · step-ca · nginx · vanilla HTML/JS.
No database: the timeline is an append-only JSONL file.

## Roadmap

Not part of this build: certificate files over SSH (PEM/PKCS12/JKS), Kubernetes TLS secrets, internal-CA reissue,
an "add missing intermediate" fix, pull-request output, Slack approval buttons, multi-tenant/RBAC, Vault/HSM keys,
and the Windows certificate store.

## More

- [SPEC.md](SPEC.md): the as-built specification, covering every component, event, config key and test.
- [CLAUDE.md](CLAUDE.md): the project's rules and scope, written for coding agents working in this repo.
