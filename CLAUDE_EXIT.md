# CLAUDE_EXIT.md — Build the demo environment (Java services + traffic probe)

Brief for a coding agent working **separately** from the main CertAgent work. Read this file fully, then
`CLAUDE.md` (project rules), then `SPEC.md` §5–§8 (lab, config, components, events). Don't start writing code
until you've read all three.

Today is 2026-11-01. The hackathon deadline is **Wed Nov 4, 9:00 PM ET**, and the demo video must be
recorded before then. Optimise for a demo that holds up on camera, not for breadth.

---

## 1. Goal in one paragraph

CertAgent (this repo, `src/`) already scans HTTPS endpoints, diagnoses certificate problems, lets the model
renew them via ACME, installs them into nginx, verifies, and rolls back. The lab today serves only a
placeholder line of text (`demo.lab OK`), which makes for a dull video. Your job is to make the lab look and
behave like **a small company running Java services**, and to add a **traffic probe**: a Java client that
keeps calling those services over HTTPS with strict certificate checks, so the video can show real clients
failing when a cert breaks and recovering when CertAgent fixes it. Then write the scripts and runbook the
owner uses to record the three demo cases.

## 2. What you are building

| Piece | Where | What it is |
|---|---|---|
| `storefront` | `demo-apps/storefront/` | Small Java HTTP service: the public shop. Plain HTTP inside docker. |
| `checkout` | `demo-apps/checkout/` | Small Java HTTP service: payments/checkout. Plain HTTP inside docker. |
| `traffic-probe` | `demo-apps/traffic-probe/` | Java HTTPS client + one status page, served at `http://localhost:8090`. |
| nginx changes | `lab/nginx/nginx.conf` | `demo.lab` → proxy to storefront; `shop.prod` → proxy to checkout. |
| compose changes | `lab/docker-compose.yml` | Add the three services. |
| demo scripts | `demo/` | `reset.sh`, `scenario.sh`, and `RUNBOOK.md` for recording. |

### Architecture

```
                         ┌──────────── docker network (certagent-lab) ────────────┐
traffic-probe ──HTTPS──▶ │ nginx :443  demo.lab  ──http──▶ storefront :8080        │
 (strict TLS,            │ nginx :8444 shop.prod ──http──▶ checkout   :8080        │
  trusts lab root only)  │ nginx :80   /.well-known/acme-challenge/ (ACME http-01) │
                         │ step-ca :9000 (ACME)                                    │
                         └─────────────────────────────────────────────────────────┘
CertAgent (host, :8088) scans https://localhost:8443 / :8444 and renews certs in lab/certs/
```

**Why nginx terminates TLS, not the Java apps:** in this build, CertAgent can only install PEM files and
reload nginx. Java keystores (JKS/PKCS12) and SSH installs are on the **Out** list in `CLAUDE.md` §4, to be
built after the video. So the Java services sit behind nginx, like a typical Java app behind a reverse
proxy. Do **not** make the services serve TLS, and do **not** add JKS support to CertAgent.

---

## 3. The contract you must not break

CertAgent, its tests and the lab scripts depend on all of these. Keep every one of them exactly as it is:

| Item | Value |
|---|---|
| Compose project / file | `name: certagent-lab`, `lab/docker-compose.yml` |
| Services that must keep their names | `ca`, `nginx` |
| Host ports | 9000 (CA), 8080 (nginx http), 8443 (`demo.lab`, env lab), 8444 (`shop.prod`, env prod), 8088 (CertAgent) |
| nginx network aliases | `demo.lab`, `shop.prod` (the CA reaches `http://demo.lab/` for http-01) |
| Cert files on host | `lab/certs/server.{crt,key}` (demo.lab), `lab/certs/prod.{crt,key}` (shop.prod), `lab/certs/root_ca.crt` |
| Mounts in nginx | `lab/certs` → `/etc/nginx/certs`, `lab/webroot` → `/var/www/acme`, `lab/conf.d` → `/etc/nginx/conf.d` |
| ACME challenge path | `location /.well-known/acme-challenge/ { root /var/www/acme; }` on port 80 for both names |
| Reload | `nginx -t -q && nginx -s reload` (a bare `-s reload` exits 0 even on a bad config) |
| `conf.d/*.conf` include | Must stay, because `break.sh reload` relies on it |
| Scripts | `lab/init.sh`, `lab/break.sh expiring\|untrusted\|weak\|reload`, `lab/lib.sh`: keep the behaviour, and you may extend them |
| CertAgent config | `src/main/resources/application.yml`: **don't edit it** |
| CertAgent code | Everything under `src/`: **don't edit it** |

If you think something in the contract has to change, stop and ask the owner. Don't change it quietly.

---

## 4. Specs for each piece

### 4.1 storefront and checkout (Java services)

- Java 21, **JDK only** (`com.sun.net.httpserver.HttpServer`), no frameworks and no Maven dependencies, so the
  image builds in seconds with no internet access at runtime. One source file per app is fine.
- Build them in docker with a multi-stage Dockerfile: `eclipse-temurin:21-jdk-alpine` to compile (`javac`,
  `jar`), then `eclipse-temurin:21-jre-alpine` to run. Pin exact image tags and check they exist on Docker Hub.
  The host has no Maven on PATH and its JDK isn't on PATH either, so builds must work inside docker only.
- Listen on `:8080` inside the network, with **no host ports** (nginx is the only way in).
- Endpoints:
  - `GET /` returns a small HTML page with the service name, a one-line description ("Storefront — product
    catalogue", "Checkout — payments"), the hostname it's served as (`X-Forwarded-Host`), and the current time.
    Keep it plain and readable on camera.
  - `GET /api/health` returns `{"service":"storefront","status":"UP","time":"…"}`.
  - `GET /api/orders` (checkout) or `/api/products` (storefront) returns a few hard-coded JSON items. This is
    the "business call" the probe makes.
- Log one line per request to stdout.

### 4.2 nginx changes

- Port 443 `demo.lab`: replace `return 200 …` with `proxy_pass http://storefront:8080;` plus
  `proxy_set_header Host $host; X-Forwarded-Host $host; X-Forwarded-Proto https;`.
- Port 8444 `shop.prod`: the same, proxying to `checkout:8080`.
- Port 80: leave the ACME location exactly as it is, and leave `/` returning plain text. Don't redirect to HTTPS,
  because the CA must fetch challenges over HTTP.
- Make nginx start even when an upstream container isn't up yet. Use a `resolver 127.0.0.11 valid=10s;` plus
  a variable in `proxy_pass` (e.g. `set $up storefront:8080; proxy_pass http://$up;`), or `depends_on` the
  apps. A missing upstream must never make `nginx -t` fail: if it did, every renewal would roll back and demo
  case 1 would break.

### 4.3 traffic-probe (the camera-facing piece)

A Java 21 app, also JDK only, that acts like **real clients** of the two services.

- Every **2 seconds**, for each target, it makes an HTTPS GET to the business endpoint:
  - `https://demo.lab:443/api/products` and `https://shop.prod:8444/api/orders`, using the docker network
    aliases so SNI and hostname checks are real.
  - It uses `java.net.http.HttpClient` with an `SSLContext` that trusts **only** `/certs/root_ca.crt`
    (mount `lab/certs/root_ca.crt` read-only), and keeps default hostname verification **on**.
  - It records: OK or FAIL, HTTP status, latency, and on failure the short TLS error (e.g.
    `PKIX path building failed`, `No subject alternative DNS name matching`).
  - On each check it also reads the served leaf certificate. Use the `HttpResponse.sslSession()` peer
    certificates; if the handshake failed, open a separate capture-all `SSLSocket`. Record the issuer CN, key
    type and bits, notAfter, and the first 12 hex characters of the SHA-256 fingerprint. The fingerprint format
    must match CertAgent's (lowercase hex of SHA-256 over the DER encoding), so the same prefix appears on the
    probe and on the CertAgent timeline.
- Status page at `http://localhost:8090` (host port 8090 → container 8090). It's one HTML page, served by the
  same app, that polls `/api/status` every second:
  - One large tile per service: name, hostname, env (`lab` / `prod`), a big state of **OK** (green) / **WARN**
    (amber) / **FAIL** (red), the last error in plain words, issuer CN, key, "expires in …", and the
    fingerprint prefix.
  - **WARN** means the request succeeded but the cert is risky: RSA under 2048 bits, or less than 6h to
    expiry. Java accepts a 1024-bit RSA key, so without this rule the weak-key case would look healthy.
  - A strip of the last 60 checks per service (small green/amber/red squares) so the outage and recovery are
    visible at a glance.
  - Running totals: requests OK / failed in the last 5 minutes.
  - No external fonts, scripts or CDNs (CLAUDE.md invariant 6: nothing leaves the network). Use system fonts
    and the same dark look as CertAgent's timeline (`src/main/resources/static/index.html`; you can copy its
    CSS variables). It must look good in a 960×1080 browser window, because it sits beside the timeline in the
    video.
- If `root_ca.crt` changes (after `lab/init.sh`), reload it. Re-reading it on every check is fine.

### 4.4 Compose changes

- Add `storefront`, `checkout` and `traffic-probe` services with `build:` contexts under `demo-apps/`.
  - `traffic-probe` mounts `./certs/root_ca.crt:/certs/root_ca.crt:ro` and publishes `8090:8090`.
  - The apps get no host ports.
- `nginx` keeps its current definition, plus whatever `depends_on` you need for the upstreams.
- `lab/init.sh` must still bring everything up from scratch. If it needs `--build`, or must start the new
  services, extend it. Remember that it recreates nginx with `--force-recreate`.

### 4.5 Demo scripts (`demo/`)

All bash, LF line endings (already set in `.gitattributes` for `*.sh`). Put `export MSYS_NO_PATHCONV=1` at the
top: the owner is on **Windows 11 with Git Bash**.

- `demo/reset.sh`: runs `./lab/init.sh`, deletes `data/` (the CertAgent timeline, backups and ACME account),
  and waits until the probe reports both services OK. It prints what to start next (CertAgent).
- `demo/scenario.sh fixed|approval|rollback`:
  - `fixed`: `./lab/break.sh untrusted`, waits until the probe shows `demo.lab` FAIL, then `POST /api/run`.
  - `approval`: nothing to break (`shop.prod` is issued with 4h validity by `init.sh`, inside the 6h warn
    window). It just triggers `POST /api/run`, and is usually combined with the cases above in the same run.
  - `rollback`: `./lab/break.sh weak`, then `./lab/break.sh reload`, waits until the probe shows WARN, then
    `POST /api/run`.
  - After triggering, poll `GET localhost:8088/api/status` until `running=false`. Then print each target's
    outcome from the last run-level `DONE` event in `GET /api/events` (`details.outcomes`).
- `demo/RUNBOOK.md`: the recording guide, see §6.

---

## 5. How CertAgent behaves (so the demo makes sense)

- On each cycle it handshakes each target, diagnoses in code, and sends unhealthy targets to the model.
- `renew_certificate` (lab only, by policy):
  1. ACME http-01 against step-ca, writing the token into `lab/webroot` on the host.
  2. Backup to `data/backups/`.
  3. Writes `lab/certs/server.{crt,key}`.
  4. Runs `docker compose -f lab/docker-compose.yml exec -T nginx sh -c "nginx -t -q && nginx -s reload"`.
  5. Waits 3s, then verifies strictly and checks that the **served fingerprint equals the new one**.
     Otherwise it restores the backup.
- `shop.prod` is env `prod`: renewal is **denied** by policy, so it shows **Needs approval** and nothing changes.
- Outcomes on the timeline: Fixed, Rolled back, Needs approval, Failed safely, Healthy, Unresolved.
- Expected demo results:

| Scenario | CertAgent timeline | Probe |
|---|---|---|
| fixed (`untrusted`) | demo.lab **Fixed** | demo.lab FAIL (`PKIX path building failed`) → OK; fingerprint prefix changes and matches the timeline |
| approval | shop.prod **Needs approval** | shop.prod stays WARN (expires in ~3–4h), no outage |
| rollback (`weak` + `reload`) | demo.lab **Rolled back**, `[emerg]` reason shown | demo.lab stays WARN (1024-bit key) throughout, **no FAIL**: the site never went down |

The probe's value in case 3 is showing that **no client saw an outage** while the agent tried and backed out.

---

## 6. `demo/RUNBOOK.md` contents (write this file)

A step-by-step guide the owner can follow while recording:

1. Prerequisites: Docker Desktop running, Ollama running with the Glimmer model pulled, and
   `OLLAMA_MODEL` set. `JAVA_HOME="/c/Program Files/Java/jdk-23.0.1"` for `./mvnw`.
2. Screen layout: CertAgent timeline (`http://localhost:8088`) on the left, probe (`http://localhost:8090`) on
   the right, a small terminal at the bottom. Browser zoom level, dark mode.
3. Take 1 (cases 1 + 2 in one run): `demo/reset.sh` → start CertAgent with
   `./mvnw spring-boot:run -Dspring-boot.run.arguments=--certagent.schedule.run-on-startup=false` →
   `demo/scenario.sh fixed`. What to point at, in order: probe goes red → timeline card appears → reasoning
   headline → AUTO · lab → before/after → probe goes green with the matching fingerprint → shop.prod
   APPROVAL NEEDED.
4. Take 2 (case 3): `demo/scenario.sh rollback`, without a reset, so take 1's cards stay on screen
   underneath. Point at: the ROLLBACK row, the `[emerg]` reason, and the probe never turning red.
5. Clean-up: `./lab/init.sh` removes the broken `conf.d` snippet.
6. "If it goes wrong" table: model slow, ACME http-01 failing (check the `demo.lab` alias and port 80), nginx
   won't start (check `conf.d` and upstreams), ports busy.

Keep it short enough to read on a second screen.

---

## 7. Definition of done

Verify each of these yourself and report the results with the actual output. Don't just say it works.

- [ ] `./lab/init.sh` from a clean state (`docker compose -f lab/docker-compose.yml down -v`) brings up the CA,
      nginx, both apps and the probe. `curl -k --resolve demo.lab:8443:127.0.0.1 https://demo.lab:8443/` shows
      the storefront page.
- [ ] `openssl s_client -connect localhost:8443 -servername demo.lab` shows the lab CA issuer, and the same
      for `:8444` / `shop.prod`.
- [ ] The probe page at `http://localhost:8090` shows demo.lab OK and shop.prod WARN (4h cert).
- [ ] `./lab/break.sh untrusted` turns demo.lab FAIL on the probe within ~4s. `./lab/break.sh weak` turns it
      WARN. `./lab/break.sh reload` makes `docker compose -f lab/docker-compose.yml exec nginx nginx -t` fail
      while the probe keeps getting responses.
- [ ] `./lab/init.sh` restores everything to OK.
- [ ] With CertAgent running (needs Ollama), `demo/scenario.sh fixed` ends with demo.lab **Fixed**, the probe
      green, and the probe's fingerprint prefix equal to the timeline's "After" fingerprint.
      `demo/scenario.sh rollback` ends with **Rolled back** and no probe FAIL. If Ollama isn't available, say
      so and verify everything up to this point.
- [ ] `./mvnw -q test` still passes (23 tests). It should, since you don't touch `src/`.
- [ ] Nothing new is committed under `lab/certs/`, `data/`, or as `*.pem|key|crt`.

---

## 8. Rules (from CLAUDE.md, apply here too)

- **Work on a branch** (`demo-env`), not on `main`. The owner merges.
- Commit often, with imperative one-line messages saying what and why. The repo is **public**, and the commit
  history is evidence of work done during the event. Never commit keys or certs.
- No runtime calls outside the docker network or localhost. Image pulls at build time are fine.
- Pin every image tag to a version that exists.
- Don't add anything to CertAgent itself, and don't add anything from the Out list (`CLAUDE.md` §4).
- Small, plain code. These are props for a video, so readability on camera matters more than features.
- When done, add a short "Demo environment" section to `SPEC.md` (what was added, ports, how to run) and a link
  to `demo/RUNBOOK.md` from `README.md`.

## 9. Environment facts

- Windows 11, Git Bash (POSIX shell) and PowerShell. Repo at `D:\dev\cert-verif-app`.
- JDK 23.0.1 at `C:\Program Files\Java\jdk-23.0.1`, not on PATH. No global Maven (use `./mvnw` for CertAgent).
- Docker Desktop and Ollama: the owner is installing them. Check `docker version` and `ollama list` before
  relying on either, and say clearly what you couldn't verify.
- GitHub remote: `origin` → `github.com/eversamurai/meta-certificate-solver-hc` (public). Don't push to `main`.
