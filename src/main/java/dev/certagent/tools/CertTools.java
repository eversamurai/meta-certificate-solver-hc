package dev.certagent.tools;

import dev.certagent.acme.AcmeClient;
import dev.certagent.acme.AcmeClient.Issued;
import dev.certagent.config.AgentProperties;
import dev.certagent.config.AgentProperties.Decision;
import dev.certagent.config.AgentProperties.Target;
import dev.certagent.exec.NginxInstaller;
import dev.certagent.exec.NginxInstaller.Backup;
import dev.certagent.model.CertRecord;
import dev.certagent.model.Event;
import dev.certagent.policy.PolicyGate;
import dev.certagent.scan.EndpointScanner;
import dev.certagent.scan.EndpointScanner.Verification;
import dev.certagent.store.EventLog;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;

/**
 * The only things the model can do. Every method goes through {@link PolicyGate} first, records the
 * model's reasoning on the timeline, and returns a plain string starting with a fixed prefix
 * (OK, SUCCESS, FAIL, FAILED, DENIED, DRY-RUN, ERROR) that the system prompt relies on.
 */
@Component
public class CertTools {

    public static final String CTX_RUN_ID = "runId";

    private final AgentProperties props;
    private final EndpointScanner scanner;
    private final PolicyGate gate;
    private final EventLog events;
    private final AcmeClient acme;
    private final NginxInstaller installer;

    public CertTools(AgentProperties props, EndpointScanner scanner, PolicyGate gate, EventLog events,
                     AcmeClient acme, NginxInstaller installer) {
        this.props = props;
        this.scanner = scanner;
        this.gate = gate;
        this.events = events;
        this.acme = acme;
        this.installer = installer;
    }

    @Tool(name = "verify_handshake", description = """
            Perform a strict TLS handshake against a target and report what it serves: issuer, expiry, key, \
            whether the chain is trusted and the hostname matches. Read-only. Call it before and after any change.""")
    public String verifyHandshake(
            @ToolParam(description = "Target name exactly as given in the findings, e.g. demo.lab") String target,
            @ToolParam(description = "One short paragraph: why you are checking this now") String reasoning,
            ToolContext ctx) {
        String runId = runId(ctx);
        Target t = find(target);
        if (t == null) return unknown(target);
        if (gate.decide(runId, "verify_handshake", t, reasoning) == Decision.DENY) {
            return "DENIED: policy does not allow verify_handshake on " + t.name();
        }

        Verification v = verify(t);
        events.append(runId, t.name(), Event.Kind.VERIFY,
                (v.ok() ? "handshake OK — " : "handshake FAIL — ") + v.summary(),
                EventLog.details("ok", v.ok(), "reasoning", reasoning, "served", snapshot(v)));
        return (v.ok() ? "OK " : "FAIL ") + t.name() + ": " + v.summary() + " | served: " + describe(v.cert());
    }

    @Tool(name = "renew_certificate", description = """
            Obtain a new certificate for the target from its ACME CA with a fresh 2048-bit+ key, install it, \
            reload the server and strictly verify the handshake. If verification fails the previous certificate \
            is restored automatically. Use for expiring, expired, untrusted-issuer or weak-key certificates.""")
    public String renewCertificate(
            @ToolParam(description = "Target name exactly as given in the findings") String target,
            @ToolParam(description = "One short paragraph: what is wrong and why renewal is the right fix") String reasoning,
            ToolContext ctx) {
        String runId = runId(ctx);
        Target t = find(target);
        if (t == null) return unknown(target);
        return switch (gate.decide(runId, "renew_certificate", t, reasoning)) {
            case DENY -> "DENIED: policy for env '" + t.env() + "' does not allow renew_certificate on " + t.name()
                    + ". A human must approve this change. Do not retry.";
            case DRY_RUN -> "DRY-RUN: would renew " + t.name() + " via ACME for " + t.domainsOrSni()
                    + "; nothing was changed.";
            case ALLOW -> renew(runId, t);
        };
    }

    @Tool(name = "rollback", description = """
            Restore the most recent backed-up certificate and key for the target, reload, and verify. \
            Only needed if a change left the target worse; renew_certificate already rolls back on its own.""")
    public String rollback(
            @ToolParam(description = "Target name exactly as given in the findings") String target,
            @ToolParam(description = "One short paragraph: why the previous certificate should come back") String reasoning,
            ToolContext ctx) {
        String runId = runId(ctx);
        Target t = find(target);
        if (t == null) return unknown(target);
        return switch (gate.decide(runId, "rollback", t, reasoning)) {
            case DENY -> "DENIED: policy for env '" + t.env() + "' does not allow rollback on " + t.name() + ".";
            case DRY_RUN -> "DRY-RUN: would restore the last backup for " + t.name() + "; nothing was changed.";
            case ALLOW -> {
                Optional<Backup> b;
                try {
                    b = installer.latestBackup(t);
                } catch (Exception e) {
                    yield "ERROR: cannot read backups for " + t.name() + ": " + e.getMessage();
                }
                if (b.isEmpty()) yield "FAIL: no backup exists for " + t.name() + "; nothing was changed.";
                Verification after = restore(runId, t, b.get(), "requested by the model: " + reasoning);
                yield (after.ok() ? "SUCCESS: " : "FAILED: ") + "restored backup " + b.get().id() + " on " + t.name()
                        + "; endpoint now: " + after.summary();
            }
        };
    }

    // ---- renewal with automatic rollback (invariant 4: not at the model's discretion) ----

    private String renew(String runId, Target t) {
        Verification before = verify(t);

        Issued issued;
        try {
            issued = acme.issue(t.domainsOrSni());
        } catch (Exception e) {
            String err = message(e);
            events.append(runId, t.name(), Event.Kind.APPLY, "ACME issuance failed — nothing changed: " + err,
                    EventLog.details("stage", "issue", "changed", false, "error", err,
                            "ca", props.acme().directoryUrl(), "before", snapshot(before)));
            return "FAILED: ACME issuance from " + props.acme().directoryUrl() + " failed: " + err
                    + ". Nothing was changed; " + t.name() + " still serves the previous certificate.";
        }
        String newFp = EndpointScanner.fingerprint(issued.leaf());

        Backup backup;
        try {
            backup = installer.backup(t);
        } catch (Exception e) {
            String err = message(e);
            events.append(runId, t.name(), Event.Kind.APPLY, "backup failed — nothing changed: " + err,
                    EventLog.details("stage", "backup", "changed", false, "error", err));
            return "FAILED: could not back up the current certificate (" + err + "), so nothing was installed.";
        }

        String problem;
        try {
            installer.install(t, issued.chainPem(), issued.keyPem());
            events.append(runId, t.name(), Event.Kind.APPLY,
                    "installed new certificate from " + issued.leaf().getIssuerX500Principal().getName()
                            + ", expires " + issued.leaf().getNotAfter().toInstant() + "; backup " + backup.id(),
                    EventLog.details("stage", "install", "changed", true, "backupId", backup.id(),
                            "newFingerprint", newFp, "before", snapshot(before)));
            installer.reload();

            Verification after = verify(t);
            boolean servesNew = newFp.equals(after.cert().fingerprintSha256());
            events.append(runId, t.name(), Event.Kind.VERIFY,
                    (after.ok() && servesNew ? "post-change handshake OK — " : "post-change handshake FAIL — ")
                            + (servesNew ? after.summary() : "endpoint is not serving the new certificate"),
                    EventLog.details("ok", after.ok() && servesNew, "phase", "after",
                            "before", snapshot(before), "served", snapshot(after)));
            if (after.ok() && servesNew) {
                return "SUCCESS: renewed and installed " + t.name() + "; strict handshake now: " + after.summary()
                        + " | before: " + before.summary();
            }
            problem = servesNew ? after.summary() : "endpoint still serves fingerprint " + after.cert().fingerprintSha256();
        } catch (Exception e) {
            problem = message(e);
        }

        Verification restored = restore(runId, t, backup, problem);
        return "FAILED: the new certificate did not pass verification (" + problem + "). Automatically rolled back "
                + "to backup " + backup.id() + "; endpoint now: " + restored.summary()
                + (restored.ok() ? "" : " (it was already failing before the change)");
    }

    private Verification restore(String runId, Target t, Backup backup, String why) {
        String err = null;
        try {
            installer.restore(t, backup);
            installer.reload();
        } catch (Exception e) {
            err = message(e);
        }
        Verification after = verify(t);
        events.append(runId, t.name(), Event.Kind.ROLLBACK,
                "restored backup " + backup.id() + (err == null ? "" : " (with error: " + err + ")")
                        + " — endpoint now serves " + shortFp(after.cert().fingerprintSha256()),
                EventLog.details("backupId", backup.id(), "reason", why, "error", err,
                        "ok", after.ok(), "served", snapshot(after)));
        return after;
    }

    // ---- helpers ----

    /** Compact one-line description of a served cert, shared with the runner's prompt. */
    public static String describe(CertRecord c) {
        if (c.handshakeError() != null) return "no certificate (" + c.handshakeError() + ")";
        return "subject=" + c.subject() + ", issuer=" + c.issuer() + ", sans=" + c.sans()
                + ", notAfter=" + c.notAfter() + ", key=" + key(c) + ", sigAlg=" + c.sigAlg()
                + ", trusted=" + c.trusted() + ", hostnameMatches=" + c.hostnameMatches();
    }

    /** What the UI needs to draw one side of a before/after comparison. */
    private static Map<String, Object> snapshot(Verification v) {
        CertRecord c = v.cert();
        return EventLog.details(
                "ok", v.ok(),
                "fingerprint", c.fingerprintSha256(),
                "issuer", c.issuer(),
                "notAfter", c.notAfter(),
                "key", key(c),
                "reasons", c.risk().reasons());
    }

    private Verification verify(Target t) {
        return scanner.verify(t.host(), t.port(), t.serverName());
    }

    private static String key(CertRecord c) {
        return c.keyType() == null ? null : c.keyType() + " " + c.keyBits();
    }

    private static String shortFp(String fp) {
        return fp == null ? "nothing" : fp.substring(0, 12) + "…";
    }

    private static String message(Exception e) {
        return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    }

    private Target find(String name) {
        return props.targets().stream().filter(t -> t.name().equalsIgnoreCase(name == null ? "" : name.trim()))
                .findFirst().orElse(null);
    }

    private String unknown(String target) {
        return "ERROR: unknown target '" + target + "'. Known targets: "
                + props.targets().stream().map(Target::name).toList();
    }

    private static String runId(ToolContext ctx) {
        Map<String, Object> m = ctx == null ? Map.of() : ctx.getContext();
        return String.valueOf(m.getOrDefault(CTX_RUN_ID, "manual"));
    }
}
