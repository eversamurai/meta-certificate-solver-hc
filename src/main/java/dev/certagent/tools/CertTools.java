package dev.certagent.tools;

import dev.certagent.config.AgentProperties;
import dev.certagent.config.AgentProperties.Decision;
import dev.certagent.config.AgentProperties.Target;
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

    public CertTools(AgentProperties props, EndpointScanner scanner, PolicyGate gate, EventLog events) {
        this.props = props;
        this.scanner = scanner;
        this.gate = gate;
        this.events = events;
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

        Verification v = scanner.verify(t.host(), t.port(), t.serverName());
        CertRecord c = v.cert();
        events.append(runId, t.name(), Event.Kind.VERIFY,
                (v.ok() ? "handshake OK — " : "handshake FAIL — ") + v.summary(),
                EventLog.details(
                        "ok", v.ok(),
                        "reasoning", reasoning,
                        "fingerprint", c.fingerprintSha256(),
                        "issuer", c.issuer(),
                        "notAfter", c.notAfter(),
                        "key", key(c),
                        "reasons", c.risk().reasons()));
        return (v.ok() ? "OK " : "FAIL ") + t.name() + ": " + v.summary() + " | served: " + describe(c);
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
            case ALLOW -> {
                // Executors (AcmeClient → NginxInstaller → verify → rollback) are wired in the next step.
                events.append(runId, t.name(), Event.Kind.ERROR, "renew_certificate executor not available yet");
                yield "ERROR: renewal executor is not available in this build; nothing was changed.";
            }
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
                events.append(runId, t.name(), Event.Kind.ERROR, "rollback executor not available yet");
                yield "ERROR: rollback executor is not available in this build; nothing was changed.";
            }
        };
    }

    // ---- helpers ----

    /** Compact one-line description of a served cert, shared with the runner's prompt. */
    public static String describe(CertRecord c) {
        if (c.handshakeError() != null) return "no certificate (" + c.handshakeError() + ")";
        return "subject=" + c.subject() + ", issuer=" + c.issuer() + ", sans=" + c.sans()
                + ", notAfter=" + c.notAfter() + ", key=" + key(c) + ", sigAlg=" + c.sigAlg()
                + ", trusted=" + c.trusted() + ", hostnameMatches=" + c.hostnameMatches();
    }

    private static String key(CertRecord c) {
        return c.keyType() == null ? null : c.keyType() + " " + c.keyBits();
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
