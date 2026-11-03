package dev.certagent.agent;

import dev.certagent.config.AgentProperties;
import dev.certagent.model.CertRecord;
import dev.certagent.model.CertRecord.Level;
import dev.certagent.model.Event;
import dev.certagent.model.Event.Kind;
import dev.certagent.policy.PolicyGate;
import dev.certagent.scan.EndpointScanner;
import dev.certagent.store.EventLog;
import dev.certagent.tools.CertTools;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.HexFormat;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

/**
 * One cycle: scan every target → diagnose in code → for each unhealthy target, let the model decide and act
 * through tools → derive the outcome from the timeline → summarise → notify.
 * Runs at startup, on the cron in config, and on POST /api/run. Only one cycle runs at a time.
 */
@Component
public class CertAgentRunner {

    static final String SYSTEM = """
            You are CertAgent, the on-call TLS operator for a private network. Each case gives you the findings \
            for one target, computed by a deterministic scanner. Decide what to do, do it with tools, and prove \
            the result.

            Tools: verify_handshake, renew_certificate, rollback. Every tool takes `target` (the exact target name \
            from the case) and `reasoning`.

            Rules:
            1. First call verify_handshake to confirm the problem is real right now.
            2. Choose the least invasive fix that resolves every finding. renew_certificate fixes expiring, expired, \
            untrusted-issuer and weak-key certificates. If the target turns out healthy, change nothing.
            3. Put your thinking in `reasoning` on every call: one short paragraph in plain English that names the \
            evidence (issuer, expiry, key size) and says why this tool is the right next step. Engineers read it.
            4. Read every tool result by its first word:
               OK or SUCCESS: it worked.
               FAIL or FAILED: it did not; renew_certificate has already restored the previous certificate.
               DENIED: policy forbids it. Do not retry or work around it; a human must approve.
               DRY-RUN: nothing was changed.
               ERROR: something broke. Do not repeat the same call more than once.
            5. After a successful change, call verify_handshake once more to prove it.
            6. Never invent targets, tools or results. Use at most 5 tool calls per case.
            7. Finish with 2-3 sentences: what was wrong, what you did, and the final state.
            """;

    private final AgentProperties props;
    private final EndpointScanner scanner;
    private final CertTools tools;
    private final PolicyGate gate;
    private final EventLog events;
    private final Notifier notifier;
    private final ChatClient chat;
    private final String model;
    private final SparkSummarizer spark;

    private final AtomicBoolean running = new AtomicBoolean();
    private volatile List<CertRecord> inventory = List.of();
    private volatile String lastRunId;

    /** The run summary and who wrote it: Spark, Glimmer, or the code-written fallback. */
    record Summary(String text, String by) {
    }

    public CertAgentRunner(AgentProperties props, EndpointScanner scanner, CertTools tools, PolicyGate gate,
                           EventLog events, Notifier notifier, ChatClient.Builder chat,
                           @Value("${spring.ai.ollama.chat.options.model:unknown}") String model,
                           SparkSummarizer spark) {
        this.props = props;
        this.scanner = scanner;
        this.tools = tools;
        this.gate = gate;
        this.events = events;
        this.notifier = notifier;
        this.chat = chat.defaultSystem(SYSTEM).build();
        this.model = model;
        this.spark = spark;
    }

    // ---- triggers ----

    @EventListener(ApplicationReadyEvent.class)
    public void onStartup() {
        if (props.schedule().runOnStartup()) trigger();
    }

    @Scheduled(cron = "${certagent.schedule.cron:0 0 6 * * *}")
    public void onSchedule() {
        trigger();
    }

    /** Starts a cycle in the background; empty if one is already running. */
    public Optional<String> trigger() {
        if (!running.compareAndSet(false, true)) return Optional.empty();
        String runId = newRunId();
        Thread.ofVirtual().name("cert-agent-" + runId).start(() -> {
            try {
                runCycle(runId);
            } finally {
                running.set(false);
            }
        });
        return Optional.of(runId);
    }

    public boolean isRunning() {
        return running.get();
    }

    public List<CertRecord> inventory() {
        return inventory;
    }

    public String lastRunId() {
        return lastRunId;
    }

    public String model() {
        return model;
    }

    /** Who writes run summaries when everything works: Spark if configured, else Glimmer. */
    public String summaryModel() {
        return spark.enabled() ? spark.label() : model + " · local";
    }

    // ---- the cycle ----

    public void runCycle(String runId) {
        lastRunId = runId;
        Map<String, String> outcomes = new LinkedHashMap<>();
        try {
            events.append(runId, null, Kind.SCAN, "run started: scanning " + props.targets().size() + " target(s)",
                    EventLog.details("model", model, "targets", props.targets().size()));
            List<CertRecord> scanned = scanner.scanAll();
            inventory = scanned;

            for (CertRecord c : scanned) {
                outcomes.put(c.target(), handleCase(runId, c));
            }

            Map<String, Integer> counts = outcomes.values().stream()
                    .collect(Collectors.toMap(o -> o, o -> 1, Integer::sum, LinkedHashMap::new));
            Summary summary = summarize(runId, outcomes);
            events.append(runId, null, Kind.DONE, summary.text(),
                    EventLog.details("summary", summary.text(), "summaryBy", summary.by(),
                            "counts", counts, "outcomes", outcomes));
            notifier.send(runId, summary.text(), counts);
        } catch (Exception e) {
            events.append(runId, null, Kind.ERROR, "run failed: " + e.getMessage());
        } finally {
            gate.endRun(runId);
        }
    }

    private String handleCase(String runId, CertRecord c) {
        events.append(runId, c.target(), Kind.SCAN, "observed " + c.target() + " (" + c.env() + ")",
                EventLog.details(
                        "env", c.env(),
                        "endpoint", c.host() + ":" + c.port(),
                        "sni", c.sni(),
                        "issuer", c.issuer(),
                        "notAfter", c.notAfter(),
                        "fingerprint", c.fingerprintSha256(),
                        "key", c.keyType() == null ? null : c.keyType() + " " + c.keyBits(),
                        "trusted", c.trusted(),
                        "handshakeError", c.handshakeError()));
        events.append(runId, c.target(), Kind.DIAGNOSE,
                c.risk().level() + (c.risk().reasons().isEmpty() ? ": healthy" : ": " + String.join("; ", c.risk().reasons())),
                EventLog.details("level", c.risk().level().name(), "reasons", c.risk().reasons()));

        if (c.risk().level() == Level.OK) {
            events.append(runId, c.target(), Kind.DONE, "Healthy", EventLog.details("outcome", "Healthy"));
            return "Healthy";
        }

        String answer = askModel(runId, c);
        String outcome = outcome(events.forCase(runId, c.target()));
        events.append(runId, c.target(), Kind.DONE, outcome,
                EventLog.details("outcome", outcome, "summary", answer));
        return outcome;
    }

    private String askModel(String runId, CertRecord c) {
        String prompt = casePrompt(c);
        events.append(runId, c.target(), Kind.PLAN, "asking " + model + " to decide",
                EventLog.details("model", model, "prompt", prompt));
        for (int attempt = 1; attempt <= 2; attempt++) {
            try {
                return chat.prompt()
                        .user(prompt)
                        .tools(tools)
                        .toolContext(Map.of(CertTools.CTX_RUN_ID, runId))
                        .call()
                        .content();
            } catch (Exception e) {
                events.append(runId, c.target(), Kind.ERROR, "model call failed (attempt " + attempt + "): " + e.getMessage());
                prompt = prompt + "\n\nYour previous attempt failed with: " + e.getMessage()
                        + "\nCall tools only with valid JSON arguments matching their schema.";
            }
        }
        return null;
    }

    static String casePrompt(CertRecord c) {
        return """
                Case: target %s (env: %s) at %s:%d, SNI %s
                Risk: %s
                Findings:
                %s
                Served: %s
                """.formatted(c.target(), c.env(), c.host(), c.port(), c.sni(), c.risk().level(),
                c.risk().reasons().stream().map(r -> "- " + r).collect(Collectors.joining("\n")),
                CertTools.describe(c));
    }

    /** Outcome comes from what actually happened on the timeline, not from what the model says happened. */
    static String outcome(List<Event> caseEvents) {
        boolean rolledBack = caseEvents.stream().anyMatch(e -> e.kind() == Kind.ROLLBACK);
        boolean applied = caseEvents.stream()
                .anyMatch(e -> e.kind() == Kind.APPLY && Boolean.TRUE.equals(e.details().get("changed")));
        boolean failedBeforeChange = caseEvents.stream()
                .anyMatch(e -> e.kind() == Kind.APPLY && Boolean.FALSE.equals(e.details().get("changed")));
        Event lastVerify = caseEvents.stream().filter(e -> e.kind() == Kind.VERIFY)
                .reduce((a, b) -> b).orElse(null);
        boolean verifiedOk = lastVerify != null && Boolean.TRUE.equals(lastVerify.details().get("ok"));

        if (rolledBack) return "Rolled back";
        if (applied && verifiedOk) return "Fixed";
        if (hasChangeDecision(caseEvents, "DENY")) return "Needs approval";
        if (hasChangeDecision(caseEvents, "DRY_RUN")) return "Dry run";
        if (failedBeforeChange) return "Failed safely";
        return "Unresolved";
    }

    private static boolean hasChangeDecision(List<Event> es, String decision) {
        return es.stream().anyMatch(e -> e.kind() == Kind.POLICY
                && decision.equals(e.details().get("decision"))
                && !"verify_handshake".equals(e.details().get("tool")));
    }

    /**
     * Spark (Meta Model API) writes the summary if configured; on any failure Glimmer does, and if that fails too
     * the code-written line is used. Only outcomes and Glimmer's closing notes go into the prompt.
     */
    private Summary summarize(String runId, Map<String, String> outcomes) {
        String facts = outcomes.entrySet().stream()
                .map(e -> "- " + e.getKey() + ": " + e.getValue() + lastAnswer(runId, e.getKey()))
                .collect(Collectors.joining("\n"));
        Summary fallback = new Summary(outcomes.size() + " target(s) checked: " + outcomes.entrySet().stream()
                .map(e -> e.getKey() + " " + e.getValue().toLowerCase()).collect(Collectors.joining(", ")) + ".",
                "rule-based");
        if (outcomes.values().stream().allMatch("Healthy"::equals)) return fallback;

        String prompt = "Write exactly 3 sentences for the on-call channel summarising this run. "
                + "Use only these facts; do not add advice beyond what a human must approve.\n" + facts;
        if (spark.enabled()) {
            try {
                String s = spark.summarize(prompt);
                if (s != null && !s.isBlank()) return new Summary(s.strip(), spark.label());
                events.append(runId, null, Kind.ERROR, "summary by " + spark.label() + " was empty; using " + model);
            } catch (Exception e) {
                events.append(runId, null, Kind.ERROR,
                        "summary by " + spark.label() + " failed: " + e.getMessage() + "; using " + model);
            }
        }
        try {
            String s = chat.prompt().user(prompt).call().content();
            return s == null || s.isBlank() ? fallback : new Summary(s.strip(), model + " · local");
        } catch (Exception e) {
            return fallback;
        }
    }

    private String lastAnswer(String runId, String target) {
        return events.forCase(runId, target).stream()
                .filter(e -> e.kind() == Kind.DONE && e.details().get("summary") != null)
                .map(e -> " — " + e.details().get("summary"))
                .reduce((a, b) -> b).orElse("");
    }

    private static String newRunId() {
        // Suffix keeps two runs started in the same second from merging their case cards.
        return "run-" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
                + "-" + HexFormat.of().toHexDigits((short) ThreadLocalRandom.current().nextInt());
    }
}
