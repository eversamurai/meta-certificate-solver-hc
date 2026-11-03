package dev.certagent.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.certagent.agent.ScriptedChatModel.Call;
import dev.certagent.agent.ScriptedChatModel.Script;
import dev.certagent.config.AgentProperties;
import dev.certagent.config.AgentProperties.Decision;
import dev.certagent.config.AgentProperties.Target;
import dev.certagent.config.TrustConfig;
import dev.certagent.model.Event;
import dev.certagent.model.Event.Kind;
import dev.certagent.policy.PolicyGate;
import dev.certagent.scan.EndpointScanner;
import dev.certagent.scan.TestPki;
import dev.certagent.scan.TestPki.Issued;
import dev.certagent.scan.TestPki.TlsServer;
import dev.certagent.store.EventLog;
import dev.certagent.tools.CertTools;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import dev.certagent.config.ModelConfig.AgentModel;
import org.springframework.web.client.RestClient;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Full cycle with real scanner, policy, tools and event log; only the model is scripted. */
class CertAgentRunnerTest {

    @TempDir
    Path tmp;

    static String args(String target, String reasoning) {
        return "{\"target\":\"" + target + "\",\"reasoning\":\"" + reasoning + "\"}";
    }

    @Test
    void cycleRoutesToolCallsThroughPolicyAndRecordsReasoning() throws Exception {
        Issued labRoot = TestPki.root("Test Lab Root");
        Issued rogue = TestPki.root("Rogue Corp Root");

        try (var demo = new TlsServer(TestPki.leaf(rogue, "demo.lab", Duration.ofDays(30)));
             var shop = new TlsServer(TestPki.leaf(labRoot, "shop.prod", Duration.ofHours(3)));
             var ok = new TlsServer(TestPki.leaf(labRoot, "ok.lab", Duration.ofHours(24)))) {

            var targets = List.of(
                    new Target("demo.lab", "localhost", demo.port(), "demo.lab", "lab", null, null, null),
                    new Target("shop.prod", "localhost", shop.port(), "shop.prod", "prod", null, null, null),
                    new Target("ok.lab", "localhost", ok.port(), "ok.lab", "lab", null, null, null));
            var policy = new AgentProperties.Policy(false, 10, Map.of(
                    "lab", Map.of("verify_handshake", Decision.ALLOW, "renew_certificate", Decision.ALLOW,
                            "rollback", Decision.ALLOW),
                    "prod", Map.of("verify_handshake", Decision.ALLOW, "renew_certificate", Decision.DENY)));
            var props = new AgentProperties(targets, policy,
                    new AgentProperties.Risk(Duration.ofHours(6), Duration.ofMinutes(30), 2048, 256, List.of()),
                    new AgentProperties.Acme("https://localhost:1/acme/acme/directory", tmp.resolve("acct.pem"),
                            tmp.resolve("webroot").toString(), Duration.ofSeconds(1), Duration.ofSeconds(2)),
                    null, null, new AgentProperties.Notification(null), new AgentProperties.Schedule("-", false),
                    tmp.resolve("events.jsonl"));

            var events = new EventLog(props, new ObjectMapper().findAndRegisterModules());
            var scanner = new EndpointScanner(props, TrustConfig.fromRoots(List.of(labRoot.cert())));
            var gate = new PolicyGate(props, events);
            // No CA is listening on localhost:1, so the lab renewal fails before touching anything.
            var tools = new CertTools(props, scanner, gate, events,
                    new dev.certagent.acme.AcmeClient(props, TrustConfig.fromRoots(List.of(labRoot.cert()))), null);

            var model = new ScriptedChatModel(prompt -> {
                if (prompt.contains("Case: target demo.lab")) return new Script(List.of(
                        new Call("verify_handshake", args("demo.lab", "Issuer is Rogue Corp Root; confirm it is still served.")),
                        new Call("renew_certificate", args("demo.lab", "Untrusted issuer; renew from the lab ACME CA."))),
                        "demo.lab served a rogue cert; renewal attempted.");
                if (prompt.contains("Case: target shop.prod")) return new Script(List.of(
                        new Call("verify_handshake", args("shop.prod", "Expires in about 3h; confirm.")),
                        new Call("renew_certificate", args("shop.prod", "Inside the renew window; renew."))),
                        "shop.prod needs renewal but policy requires approval.");
                return new Script(List.of(), "One fixed, one waiting for approval, one healthy.");
            });
            var runner = new CertAgentRunner(props, scanner, tools, gate, events,
                    new Notifier(props, events, RestClient.builder()), new AgentModel(model, "scripted", "local"));

            runner.runCycle("run-test");

            // Healthy target never reaches the model; two cases plus one summary call do.
            assertThat(model.userPrompts).hasSize(3);
            assertThat(model.userPrompts.get(0)).contains("Risk: CRITICAL", "Rogue Corp Root");
            assertThat(model.userPrompts.get(1)).contains("Risk: WARN", "renew window");

            // What the model actually reads back; Spring AI JSON-encodes String results, so strip the quotes.
            assertThat(model.toolResults).map(r -> r.replace("-> \"", "-> ")).satisfiesExactly(
                    r -> assertThat(r).startsWith("verify_handshake -> FAIL demo.lab: chain does not validate"),
                    r -> assertThat(r).startsWith("renew_certificate -> FAILED: ACME issuance from https://localhost:1/acme/acme/directory failed"),
                    r -> assertThat(r).startsWith("verify_handshake -> OK shop.prod: trusted chain"),
                    r -> assertThat(r).startsWith("renew_certificate -> DENIED: policy for env 'prod'"));

            // Every tool call left a POLICY event carrying the model's reasoning and a badge.
            List<Event> shopCase = events.forCase("run-test", "shop.prod");
            assertThat(shopCase).filteredOn(e -> e.kind() == Kind.POLICY)
                    .extracting(e -> e.details().get("badge"), e -> e.details().get("reasoning"))
                    .containsExactly(
                            org.assertj.core.groups.Tuple.tuple("AUTO · prod", "Expires in about 3h; confirm."),
                            org.assertj.core.groups.Tuple.tuple("APPROVAL NEEDED · prod", "Inside the renew window; renew."));
            assertThat(shopCase).extracting(Event::kind)
                    .containsExactly(Kind.SCAN, Kind.DIAGNOSE, Kind.PLAN, Kind.POLICY, Kind.VERIFY, Kind.POLICY, Kind.DONE);

            // Outcomes come from the timeline, not the model's words.
            assertThat(events.forCase("run-test", "shop.prod").getLast().message()).isEqualTo("Needs approval");
            assertThat(events.forCase("run-test", "demo.lab").getLast().message()).isEqualTo("Failed safely");
            assertThat(events.forCase("run-test", "ok.lab").getLast().message()).isEqualTo("Healthy");

            Event done = events.forCase("run-test", null).getLast();
            assertThat(done.kind()).isEqualTo(Kind.DONE);
            assertThat(done.message()).isEqualTo("One fixed, one waiting for approval, one healthy.");
            assertThat(done.details()).containsEntry("summaryBy", "scripted · local");
            assertThat(runner.hosting()).isEqualTo("local");
            assertThat(done.details().get("counts"))
                    .isEqualTo(Map.of("Failed safely", 1, "Needs approval", 1, "Healthy", 1));

            // The JSONL file reloads into an identical timeline.
            var reloaded = new EventLog(props, new ObjectMapper().findAndRegisterModules());
            assertThat(reloaded.since(0)).hasSameSizeAs(events.since(0));
            assertThat(reloaded.since(0).getLast().message()).isEqualTo(done.message());
        }
    }

    /** One unreachable lab target, so the case reaches the model and the run needs a summary. */
    private CertAgentRunner runnerWith(AgentModel model, EventLog[] eventsOut) throws Exception {
        int closedPort;
        try (var s = new java.net.ServerSocket(0)) {
            closedPort = s.getLocalPort();
        }
        var props = new AgentProperties(
                List.of(new Target("demo.lab", "localhost", closedPort, "demo.lab", "lab", null, null, null)),
                new AgentProperties.Policy(false, 10, Map.of("lab", Map.of("verify_handshake", Decision.ALLOW))),
                new AgentProperties.Risk(Duration.ofHours(6), Duration.ofMinutes(30), 2048, 256, List.of()),
                null, null, null, new AgentProperties.Notification(null), new AgentProperties.Schedule("-", false),
                tmp.resolve("events.jsonl"));
        var events = new EventLog(props, new ObjectMapper().findAndRegisterModules());
        eventsOut[0] = events;
        var scanner = new EndpointScanner(props, TrustConfig.fromRoots(List.of(TestPki.root("Root").cert())));
        var gate = new PolicyGate(props, events);
        var tools = new CertTools(props, scanner, gate, events, null, null);
        return new CertAgentRunner(props, scanner, tools, gate, events,
                new Notifier(props, events, RestClient.builder()), model);
    }

    @Test
    void activeModelDecidesAndWritesTheSummaryAndIsLabelledWithWhereItRuns() throws Exception {
        var spark = new ScriptedChatModel(p -> new Script(List.of(),
                p.startsWith("Case:") ? "demo.lab is unreachable; nothing to renew." : "Spark: demo.lab could not be reached."));
        EventLog[] events = new EventLog[1];

        var runner = runnerWith(new AgentModel(spark, "muse-spark-1.3", "Meta Model API"), events);
        runner.runCycle("run-spark");

        // One model handles both the case and the summary; the summary prompt holds outcomes, not tools.
        assertThat(spark.userPrompts).hasSize(2);
        assertThat(spark.userPrompts.get(0)).startsWith("Case: target demo.lab");
        assertThat(spark.userPrompts.get(1)).contains("- demo.lab: Unresolved — demo.lab is unreachable; nothing to renew.");

        List<Event> runEvents = events[0].forCase("run-spark", null);
        assertThat(runEvents.getFirst().details()).containsEntry("model", "muse-spark-1.3 · Meta Model API");
        assertThat(events[0].forCase("run-spark", "demo.lab"))
                .anySatisfy(e -> assertThat(e.message()).isEqualTo("asking muse-spark-1.3 · Meta Model API to decide"));
        Event done = runEvents.getLast();
        assertThat(done.message()).isEqualTo("Spark: demo.lab could not be reached.");
        assertThat(done.details()).containsEntry("summaryBy", "muse-spark-1.3 · Meta Model API");
        assertThat(runner.model()).isEqualTo("muse-spark-1.3");
        assertThat(runner.hosting()).isEqualTo("Meta Model API");
    }

    @Test
    void summaryFailureFallsBackToTheRuleBasedLineAndIsRecorded() throws Exception {
        var model = new ScriptedChatModel(p -> {
            if (p.startsWith("Case:")) return new Script(List.of(), "Unreachable.");
            throw new IllegalStateException("401 Unauthorized");
        });
        EventLog[] events = new EventLog[1];

        runnerWith(new AgentModel(model, "muse-spark-1.3", "Meta Model API"), events).runCycle("run-fallback");

        List<Event> runEvents = events[0].forCase("run-fallback", null);
        assertThat(runEvents).filteredOn(e -> e.kind() == Kind.ERROR).singleElement()
                .satisfies(e -> assertThat(e.message()).contains(
                        "summary by muse-spark-1.3 · Meta Model API failed", "401 Unauthorized", "rule-based"));
        Event done = runEvents.getLast();
        assertThat(done.message()).isEqualTo("1 target(s) checked: demo.lab unresolved.");
        assertThat(done.details()).containsEntry("summaryBy", "rule-based");
    }

    @Test
    void outcomeIsDerivedFromEvents() {
        Event applyOk = ev(Kind.APPLY, Map.of("changed", true));
        Event issueFailed = ev(Kind.APPLY, Map.of("changed", false));
        Event verifyOk = ev(Kind.VERIFY, Map.of("ok", true));
        Event verifyFail = ev(Kind.VERIFY, Map.of("ok", false));
        Event rollback = ev(Kind.ROLLBACK, Map.of());
        Event denyRenew = ev(Kind.POLICY, Map.of("decision", "DENY", "tool", "renew_certificate"));
        Event denyVerify = ev(Kind.POLICY, Map.of("decision", "DENY", "tool", "verify_handshake"));
        Event dryRenew = ev(Kind.POLICY, Map.of("decision", "DRY_RUN", "tool", "renew_certificate"));

        assertThat(CertAgentRunner.outcome(List.of(applyOk, verifyOk))).isEqualTo("Fixed");
        assertThat(CertAgentRunner.outcome(List.of(applyOk, verifyFail, rollback, verifyOk))).isEqualTo("Rolled back");
        assertThat(CertAgentRunner.outcome(List.of(applyOk, verifyFail))).isEqualTo("Unresolved");
        assertThat(CertAgentRunner.outcome(List.of(verifyOk, denyRenew))).isEqualTo("Needs approval");
        assertThat(CertAgentRunner.outcome(List.of(denyVerify))).isEqualTo("Unresolved");
        assertThat(CertAgentRunner.outcome(List.of(dryRenew))).isEqualTo("Dry run");
        assertThat(CertAgentRunner.outcome(List.of(verifyFail, issueFailed))).isEqualTo("Failed safely");
    }

    private static Event ev(Kind kind, Map<String, Object> details) {
        return new Event(0, java.time.Instant.now(), "r", "t", kind, "", details);
    }
}
