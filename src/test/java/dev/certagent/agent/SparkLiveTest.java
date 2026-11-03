package dev.certagent.agent;

import dev.certagent.config.ModelConfig;
import dev.certagent.model.CertRecord;
import dev.certagent.model.CertRecord.Level;
import dev.certagent.model.CertRecord.Risk;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Calls the real Meta Model API, so it only runs when MODEL_API_KEY is set; normal builds skip it.
 * Real system prompt and case prompt, stand-in tools: checks Muse Spark calls the tools through Spring AI
 * with the arguments the contract needs, in the order the prompt asks for.
 */
@EnabledIfEnvironmentVariable(named = "MODEL_API_KEY", matches = ".+")
class SparkLiveTest {

    /** Stand-ins with the real names and result prefixes; renewal "works" so the model should verify again. */
    static class Tools {
        final List<String> calls = new ArrayList<>();
        boolean renewed;

        @Tool(name = "verify_handshake", description = "Strict TLS handshake against a target. Read-only. Call before and after any change.")
        String verifyHandshake(@ToolParam(description = "Target name") String target,
                               @ToolParam(description = "Why you are checking this now") String reasoning) {
            calls.add("verify_handshake|" + target + "|" + reasoning);
            return renewed
                    ? "OK demo.lab: trusted chain, hostname matches, expires in 23h59m | served: issuer=CN=CertAgent Lab CA Intermediate CA"
                    : "FAIL demo.lab: chain does not validate to a trusted root (issuer CN=Rogue Corp Root) | served: issuer=CN=Rogue Corp Root";
        }

        @Tool(name = "renew_certificate", description = "Renew the target's certificate from its ACME CA, install, reload, verify; rolls back on failure.")
        String renewCertificate(@ToolParam(description = "Target name") String target,
                                @ToolParam(description = "What is wrong and why renewal fixes it") String reasoning) {
            calls.add("renew_certificate|" + target + "|" + reasoning);
            renewed = true;
            return "SUCCESS: renewed and installed demo.lab; strict handshake now: trusted chain, hostname matches";
        }

        @Tool(name = "rollback", description = "Restore the last backup for the target. renew_certificate already rolls back on its own.")
        String rollback(@ToolParam(description = "Target name") String target,
                        @ToolParam(description = "Why") String reasoning) {
            calls.add("rollback|" + target + "|" + reasoning);
            return "ERROR: not expected in this test";
        }
    }

    /** Facts from the real run run-20261102-233317-ca0a, whose summary came back far too long for the timeline. */
    @Test
    void museSparkKeepsTheRunSummaryShort() {
        var spark = ModelConfig.spark(System.getenv("MODEL_API_KEY"), "https://api.meta.ai",
                System.getenv().getOrDefault("MUSE_SPARK_MODEL", "muse-spark-1.3"), "low", Duration.ofSeconds(120));
        String facts = """
                - demo.lab: Fixed — The certificate for demo.lab was issued by untrusted CN=Rogue Corp Root, causing chain validation to fail despite valid hostname and expiry. I renewed it via the trusted Lab CA, installing an RSA 2048 cert for demo.lab. Final handshake shows OK with trusted chain and hostname match, expiring in ~24h.
                - shop.prod: Needs approval — Certificate for shop.prod is expiring in ~3h52m (within 6h renew window) but otherwise healthy with trusted Lab CA Intermediate issuer and matching hostname. Attempted renewal was DENIED by prod policy, so no change was made and human approval is required. Final state remains trusted and matching but expiring imminently at 2026-11-03T08:25:49Z.
                - accounts.lab: Healthy""";

        String summary = ChatClient.builder(spark).defaultSystem(CertAgentRunner.SYSTEM).build()
                .prompt().user(CertAgentRunner.summaryPrompt(facts)).call().content().strip();
        System.out.println("Spark summary (" + summary.split("\\s+").length + " words): " + summary);

        assertThat(summary.split("\\s+").length).as("words").isLessThanOrEqualTo(60);
        assertThat(summary).contains("shop.prod", "demo.lab").doesNotContain("2026-11");
    }

    @Test
    void museSparkDiagnosesRenewsAndVerifiesThroughTheTools() {
        var spark = ModelConfig.spark(System.getenv("MODEL_API_KEY"), "https://api.meta.ai",
                System.getenv().getOrDefault("MUSE_SPARK_MODEL", "muse-spark-1.3"), "low", Duration.ofSeconds(120));
        String reason = "chain does not validate to a trusted root (issuer CN=Rogue Corp Root): "
                + "SunCertPathBuilderException: unable to find valid certification path to requested target";
        var rogue = new CertRecord("demo.lab", "lab", "localhost", 8443, "demo.lab", Instant.now(),
                "CN=demo.lab", "CN=Rogue Corp Root", List.of("demo.lab"), Instant.now().minusSeconds(60),
                Instant.now().plus(Duration.ofDays(30)), "7c1e9a4be2d05f3318a6c9e0b47d21f5c8e93a6d0b1f24e78c5a9d3e6f10b2c4",
                "RSA", 2048, "SHA256withRSA", 1, false, true, null, new Risk(Level.CRITICAL, List.of(reason)));
        var tools = new Tools();

        long t0 = System.nanoTime();
        String answer = ChatClient.builder(spark).defaultSystem(CertAgentRunner.SYSTEM).build()
                .prompt().user(CertAgentRunner.casePrompt(rogue)).tools(tools).call().content();
        System.out.printf("Spark case took %.1fs; calls: %s%n", (System.nanoTime() - t0) / 1e9, tools.calls);
        System.out.println("Spark answer: " + answer);

        assertThat(tools.calls).as("verify first, then renew").hasSizeGreaterThanOrEqualTo(2);
        assertThat(tools.calls.get(0)).startsWith("verify_handshake|demo.lab|");
        assertThat(tools.calls).anySatisfy(c -> assertThat(c).startsWith("renew_certificate|demo.lab|"));
        assertThat(tools.calls).allSatisfy(c -> assertThat(c.split("\\|", 3)[2]).as("reasoning").hasSizeGreaterThan(20));
        assertThat(tools.calls).noneMatch(c -> c.startsWith("rollback"));
        assertThat(answer).isNotBlank();
    }
}
