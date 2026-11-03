package dev.certagent.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Calls the real Meta Model API, so it only runs when MODEL_API_KEY is set; normal builds skip it.
 * Checks the actual client setup (base URL, path, auth, model, reasoning effort) that unit tests stub out.
 */
@EnabledIfEnvironmentVariable(named = "MODEL_API_KEY", matches = ".+")
class SparkSummarizerLiveTest {

    @Test
    void museSparkWritesASummaryFromOutcomeFacts() {
        var spark = new SparkSummarizer(System.getenv("MODEL_API_KEY"), "https://api.meta.ai",
                System.getenv().getOrDefault("MUSE_SPARK_MODEL", "muse-spark-1.3"), Duration.ofSeconds(60));

        String summary = spark.summarize("""
                Write exactly 3 sentences for the on-call channel summarising this run. \
                Use only these facts; do not add advice beyond what a human must approve.
                - demo.lab: Fixed — served a cert from the untrusted Rogue Corp Root; renewed from the lab ACME CA, handshake passes.
                - shop.prod: Needs approval — expires in about 3 hours; renewal denied by prod policy.""");

        assertThat(spark.enabled()).isTrue();
        assertThat(summary).isNotBlank().containsIgnoringCase("demo.lab").containsIgnoringCase("shop.prod");
    }
}
