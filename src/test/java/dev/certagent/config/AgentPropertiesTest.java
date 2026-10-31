package dev.certagent.config;

import dev.certagent.config.AgentProperties.Decision;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = AgentPropertiesTest.Config.class)
class AgentPropertiesTest {

    @EnableConfigurationProperties(AgentProperties.class)
    static class Config {
    }

    @Autowired
    AgentProperties props;

    @Test
    void bindsTargetsFromApplicationYml() {
        assertThat(props.targets()).extracting(AgentProperties.Target::name)
                .containsExactly("demo.lab", "shop.prod");
        assertThat(props.targets().get(1).env()).isEqualTo("prod");
        assertThat(props.targets().getFirst().domainsOrSni()).containsExactly("demo.lab");
        assertThat(props.risk().criticalWithin()).isEqualTo(Duration.ofMinutes(30));
        assertThat(props.install().reloadCommand()).startsWith("docker", "compose");
    }

    @Test
    void policyFromConfig() {
        assertThat(props.policy().decide("lab", "renew_certificate")).isEqualTo(Decision.ALLOW);
        assertThat(props.policy().decide("prod", "renew_certificate")).isEqualTo(Decision.DENY);
    }

    @Test
    void unknownToolOrEnvIsDenied() {
        assertThat(props.policy().decide("lab", "delete_everything")).isEqualTo(Decision.DENY);
        assertThat(props.policy().decide("staging", "verify_handshake")).isEqualTo(Decision.DENY);
    }

    @Test
    void dryRunDowngradesAllowOnly() {
        var policy = new AgentProperties.Policy(true, 10, Map.of(
                "lab", Map.of("renew_certificate", Decision.ALLOW, "rollback", Decision.DENY)));
        assertThat(policy.decide("lab", "renew_certificate")).isEqualTo(Decision.DRY_RUN);
        assertThat(policy.decide("lab", "rollback")).isEqualTo(Decision.DENY);
    }
}
