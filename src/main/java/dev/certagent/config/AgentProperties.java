package dev.certagent.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/** Typed view of {@code certagent.*} in application.yml. */
@Validated
@ConfigurationProperties(prefix = "certagent")
public record AgentProperties(
        @NotEmpty @Valid List<Target> targets,
        @Valid Policy policy,
        @Valid Risk risk,
        @Valid Acme acme,
        @Valid Trust trust,
        @Valid Install install,
        Notification notification,
        @Valid Schedule schedule,
        @DefaultValue("data/events.jsonl") Path eventLog) {

    /** One HTTPS endpoint the agent watches. certPath/keyPath say where its nginx reads the cert. */
    public record Target(
            @NotBlank String name,
            @NotBlank String host,
            @DefaultValue("443") int port,
            String sni,
            @NotBlank String env,
            List<String> domains,
            Path certPath,
            Path keyPath) {

        public String serverName() {
            return sni != null && !sni.isBlank() ? sni : host;
        }

        public List<String> domainsOrSni() {
            return domains != null && !domains.isEmpty() ? domains : List.of(serverName());
        }
    }

    public enum Decision { ALLOW, DRY_RUN, DENY }

    /**
     * Per environment, per tool name → decision. A tool missing from an environment is DENY.
     * {@code dryRun: true} downgrades every ALLOW to DRY_RUN for the whole run.
     */
    public record Policy(
            @DefaultValue("false") boolean dryRun,
            @DefaultValue("10") int maxActionsPerRun,
            Map<String, Map<String, Decision>> environments) {

        public Decision decide(String env, String tool) {
            Decision d = environments == null ? null
                    : environments.getOrDefault(env, Map.of()).get(tool);
            if (d == null) return Decision.DENY;
            return dryRun && d == Decision.ALLOW ? Decision.DRY_RUN : d;
        }
    }

    /** Thresholds for the deterministic risk rules. */
    public record Risk(
            @DefaultValue("14d") Duration warnWithin,
            @DefaultValue("3d") Duration criticalWithin,
            @DefaultValue("2048") int minRsaBits,
            @DefaultValue("256") int minEcBits,
            @DefaultValue({"SHA1withRSA", "MD5withRSA", "SHA1withECDSA"}) List<String> forbiddenSigAlgs) {
    }

    public record Acme(
            @NotBlank String directoryUrl,
            @DefaultValue("data/acme-account.pem") Path accountKey,
            @NotBlank String webroot,
            @DefaultValue("3s") Duration pollInterval,
            @DefaultValue("60s") Duration timeout) {
    }

    /** Extra roots trusted on top of the JVM's own (the lab root CA). */
    public record Trust(List<Path> extraRoots) {
    }

    public record Install(
            @DefaultValue("data/backups") Path backupDir,
            @NotEmpty List<String> reloadCommand,
            @DefaultValue("3s") Duration settleAfterReload) {
    }

    public record Notification(String webhookUrl) {
    }

    public record Schedule(
            @DefaultValue("0 0 6 * * *") String cron,
            @DefaultValue("true") boolean runOnStartup) {
    }
}
