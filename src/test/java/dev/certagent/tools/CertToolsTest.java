package dev.certagent.tools;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.certagent.acme.AcmeClient;
import dev.certagent.config.AgentProperties;
import dev.certagent.config.AgentProperties.Decision;
import dev.certagent.config.AgentProperties.Target;
import dev.certagent.config.TrustConfig;
import dev.certagent.exec.NginxInstaller;
import dev.certagent.model.Event;
import dev.certagent.model.Event.Kind;
import dev.certagent.policy.PolicyGate;
import dev.certagent.scan.EndpointScanner;
import dev.certagent.scan.FileTlsServer;
import dev.certagent.scan.TestPki;
import dev.certagent.scan.TestPki.Issued;
import dev.certagent.store.EventLog;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shredzone.acme4j.exception.AcmeException;
import org.springframework.ai.chat.model.ToolContext;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Renewal and rollback end to end against a file-backed TLS server. Only the CA is stubbed: it hands back
 * a good cert, a cert from an untrusted CA, or an error, which covers every branch of the renew flow.
 */
class CertToolsTest {

    static Issued labRoot;
    static Issued rogueRoot;

    @TempDir
    Path tmp;

    Path certFile;
    Path keyFile;
    String originalCert;
    FileTlsServer server;
    EventLog events;
    CertTools tools;

    /** What the stub CA does on the next issue() call. */
    AcmeStub ca;
    /** When set, every reload() throws with this message, like nginx -t rejecting a broken config. */
    String brokenConfig;

    static final ToolContext CTX = new ToolContext(Map.of(CertTools.CTX_RUN_ID, "run-t"));

    interface AcmeStub {
        AcmeClient.Issued issue(List<String> domains) throws Exception;
    }

    @BeforeAll
    static void pki() throws Exception {
        labRoot = TestPki.root("Test Lab Root");
        rogueRoot = TestPki.root("Rogue Corp Root");
    }

    @BeforeEach
    void setUp() throws Exception {
        // Start in the "untrusted" break mode: demo.lab serves a rogue-signed cert.
        Issued rogueLeaf = TestPki.leaf(rogueRoot, "demo.lab", Duration.ofDays(30));
        certFile = tmp.resolve("server.crt");
        keyFile = tmp.resolve("server.key");
        originalCert = TestPki.certPem(rogueLeaf.cert());
        Files.writeString(certFile, originalCert);
        Files.writeString(keyFile, TestPki.keyPem(rogueLeaf.keys()));
        server = new FileTlsServer(certFile, keyFile);

        var targets = List.of(
                new Target("demo.lab", "localhost", server.port(), "demo.lab", "lab", null, certFile, keyFile),
                new Target("shop.prod", "localhost", server.port(), "demo.lab", "prod", null, certFile, keyFile));
        var policy = new AgentProperties.Policy(false, 20, Map.of(
                "lab", Map.of("verify_handshake", Decision.ALLOW, "renew_certificate", Decision.ALLOW,
                        "rollback", Decision.ALLOW),
                "prod", Map.of("verify_handshake", Decision.ALLOW)));
        var props = new AgentProperties(targets, policy,
                new AgentProperties.Risk(Duration.ofHours(6), Duration.ofMinutes(30), 2048, 256, List.of()),
                new AgentProperties.Acme("https://ca.test/acme/acme/directory", tmp.resolve("acct.pem"),
                        tmp.resolve("webroot").toString(), Duration.ofSeconds(1), Duration.ofSeconds(5)),
                null,
                new AgentProperties.Install(tmp.resolve("backups"), List.of("unused"), Duration.ZERO),
                new AgentProperties.Notification(null), null, tmp.resolve("events.jsonl"));

        events = new EventLog(props, new ObjectMapper().findAndRegisterModules());
        var trust = TrustConfig.fromRoots(List.of(labRoot.cert()));
        var scanner = new EndpointScanner(props, trust);
        var acme = new AcmeClient(props, trust) {
            @Override
            public Issued issue(List<String> domains) throws AcmeException, IOException {
                try {
                    return ca.issue(domains);
                } catch (AcmeException | IOException e) {
                    throw e;
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
        };
        var installer = new NginxInstaller(props) {
            @Override
            public void reload() throws IOException {
                if (brokenConfig != null) {
                    String msg = brokenConfig;
                    throw new IOException(msg);
                }
                try {
                    server.reload();
                } catch (Exception e) {
                    throw new IOException("reload failed: " + e.getMessage(), e);
                }
            }
        };
        tools = new CertTools(props, scanner, new PolicyGate(props, events), events, acme, installer);
    }

    @AfterEach
    void tearDown() throws Exception {
        server.close();
    }

    static AcmeStub issuing(Issued root) {
        return domains -> {
            Issued leaf = TestPki.leaf(root, domains.getFirst(), Duration.ofHours(24));
            return new AcmeClient.Issued(TestPki.certPem(leaf.cert(), root.cert()),
                    TestPki.keyPem(leaf.keys()), leaf.cert());
        };
    }

    List<Event> caseEvents() {
        return events.forCase("run-t", "demo.lab");
    }

    @Test
    void renewFixesUntrustedCertAndKeepsBackup() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        ca = domains -> {
            calls.incrementAndGet();
            assertThat(domains).containsExactly("demo.lab");
            return issuing(labRoot).issue(domains);
        };

        assertThat(tools.verifyHandshake("demo.lab", "check first", CTX)).startsWith("FAIL demo.lab");
        String r = tools.renewCertificate("demo.lab", "Rogue issuer; renew from lab CA.", CTX);

        assertThat(r).startsWith("SUCCESS: renewed and installed demo.lab")
                .contains("before: chain does not validate");
        assertThat(calls).hasValue(1);
        assertThat(tools.verifyHandshake("demo.lab", "prove it", CTX)).startsWith("OK demo.lab");

        // Backup holds exactly what was there before.
        Path backups = tmp.resolve("backups/demo.lab");
        try (var dirs = Files.list(backups)) {
            Path b = dirs.findFirst().orElseThrow();
            assertThat(Files.readString(b.resolve("cert.pem"))).isEqualTo(originalCert);
        }

        Event apply = caseEvents().stream().filter(e -> e.kind() == Kind.APPLY).findFirst().orElseThrow();
        assertThat(apply.details()).containsEntry("changed", true).containsKeys("backupId", "newFingerprint", "before");
        Event postVerify = caseEvents().stream()
                .filter(e -> e.kind() == Kind.VERIFY && "after".equals(e.details().get("phase"))).findFirst().orElseThrow();
        assertThat(postVerify.details()).containsEntry("ok", true).containsKeys("before", "served");
        assertThat(caseEvents()).noneMatch(e -> e.kind() == Kind.ROLLBACK);
    }

    @Test
    void acmeFailureChangesNothing() throws Exception {
        ca = domains -> {
            throw new AcmeException("connection refused");
        };

        String r = tools.renewCertificate("demo.lab", "renew", CTX);

        assertThat(r).startsWith("FAILED: ACME issuance").contains("connection refused", "Nothing was changed");
        assertThat(Files.readString(certFile)).isEqualTo(originalCert);
        assertThat(tmp.resolve("backups")).doesNotExist();
        assertThat(caseEvents()).filteredOn(e -> e.kind() == Kind.APPLY).singleElement()
                .satisfies(e -> assertThat(e.details()).containsEntry("changed", false));
    }

    @Test
    void certThatFailsVerificationIsRolledBackAutomatically() throws Exception {
        ca = issuing(rogueRoot); // CA hands back something we don't trust

        String r = tools.renewCertificate("demo.lab", "renew", CTX);

        assertThat(r).startsWith("FAILED: the new certificate did not pass verification")
                .contains("Automatically rolled back", "Rogue Corp Root");
        assertThat(Files.readString(certFile)).isEqualTo(originalCert);
        assertThat(caseEvents()).extracting(Event::kind).containsSubsequence(Kind.APPLY, Kind.VERIFY, Kind.ROLLBACK);
    }

    @Test
    void failedReloadIsRolledBackAutomatically() throws Exception {
        // Demo case 3: `break.sh reload` leaves a config that `nginx -t` rejects, so every reload fails —
        // including the one after restoring. nginx keeps serving what it had, which is the backup.
        ca = issuing(labRoot);
        String emerg = "reload exited 1: nginx: [emerg] invalid parameter \"max_fails=three\"";
        brokenConfig = emerg;

        String r = tools.renewCertificate("demo.lab", "renew", CTX);

        assertThat(r).startsWith("FAILED").contains("nginx: [emerg]", "Automatically rolled back");
        assertThat(Files.readString(certFile)).isEqualTo(originalCert);
        assertThat(caseEvents()).filteredOn(e -> e.kind() == Kind.ROLLBACK).singleElement()
                .satisfies(e -> {
                    assertThat(e.details()).containsEntry("reason", emerg)
                            .containsEntry("error", emerg)
                            .containsEntry("servesBackup", true);
                    assertThat(e.message()).contains("endpoint serves the backed-up certificate again",
                            "reload after restore also failed");
                });
    }

    @Test
    void rollbackToolRestoresLatestBackup() throws Exception {
        assertThat(tools.rollback("demo.lab", "undo", CTX)).startsWith("FAIL: no backup exists");

        ca = issuing(labRoot);
        assertThat(tools.renewCertificate("demo.lab", "renew", CTX)).startsWith("SUCCESS");
        assertThat(Files.readString(certFile)).isNotEqualTo(originalCert);

        String r = tools.rollback("demo.lab", "operator wants the old one back", CTX);
        // The restored cert is the rogue one, so the endpoint is back to failing — reported honestly.
        assertThat(r).startsWith("FAILED: restored backup").contains("Rogue Corp Root");
        assertThat(Files.readString(certFile)).isEqualTo(originalCert);
    }

    @Test
    void deniedRenewNeverReachesTheCa() throws Exception {
        ca = domains -> {
            throw new AssertionError("CA must not be called when policy denies");
        };

        String r = tools.renewCertificate("shop.prod", "renew", CTX);

        assertThat(r).startsWith("DENIED: policy for env 'prod'");
        assertThat(Files.readString(certFile)).isEqualTo(originalCert);
    }
}
