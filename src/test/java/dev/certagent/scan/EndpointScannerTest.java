package dev.certagent.scan;

import dev.certagent.config.AgentProperties;
import dev.certagent.config.AgentProperties.Target;
import dev.certagent.config.TrustConfig;
import dev.certagent.model.CertRecord;
import dev.certagent.model.CertRecord.Level;
import dev.certagent.scan.TestPki.Issued;
import dev.certagent.scan.TestPki.TlsServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Real handshakes against a local TLS server; mirrors the three lab break modes plus a few edges. */
class EndpointScannerTest {

    static final AgentProperties.Risk RULES = new AgentProperties.Risk(
            Duration.ofHours(6), Duration.ofMinutes(30), 2048, 256, List.of("SHA1withRSA"));

    static Issued labRoot;
    static Issued rogueRoot;
    static TrustConfig.TrustBundle trust;

    @BeforeAll
    static void pki() throws Exception {
        labRoot = TestPki.root("Test Lab Root");
        rogueRoot = TestPki.root("Rogue Corp Root");
        trust = TrustConfig.fromRoots(List.of(labRoot.cert()));
    }

    static EndpointScanner scanner(int port, String env) {
        var target = new Target("demo.lab", "localhost", port, "demo.lab", env, null, null, null);
        var props = new AgentProperties(List.of(target), null, RULES, null, null, null, null, null, null);
        return new EndpointScanner(props, trust);
    }

    static CertRecord scanServing(Issued leaf) throws Exception {
        try (var server = new TlsServer(leaf)) {
            var s = scanner(server.port(), "lab");
            return s.scanAll().getFirst();
        }
    }

    @Test
    void healthyCertIsOk() throws Exception {
        CertRecord c = scanServing(TestPki.leaf(labRoot, "demo.lab", Duration.ofHours(24)));

        assertThat(c.handshakeError()).isNull();
        assertThat(c.trusted()).isTrue();
        assertThat(c.hostnameMatches()).isTrue();
        assertThat(c.sans()).containsExactly("demo.lab");
        assertThat(c.keyType()).isEqualTo("RSA");
        assertThat(c.keyBits()).isEqualTo(2048);
        assertThat(c.issuer()).isEqualTo("CN=Test Lab Root");
        assertThat(c.fingerprintSha256()).hasSize(64);
        assertThat(c.risk().level()).isEqualTo(Level.OK);
        assertThat(c.risk().reasons()).isEmpty();
    }

    @Test
    void untrustedIssuerIsCritical() throws Exception {
        CertRecord c = scanServing(TestPki.leaf(rogueRoot, "demo.lab", Duration.ofDays(30)));

        assertThat(c.trusted()).isFalse();
        assertThat(c.issuer()).isEqualTo("CN=Rogue Corp Root");
        assertThat(c.risk().level()).isEqualTo(Level.CRITICAL);
        assertThat(c.risk().reasons()).singleElement().asString()
                .contains("does not validate to a trusted root", "Rogue Corp Root");
    }

    @Test
    void weakKeyIsCritical() throws Exception {
        Instant now = Instant.now();
        CertRecord c = scanServing(TestPki.leaf(labRoot, "demo.lab", 1024,
                now.minus(Duration.ofMinutes(5)), now.plus(Duration.ofHours(24))));

        assertThat(c.trusted()).isTrue();
        assertThat(c.keyBits()).isEqualTo(1024);
        assertThat(c.risk().level()).isEqualTo(Level.CRITICAL);
        assertThat(c.risk().reasons()).singleElement().asString().contains("weak key: RSA 1024 bits");
    }

    @Test
    void expiringSoonIsCriticalInsideWindowAndWarnBeforeIt() throws Exception {
        CertRecord soon = scanServing(TestPki.leaf(labRoot, "demo.lab", Duration.ofMinutes(10)));
        assertThat(soon.risk().level()).isEqualTo(Level.CRITICAL);
        assertThat(soon.risk().reasons()).singleElement().asString().startsWith("expires in 9m");

        CertRecord later = scanServing(TestPki.leaf(labRoot, "demo.lab", Duration.ofHours(3)));
        assertThat(later.risk().level()).isEqualTo(Level.WARN);
        assertThat(later.risk().reasons()).singleElement().asString().contains("renew window 6h");
    }

    @Test
    void expiredCertIsCritical() throws Exception {
        Instant now = Instant.now();
        CertRecord c = scanServing(TestPki.leaf(labRoot, "demo.lab", 2048,
                now.minus(Duration.ofDays(2)), now.minus(Duration.ofHours(1))));

        assertThat(c.risk().level()).isEqualTo(Level.CRITICAL);
        assertThat(c.risk().reasons()).anyMatch(r -> r.startsWith("expired 1h"));
    }

    @Test
    void wrongHostnameIsCritical() throws Exception {
        CertRecord c = scanServing(TestPki.leaf(labRoot, "other.lab", Duration.ofHours(24)));

        assertThat(c.hostnameMatches()).isFalse();
        assertThat(c.risk().reasons()).singleElement().asString().contains("hostname demo.lab not in");
    }

    @Test
    void closedPortReportsHandshakeFailure() throws Exception {
        int port;
        try (var s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        CertRecord c = scanner(port, "lab").scanAll().getFirst();

        assertThat(c.handshakeError()).contains("ConnectException");
        assertThat(c.fingerprintSha256()).isNull();
        assertThat(c.risk().level()).isEqualTo(Level.CRITICAL);
        assertThat(c.risk().reasons()).singleElement().asString().startsWith("handshake failed");
    }

    @Test
    void verifyPassesForHealthyAndFailsForBroken() throws Exception {
        try (var server = new TlsServer(TestPki.leaf(labRoot, "demo.lab", Duration.ofHours(24)))) {
            var v = scanner(server.port(), "lab").verify("localhost", server.port(), "demo.lab");
            assertThat(v.ok()).isTrue();
            assertThat(v.summary()).startsWith("trusted chain, hostname matches, expires");
            assertThat(v.cert().env()).isEqualTo("lab");
        }
        try (var server = new TlsServer(TestPki.leaf(rogueRoot, "demo.lab", Duration.ofHours(24)))) {
            var v = scanner(server.port(), "lab").verify("localhost", server.port(), "demo.lab");
            assertThat(v.ok()).isFalse();
            assertThat(v.summary()).contains("Rogue Corp Root");
        }
    }

    @Test
    void wildcardMatchesExactlyOneLabel() {
        assertThat(EndpointScanner.hostnameMatches("a.example.com", List.of("*.example.com"))).isTrue();
        assertThat(EndpointScanner.hostnameMatches("A.Example.com", List.of("*.example.com"))).isTrue();
        assertThat(EndpointScanner.hostnameMatches("a.b.example.com", List.of("*.example.com"))).isFalse();
        assertThat(EndpointScanner.hostnameMatches("example.com", List.of("*.example.com"))).isFalse();
    }

    @Test
    void compactDurations() {
        assertThat(EndpointScanner.ago(Duration.ofMinutes(9))).isEqualTo("9m");
        assertThat(EndpointScanner.ago(Duration.ofMinutes(192))).isEqualTo("3h12m");
        assertThat(EndpointScanner.ago(Duration.ofHours(6))).isEqualTo("6h");
        assertThat(EndpointScanner.ago(Duration.ofHours(124))).isEqualTo("5d4h");
    }
}
