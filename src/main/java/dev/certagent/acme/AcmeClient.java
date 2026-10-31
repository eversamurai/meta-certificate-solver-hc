package dev.certagent.acme;

import dev.certagent.config.AgentProperties;
import dev.certagent.config.TrustConfig.TrustBundle;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.GenericAcmeProvider;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Gets a fresh certificate from the configured ACME CA using http-01: the challenge file is written into
 * the webroot that nginx serves on port 80, and the CA fetches it from http://&lt;domain&gt;/.well-known/….
 * Talks to the CA over HTTPS with the agent's own trust bundle (JVM roots + lab root).
 */
@Component
public class AcmeClient {

    private static final Logger log = LoggerFactory.getLogger(AcmeClient.class);

    private final AgentProperties.Acme acme;
    private final TrustBundle trust;

    public AcmeClient(AgentProperties props, TrustBundle trust) {
        this.acme = props.acme();
        this.trust = trust;
    }

    /** A new key and the full chain the CA returned, both PEM. {@code leaf} is the first cert of the chain. */
    public record Issued(String chainPem, String keyPem, X509Certificate leaf) {
    }

    public Issued issue(List<String> domains) throws AcmeException, IOException, InterruptedException {
        Session session = new Session(URI.create(acme.directoryUrl()), new TrustingProvider(trust));
        session.networkSettings().setTimeout(acme.timeout());

        var account = new AccountBuilder()
                .agreeToTermsOfService()
                .useKeyPair(accountKey())
                .create(session);

        Order order = account.newOrder().domains(domains).create();
        List<Path> challengeFiles = new ArrayList<>();
        try {
            for (Authorization auth : order.getAuthorizations()) {
                if (auth.getStatus() == Status.VALID) continue;
                Http01Challenge ch = auth.findChallenge(Http01Challenge.class)
                        .orElseThrow(() -> new AcmeException("CA offered no http-01 challenge for " + auth.getIdentifier()));
                challengeFiles.add(writeChallenge(ch));
                ch.trigger();
                Status s = auth.waitForCompletion(acme.timeout());
                if (s != Status.VALID) {
                    throw new AcmeException("http-01 for " + auth.getIdentifier().getDomain() + " ended " + s
                            + ch.getError().map(p -> ": " + p).orElse(""));
                }
            }

            order.waitUntilReady(acme.timeout());
            KeyPair domainKey = KeyPairUtils.createKeyPair(2048);
            order.execute(domainKey);
            Status s = order.waitForCompletion(acme.timeout());
            if (s != Status.VALID) {
                throw new AcmeException("order ended " + s + order.getError().map(p -> ": " + p).orElse(""));
            }

            var cert = order.getCertificate();
            StringWriter chain = new StringWriter();
            cert.writeCertificate(chain);
            StringWriter key = new StringWriter();
            KeyPairUtils.writeKeyPair(domainKey, key);
            log.info("ACME issued {} for {} (expires {})", cert.getCertificate().getSubjectX500Principal(),
                    domains, cert.getCertificate().getNotAfter());
            return new Issued(chain.toString(), key.toString(), cert.getCertificate());
        } finally {
            for (Path p : challengeFiles) Files.deleteIfExists(p);
        }
    }

    private Path writeChallenge(Http01Challenge ch) throws IOException {
        Path dir = Path.of(acme.webroot(), ".well-known", "acme-challenge");
        Files.createDirectories(dir);
        Path file = dir.resolve(ch.getToken());
        Files.writeString(file, ch.getAuthorization(), StandardCharsets.US_ASCII);
        return file;
    }

    /** One account key per agent install, created on first use. */
    private KeyPair accountKey() throws IOException {
        Path p = acme.accountKey();
        if (Files.exists(p)) {
            try (Reader r = Files.newBufferedReader(p)) {
                return KeyPairUtils.readKeyPair(r);
            }
        }
        KeyPair kp = KeyPairUtils.createKeyPair(2048);
        if (p.getParent() != null) Files.createDirectories(p.getParent());
        try (Writer w = Files.newBufferedWriter(p)) {
            KeyPairUtils.writeKeyPair(kp, w);
        }
        log.info("Created ACME account key {}", p);
        return kp;
    }

    /** Generic ACME provider whose HTTP client trusts our bundle instead of only the JVM defaults. */
    private static final class TrustingProvider extends GenericAcmeProvider {
        private final TrustBundle trust;

        TrustingProvider(TrustBundle trust) {
            this.trust = trust;
        }

        @Override
        protected HttpConnector createHttpConnector(NetworkSettings settings) {
            return new HttpConnector(settings) {
                @Override
                public HttpClient.Builder createClientBuilder() {
                    return super.createClientBuilder().sslContext(trust.sslContext());
                }
            };
        }
    }
}
