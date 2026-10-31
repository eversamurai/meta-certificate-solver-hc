package dev.certagent.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/** What the agent trusts: the JVM's roots plus any extra roots from config (the lab root CA). */
@Configuration
public class TrustConfig {

    private static final Logger log = LoggerFactory.getLogger(TrustConfig.class);

    public record TrustBundle(SSLContext sslContext, X509TrustManager trustManager) {
    }

    @Bean
    TrustBundle trustBundle(AgentProperties props) throws GeneralSecurityException, IOException {
        List<Path> extra = props.trust() == null || props.trust().extraRoots() == null
                ? List.of() : props.trust().extraRoots();
        return build(extra);
    }

    /** Missing extra roots are skipped with a warning so the app still starts before lab/init.sh has run. */
    public static TrustBundle build(List<Path> extraRoots) throws GeneralSecurityException, IOException {
        List<X509Certificate> roots = new ArrayList<>(List.of(jvmDefaultTrustManager().getAcceptedIssuers()));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (Path p : extraRoots) {
            if (!Files.isReadable(p)) {
                log.warn("Extra trust root {} not found; run ./lab/init.sh to create it", p);
                continue;
            }
            try (InputStream in = Files.newInputStream(p)) {
                Collection<? extends java.security.cert.Certificate> certs = cf.generateCertificates(in);
                certs.forEach(c -> roots.add((X509Certificate) c));
                log.info("Trusting {} extra root(s) from {}", certs.size(), p);
            }
        }
        return fromRoots(roots);
    }

    public static TrustBundle fromRoots(List<X509Certificate> roots) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        for (int i = 0; i < roots.size(); i++) {
            ks.setCertificateEntry("root-" + i, roots.get(i));
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager tm = firstX509(tmf.getTrustManagers());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{tm}, null);
        return new TrustBundle(ctx, tm);
    }

    private static X509TrustManager jvmDefaultTrustManager() throws GeneralSecurityException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        return firstX509(tmf.getTrustManagers());
    }

    private static X509TrustManager firstX509(TrustManager[] tms) {
        for (TrustManager tm : tms) {
            if (tm instanceof X509TrustManager x) return x;
        }
        throw new IllegalStateException("No X509TrustManager available");
    }
}
