package dev.certagent.scan;

import dev.certagent.config.AgentProperties;
import dev.certagent.config.AgentProperties.Target;
import dev.certagent.config.TrustConfig.TrustBundle;
import dev.certagent.model.CertRecord;
import dev.certagent.model.CertRecord.Level;
import dev.certagent.model.CertRecord.Risk;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * Connects to each target, captures whatever chain it serves (trusted or not), and computes risk in code.
 * The model never decides whether a cert is bad; it reasons over what this class reports.
 */
@Component
public class EndpointScanner {

    private static final int TIMEOUT_MS = 5_000;

    private final AgentProperties props;
    private final TrustBundle trust;
    private final Clock clock;

    @Autowired
    public EndpointScanner(AgentProperties props, TrustBundle trust) {
        this(props, trust, Clock.systemUTC());
    }

    EndpointScanner(AgentProperties props, TrustBundle trust, Clock clock) {
        this.props = props;
        this.trust = trust;
        this.clock = clock;
    }

    /** Result of a strict check: ok only if the handshake works and nothing is CRITICAL. */
    public record Verification(boolean ok, String summary, CertRecord cert) {
    }

    public List<CertRecord> scanAll() {
        return props.targets().stream().map(this::scan).toList();
    }

    public CertRecord scan(Target t) {
        return observe(t.name(), t.env(), t.host(), t.port(), t.serverName());
    }

    public Verification verify(String host, int port, String sni) {
        String name = sni != null && !sni.isBlank() ? sni : host;
        String env = props.targets().stream()
                .filter(t -> t.host().equals(host) && t.port() == port && t.serverName().equals(name))
                .map(Target::env).findFirst().orElse("unknown");
        CertRecord c = observe(name, env, host, port, name);
        boolean ok = c.handshakeError() == null && c.risk().level() != Level.CRITICAL;
        String summary = ok
                ? "trusted chain, hostname matches, expires " + c.notAfter() + " (" + until(c.notAfter()) + ")"
                : String.join("; ", c.risk().reasons());
        return new Verification(ok, summary, c);
    }

    CertRecord observe(String name, String env, String host, int port, String sni) {
        Instant now = clock.instant();
        X509Certificate[] chain;
        try {
            chain = handshake(host, port, sni);
        } catch (Exception e) {
            String err = rootMessage(e);
            return new CertRecord(name, env, host, port, sni, now, null, null, List.of(), null, null, null,
                    null, 0, null, 0, false, false, err,
                    new Risk(Level.CRITICAL, List.of("handshake failed: " + err)));
        }

        X509Certificate leaf = chain[0];
        String trustError = trustError(chain);
        List<String> sans = dnsSans(leaf);
        var key = describeKey(leaf);

        CertRecord c = new CertRecord(name, env, host, port, sni, now,
                leaf.getSubjectX500Principal().getName(),
                leaf.getIssuerX500Principal().getName(),
                sans,
                leaf.getNotBefore().toInstant(),
                leaf.getNotAfter().toInstant(),
                fingerprint(leaf),
                key.type(), key.bits(),
                leaf.getSigAlgName(),
                chain.length,
                trustError == null,
                hostnameMatches(sni, sans),
                null, null);
        return withRisk(c, assess(c, trustError, props.risk(), now));
    }

    // ---- risk rules (pure; unit-tested directly) ----

    static Risk assess(CertRecord c, String trustError, AgentProperties.Risk rules, Instant now) {
        List<String> crit = new ArrayList<>();
        List<String> warn = new ArrayList<>();

        if (now.isAfter(c.notAfter())) {
            crit.add("expired " + ago(Duration.between(c.notAfter(), now)) + " ago (notAfter " + c.notAfter() + ")");
        } else if (now.isBefore(c.notBefore())) {
            crit.add("not yet valid (notBefore " + c.notBefore() + ")");
        } else {
            Duration left = Duration.between(now, c.notAfter());
            if (left.compareTo(rules.criticalWithin()) < 0) {
                crit.add("expires in " + ago(left) + " (critical window " + ago(rules.criticalWithin()) + ")");
            } else if (left.compareTo(rules.warnWithin()) < 0) {
                warn.add("expires in " + ago(left) + " (renew window " + ago(rules.warnWithin()) + ")");
            }
        }

        if (trustError != null) {
            crit.add("chain does not validate to a trusted root (issuer " + c.issuer() + "): " + trustError);
        }
        if (!c.hostnameMatches()) {
            crit.add("hostname " + c.sni() + " not in certificate SANs " + c.sans());
        }
        if ("RSA".equals(c.keyType()) && c.keyBits() < rules.minRsaBits()) {
            crit.add("weak key: RSA " + c.keyBits() + " bits (minimum " + rules.minRsaBits() + ")");
        }
        if ("EC".equals(c.keyType()) && c.keyBits() < rules.minEcBits()) {
            warn.add("weak key: EC " + c.keyBits() + " bits (minimum " + rules.minEcBits() + ")");
        }
        if (c.sigAlg() != null && rules.forbiddenSigAlgs().stream().anyMatch(a -> a.equalsIgnoreCase(c.sigAlg()))) {
            crit.add("forbidden signature algorithm " + c.sigAlg());
        }

        List<String> reasons = new ArrayList<>(crit);
        reasons.addAll(warn);
        Level level = !crit.isEmpty() ? Level.CRITICAL : !warn.isEmpty() ? Level.WARN : Level.OK;
        return new Risk(level, List.copyOf(reasons));
    }

    static boolean hostnameMatches(String host, List<String> sans) {
        String h = host.toLowerCase(Locale.ROOT);
        for (String san : sans) {
            String s = san.toLowerCase(Locale.ROOT);
            if (s.equals(h)) return true;
            // "*.example.com" matches exactly one extra label
            if (s.startsWith("*.") && h.endsWith(s.substring(1)) && h.indexOf('.') == h.length() - s.length() + 1) {
                return true;
            }
        }
        return false;
    }

    // ---- TLS plumbing ----

    /** Handshake that accepts any chain, so we can see and report what a broken endpoint serves. */
    private X509Certificate[] handshake(String host, int port, String sni) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{new CaptureAll()}, null);
        try (Socket raw = new Socket()) {
            raw.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            raw.setSoTimeout(TIMEOUT_MS);
            try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(raw, host, port, false)) {
                SSLParameters p = s.getSSLParameters();
                if (sni != null && !sni.isBlank() && !isIpLiteral(sni)) {
                    p.setServerNames(List.of(new SNIHostName(sni)));
                }
                s.setSSLParameters(p);
                s.startHandshake();
                Certificate[] certs = s.getSession().getPeerCertificates();
                return Arrays.stream(certs).map(X509Certificate.class::cast).toArray(X509Certificate[]::new);
            }
        }
    }

    /** Null when the served chain validates against our trust bundle, else the reason it doesn't. */
    private String trustError(X509Certificate[] chain) {
        try {
            // "UNKNOWN" is what JSSE passes for TLS 1.3; it checks the leaf is fit for a TLS server signature.
            trust.trustManager().checkServerTrusted(chain, "UNKNOWN");
            return null;
        } catch (CertificateException e) {
            return rootMessage(e);
        }
    }

    private record KeyInfo(String type, int bits) {
    }

    private static KeyInfo describeKey(X509Certificate cert) {
        var k = cert.getPublicKey();
        if (k instanceof RSAPublicKey rsa) return new KeyInfo("RSA", rsa.getModulus().bitLength());
        if (k instanceof ECPublicKey ec) return new KeyInfo("EC", ec.getParams().getOrder().bitLength());
        return new KeyInfo(k.getAlgorithm(), 0);
    }

    private static List<String> dnsSans(X509Certificate cert) {
        try {
            var sans = cert.getSubjectAlternativeNames();
            if (sans == null) return List.of();
            return sans.stream()
                    .filter(s -> (Integer) s.get(0) == 2 || (Integer) s.get(0) == 7) // dNSName, iPAddress
                    .map(s -> String.valueOf(s.get(1)))
                    .toList();
        } catch (CertificateParsingException e) {
            return List.of();
        }
    }

    public static String fingerprint(X509Certificate cert) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static CertRecord withRisk(CertRecord c, Risk r) {
        return new CertRecord(c.target(), c.env(), c.host(), c.port(), c.sni(), c.observedAt(), c.subject(),
                c.issuer(), c.sans(), c.notBefore(), c.notAfter(), c.fingerprintSha256(), c.keyType(), c.keyBits(),
                c.sigAlg(), c.chainLength(), c.trusted(), c.hostnameMatches(), c.handshakeError(), r);
    }

    private static boolean isIpLiteral(String s) {
        return s.chars().allMatch(ch -> Character.isDigit(ch) || ch == '.') || s.contains(":");
    }

    private static String rootMessage(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null && t.getCause() != t) t = t.getCause();
        String m = t.getMessage();
        return t.getClass().getSimpleName() + (m == null ? "" : ": " + m);
    }

    private String until(Instant notAfter) {
        return "in " + ago(Duration.between(clock.instant(), notAfter));
    }

    /** Compact human duration: 9m, 3h12m, 5d4h. */
    static String ago(Duration d) {
        long m = Math.max(0, d.toMinutes());
        if (m < 60) return m + "m";
        long h = m / 60;
        if (h < 48) return h + "h" + (m % 60 == 0 ? "" : (m % 60) + "m");
        return (h / 24) + "d" + (h % 24 == 0 ? "" : (h % 24) + "h");
    }

    private static final class CaptureAll extends X509ExtendedTrustManager {
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket s) { }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine e) { }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket s) { }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine e) { }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}
