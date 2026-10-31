package dev.certagent.scan;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/** Throwaway CA, leaf certs and a local TLS server, so scanner tests need no docker lab. */
public final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    public record Issued(X509Certificate cert, KeyPair keys) {
    }

    public static Issued root(String cn) throws Exception {
        KeyPair kp = rsa(2048);
        X500Name name = new X500Name("CN=" + cn);
        Instant now = Instant.now();
        var b = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(SERIAL.incrementAndGet()),
                Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(365))),
                name, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return new Issued(sign(b, kp), kp);
    }

    public static Issued leaf(Issued ca, String dnsName, int rsaBits, Instant notBefore, Instant notAfter) throws Exception {
        KeyPair kp = rsa(rsaBits);
        var b = new JcaX509v3CertificateBuilder(ca.cert(), BigInteger.valueOf(SERIAL.incrementAndGet()),
                Date.from(notBefore), Date.from(notAfter), new X500Name("CN=" + dnsName), kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        b.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        return new Issued(sign(b, ca.keys()), kp);
    }

    public static Issued leaf(Issued ca, String dnsName, Duration validFor) throws Exception {
        Instant now = Instant.now();
        return leaf(ca, dnsName, 2048, now.minus(Duration.ofMinutes(5)), now.plus(validFor));
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder b, KeyPair signer) throws Exception {
        var signerOp = new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(b.build(signerOp));
    }

    private static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        return g.generateKeyPair();
    }

    /** Serves {@code leaf} on an ephemeral localhost port until closed; every connection just handshakes. */
    public static final class TlsServer implements AutoCloseable {
        private final SSLServerSocket socket;
        private final Thread thread;

        public TlsServer(Issued leaf) throws Exception {
            char[] pw = "test".toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("leaf", leaf.keys().getPrivate(), pw, new X509Certificate[]{leaf.cert()});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pw);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            socket = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0);
            thread = Thread.ofVirtual().start(() -> {
                while (!socket.isClosed()) {
                    try (SSLSocket s = (SSLSocket) socket.accept()) {
                        s.startHandshake();
                    } catch (IOException ignored) {
                        // client closed early or server shutting down
                    }
                }
            });
        }

        public int port() {
            return socket.getLocalPort();
        }

        @Override
        public void close() throws Exception {
            socket.close();
            thread.join(2_000);
        }
    }
}
