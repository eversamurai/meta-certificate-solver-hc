package dev.certagent.scan;

import org.shredzone.acme4j.util.KeyPairUtils;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

/**
 * Stands in for nginx in tests: serves whatever PEM cert/key are on disk as of the last {@link #reload()},
 * so install → reload → verify → restore can be exercised for real without docker.
 */
public final class FileTlsServer implements AutoCloseable {

    private final Path cert;
    private final Path key;
    private final ServerSocket socket;
    private final Thread thread;
    private volatile SSLContext ctx;

    public FileTlsServer(Path cert, Path key) throws Exception {
        this.cert = cert;
        this.key = key;
        reload();
        socket = new ServerSocket(0);
        thread = Thread.ofVirtual().start(() -> {
            while (!socket.isClosed()) {
                try (Socket raw = socket.accept();
                     SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(raw, (InputStream) null, true)) {
                    s.setUseClientMode(false);
                    s.startHandshake();
                } catch (IOException ignored) {
                    // client closed early or server shutting down
                }
            }
        });
    }

    /** Re-reads the files, like {@code nginx -s reload}. Throws if they don't parse, like a failed reload. */
    public void reload() throws Exception {
        Certificate[] chain;
        try (InputStream in = Files.newInputStream(cert)) {
            chain = CertificateFactory.getInstance("X.509").generateCertificates(in).toArray(Certificate[]::new);
        }
        KeyPair kp;
        try (Reader r = Files.newBufferedReader(key)) {
            kp = KeyPairUtils.readKeyPair(r);
        }
        char[] pw = "test".toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("leaf", kp.getPrivate(), pw, chain);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pw);
        SSLContext next = SSLContext.getInstance("TLS");
        next.init(kmf.getKeyManagers(), null, null);
        ctx = next;
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
