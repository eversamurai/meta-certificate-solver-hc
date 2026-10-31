package dev.certagent.exec;

import dev.certagent.config.AgentProperties;
import dev.certagent.config.AgentProperties.Target;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Puts a cert/key pair where a target's nginx reads it and reloads nginx. Never changes anything without a
 * backup first; {@link #restore} puts the backup back byte for byte.
 */
@Component
public class NginxInstaller {

    private static final DateTimeFormatter ID = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS");

    private final AgentProperties.Install install;

    public NginxInstaller(AgentProperties props) {
        this.install = props.install();
    }

    public record Backup(String id, Path cert, Path key) {
    }

    public Backup backup(Target t) throws IOException {
        requirePaths(t);
        String id = LocalDateTime.now().format(ID);
        Path dir = install.backupDir().resolve(t.name()).resolve(id);
        Files.createDirectories(dir);
        Path cert = dir.resolve("cert.pem");
        Path key = dir.resolve("key.pem");
        Files.copy(t.certPath(), cert, StandardCopyOption.REPLACE_EXISTING);
        Files.copy(t.keyPath(), key, StandardCopyOption.REPLACE_EXISTING);
        return new Backup(id, cert, key);
    }

    public Optional<Backup> latestBackup(Target t) throws IOException {
        Path dir = install.backupDir().resolve(t.name());
        if (!Files.isDirectory(dir)) return Optional.empty();
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(Files::isDirectory)
                    .max(Comparator.comparing(p -> p.getFileName().toString()))
                    .map(p -> new Backup(p.getFileName().toString(), p.resolve("cert.pem"), p.resolve("key.pem")));
        }
    }

    /** Key first, then cert, each via temp file + move so nginx never reads a half-written file. */
    public void install(Target t, String certPem, String keyPem) throws IOException {
        requirePaths(t);
        writeAtomically(t.keyPath(), keyPem);
        writeAtomically(t.certPath(), certPem);
    }

    public void restore(Target t, Backup b) throws IOException {
        requirePaths(t);
        writeAtomically(t.keyPath(), Files.readString(b.key(), StandardCharsets.UTF_8));
        writeAtomically(t.certPath(), Files.readString(b.cert(), StandardCharsets.UTF_8));
    }

    /** Runs the configured reload command; throws with its output if it fails or hangs. */
    public void reload() throws IOException, InterruptedException {
        Process p = new ProcessBuilder(install.reloadCommand()).redirectErrorStream(true).start();
        if (!p.waitFor(30, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IOException("reload timed out: " + String.join(" ", install.reloadCommand()));
        }
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
        if (p.exitValue() != 0) {
            throw new IOException("reload exited " + p.exitValue() + (out.isEmpty() ? "" : ": " + out));
        }
        Thread.sleep(install.settleAfterReload());
    }

    private static void writeAtomically(Path target, String content) throws IOException {
        Path tmp = target.resolveSibling(target.getFileName() + ".certagent.tmp");
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void requirePaths(Target t) {
        if (t.certPath() == null || t.keyPath() == null) {
            throw new IllegalStateException("target " + t.name() + " has no cert-path/key-path configured");
        }
    }
}
