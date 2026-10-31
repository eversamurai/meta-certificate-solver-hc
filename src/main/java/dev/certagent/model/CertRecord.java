package dev.certagent.model;

import java.time.Instant;
import java.util.List;

/**
 * One observed certificate as served by one target, plus the risk computed for it in code.
 * When the handshake itself failed, the cert fields may be null and {@code handshakeError} says why.
 */
public record CertRecord(
        String target,
        String env,
        String host,
        int port,
        String sni,
        Instant observedAt,
        String subject,
        String issuer,
        List<String> sans,
        Instant notBefore,
        Instant notAfter,
        String fingerprintSha256,
        String keyType,
        int keyBits,
        String sigAlg,
        int chainLength,
        boolean trusted,
        boolean hostnameMatches,
        String handshakeError,
        Risk risk) {

    public enum Level { OK, WARN, CRITICAL }

    public record Risk(Level level, List<String> reasons) {
        public static Risk ok() {
            return new Risk(Level.OK, List.of());
        }
    }
}
