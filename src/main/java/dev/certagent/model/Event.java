package dev.certagent.model;

import java.time.Instant;
import java.util.Map;

/**
 * One timeline entry. The UI groups events by {@code runId + target} into case cards and colours by kind.
 * Prefer new {@code details} entries over new kinds.
 */
public record Event(
        long seq,
        Instant ts,
        String runId,
        String target,
        Kind kind,
        String message,
        Map<String, Object> details) {

    public enum Kind { SCAN, DIAGNOSE, PLAN, POLICY, APPLY, VERIFY, ROLLBACK, NOTIFY, ERROR, DONE }
}
