package dev.certagent.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.certagent.config.AgentProperties;
import dev.certagent.model.Event;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Append-only timeline: kept in memory for the API, mirrored to JSONL so it survives restarts. */
@Component
public class EventLog {

    private static final Logger log = LoggerFactory.getLogger(EventLog.class);

    private final Path file;
    private final ObjectMapper json;
    private final List<Event> events = new ArrayList<>();
    private long seq;

    public EventLog(AgentProperties props, ObjectMapper json) {
        this.file = props.eventLog();
        this.json = json;
        load();
    }

    public synchronized Event append(String runId, String target, Event.Kind kind, String message,
                                     Map<String, Object> details) {
        Event e = new Event(++seq, Instant.now(), runId, target, kind, message, copy(details));
        events.add(e);
        write(e);
        log.info("[{}] {} {} {}", runId, kind, target == null ? "-" : target, message);
        return e;
    }

    public Event append(String runId, String target, Event.Kind kind, String message) {
        return append(runId, target, kind, message, Map.of());
    }

    public synchronized List<Event> since(long afterSeq) {
        return events.stream().filter(e -> e.seq() > afterSeq).toList();
    }

    public synchronized List<Event> forCase(String runId, String target) {
        return events.stream()
                .filter(e -> e.runId().equals(runId) && Objects.equals(e.target(), target))
                .toList();
    }

    /** Builds a details map that tolerates null values, which {@link Map#of} does not. */
    public static Map<String, Object> details(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            if (kv[i + 1] != null) m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    private static Map<String, Object> copy(Map<String, Object> m) {
        return m == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(m));
    }

    private void write(Event e) {
        try {
            Files.writeString(file, json.writeValueAsString(e) + "\n", StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ex) {
            throw new UncheckedIOException("Cannot append to " + file, ex);
        }
    }

    private void load() {
        try {
            if (file.getParent() != null) Files.createDirectories(file.getParent());
            if (!Files.exists(file)) return;
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (line.isBlank()) continue;
                Event e = json.readValue(line, Event.class);
                events.add(e);
                seq = Math.max(seq, e.seq());
            }
            log.info("Loaded {} events from {}", events.size(), file);
        } catch (IOException ex) {
            throw new UncheckedIOException("Cannot read " + file, ex);
        }
    }
}
