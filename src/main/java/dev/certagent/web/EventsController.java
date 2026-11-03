package dev.certagent.web;

import dev.certagent.agent.CertAgentRunner;
import dev.certagent.model.CertRecord;
import dev.certagent.model.Event;
import dev.certagent.store.EventLog;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class EventsController {

    private final EventLog events;
    private final CertAgentRunner runner;

    public EventsController(EventLog events, CertAgentRunner runner) {
        this.events = events;
        this.runner = runner;
    }

    /** Timeline entries after {@code since}; the UI polls with the last seq it has. */
    @GetMapping("/events")
    public List<Event> events(@RequestParam(defaultValue = "0") long since) {
        return events.since(since);
    }

    @GetMapping("/inventory")
    public List<CertRecord> inventory() {
        return runner.inventory();
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        Map<String, Object> m = new HashMap<>();
        m.put("running", runner.isRunning());
        m.put("lastRunId", runner.lastRunId());
        m.put("model", runner.model());
        m.put("hosting", runner.hosting());   // "Meta Model API" (Muse Spark) or "local" (Glimmer via Ollama)
        return m;
    }

    @PostMapping("/run")
    public ResponseEntity<Map<String, String>> run() {
        return runner.trigger()
                .map(id -> ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("runId", id)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "a run is already in progress")));
    }
}
