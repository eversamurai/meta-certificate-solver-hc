package dev.certagent.agent;

import dev.certagent.config.AgentProperties;
import dev.certagent.model.Event;
import dev.certagent.store.EventLog;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;

/** Posts the run summary to a webhook (Slack-compatible {"text": …} body). Silent when no URL is set. */
@Component
public class Notifier {

    private final String webhookUrl;
    private final EventLog events;
    private final RestClient http;

    public Notifier(AgentProperties props, EventLog events, RestClient.Builder http) {
        this.webhookUrl = props.notification().webhookUrl();
        this.events = events;
        this.http = http.build();
    }

    public void send(String runId, String text, Map<String, Integer> counts) {
        if (webhookUrl == null || webhookUrl.isBlank()) return;
        try {
            http.post().uri(webhookUrl)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("text", text, "runId", runId, "counts", counts))
                    .retrieve()
                    .toBodilessEntity();
            events.append(runId, null, Event.Kind.NOTIFY, "summary posted to webhook");
        } catch (Exception e) {
            events.append(runId, null, Event.Kind.ERROR, "webhook failed: " + e.getMessage());
        }
    }
}
