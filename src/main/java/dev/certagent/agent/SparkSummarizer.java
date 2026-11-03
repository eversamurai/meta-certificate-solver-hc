package dev.certagent.agent;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.OpenAiApi;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;

/**
 * Muse Spark on Meta Model API writes the run summary. Glimmer still makes every decision and tool call locally;
 * Spark only sees the outcome facts for the summary. Off unless {@code MODEL_API_KEY} is set, and the runner
 * falls back to Glimmer if a call fails, so a run never depends on the API.
 */
@Component
public class SparkSummarizer {

    private final ChatClient chat;   // null when no API key is configured
    private final String model;

    @Autowired
    public SparkSummarizer(@Value("${certagent.summary.api-key:}") String apiKey,
                           @Value("${certagent.summary.base-url:https://api.meta.ai}") String baseUrl,
                           @Value("${certagent.summary.model:muse-spark-1.3}") String model,
                           @Value("${certagent.summary.timeout:60s}") Duration timeout) {
        this.model = model;
        this.chat = apiKey == null || apiKey.isBlank() ? null : ChatClient.create(sparkModel(apiKey, baseUrl, model, timeout));
    }

    /** For tests: any ChatModel stands in for the API. */
    SparkSummarizer(ChatModel chatModel, String model) {
        this.model = model;
        this.chat = ChatClient.create(chatModel);
    }

    public boolean enabled() {
        return chat != null;
    }

    /** How the summary's author is shown on the timeline and in /api/status. */
    public String label() {
        return model + " · Meta Model API";
    }

    public String summarize(String prompt) {
        return chat.prompt().user(prompt).call().content();
    }

    private static ChatModel sparkModel(String apiKey, String baseUrl, String model, Duration timeout) {
        var http = new SimpleClientHttpRequestFactory();
        http.setConnectTimeout(Duration.ofSeconds(10));
        http.setReadTimeout(timeout);
        var api = OpenAiApi.builder()
                .baseUrl(baseUrl)                       // https://api.meta.ai + /v1/chat/completions
                .apiKey(apiKey)
                .restClientBuilder(RestClient.builder().requestFactory(http))
                .build();
        return OpenAiChatModel.builder()
                .openAiApi(api)
                .defaultOptions(OpenAiChatOptions.builder().model(model).temperature(0.2).build())
                // One retry at most: the runner has its own fallback, and a run must not hang on the API.
                .retryTemplate(RetryTemplate.builder().maxAttempts(2).fixedBackoff(1000).build())
                .build();
    }
}
