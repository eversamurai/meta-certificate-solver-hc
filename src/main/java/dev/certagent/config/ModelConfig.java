package dev.certagent.config;

import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.OpenAiApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.web.client.RestClient;

import java.time.Duration;

/**
 * Picks the model that decides and calls tools: Muse Spark on Meta Model API (default) or Muse Glimmer on this
 * machine through Ollama ({@code certagent.model: glimmer}). Everything else — tools, policy, backups,
 * verification, rollback — runs locally either way.
 */
@Configuration
public class ModelConfig {

    /** The active model, its name, and where it runs ("Meta Model API" or "local"). */
    public record AgentModel(ChatModel chatModel, String name, String hosting) {
        public String label() {
            return name + " · " + hosting;
        }
    }

    /**
     * Spark is built here rather than auto-configured, so Ollama's auto-configured model (used for glimmer) and
     * Spring AI's single-model ChatClient.Builder stay as they are.
     */
    @Bean
    AgentModel agentModel(@Value("${certagent.model:spark}") String which,
                          ChatModel ollama,
                          @Value("${spring.ai.ollama.chat.options.model:unknown}") String ollamaModel,
                          @Value("${certagent.spark.api-key:}") String apiKey,
                          @Value("${certagent.spark.base-url:https://api.meta.ai}") String baseUrl,
                          @Value("${certagent.spark.model:muse-spark-1.3}") String sparkModel,
                          @Value("${certagent.spark.reasoning-effort:low}") String effort,
                          @Value("${certagent.spark.timeout:120s}") Duration timeout) {
        return switch (which.trim().toLowerCase()) {
            case "glimmer" -> new AgentModel(ollama, ollamaModel, "local");
            case "spark" -> {
                if (apiKey == null || apiKey.isBlank()) {
                    throw new IllegalStateException("certagent.model=spark needs a Meta Model API key: set MODEL_API_KEY "
                            + "or certagent.spark.api-key in config/application.yml, or use certagent.model=glimmer");
                }
                yield new AgentModel(spark(apiKey, baseUrl, sparkModel, effort, timeout), sparkModel, "Meta Model API");
            }
            default -> throw new IllegalStateException("certagent.model must be spark or glimmer, not '" + which + "'");
        };
    }

    /** Muse Spark through Meta Model API's OpenAI-compatible Chat Completions endpoint. */
    public static ChatModel spark(String apiKey, String baseUrl, String model, String effort, Duration timeout) {
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
                // Low effort: a 3-sentence summary took 29s at the default and 8s at low, same quality. The visible
                // reasoning on the timeline is the `reasoning` tool argument, which effort does not remove.
                .defaultOptions(OpenAiChatOptions.builder().model(model).temperature(0.1).reasoningEffort(effort).build())
                // One retry at most: the runner retries a failed case itself, and a run must not hang on the API.
                .retryTemplate(RetryTemplate.builder().maxAttempts(2).fixedBackoff(1000).build())
                .build();
    }
}
