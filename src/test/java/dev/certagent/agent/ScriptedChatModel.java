package dev.certagent.agent;

import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.tool.ToolCallback;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Stand-in for Glimmer: for each prompt it runs a scripted list of tool calls through the real
 * ToolCallbacks that ChatClient registered, records what the tools returned, then answers with fixed text.
 */
class ScriptedChatModel implements ChatModel {

    record Call(String tool, String jsonArgs) {
    }

    record Script(List<Call> calls, String answer) {
    }

    /** Every tool call made and the string the tool returned to the "model". */
    final List<String> toolResults = new ArrayList<>();
    final List<String> userPrompts = new ArrayList<>();

    private final Function<String, Script> scriptFor;

    ScriptedChatModel(Function<String, Script> scriptFor) {
        this.scriptFor = scriptFor;
    }

    @Override
    public ChatResponse call(Prompt prompt) {
        String user = prompt.getUserMessage().getText();
        userPrompts.add(user);
        Script script = scriptFor.apply(user);

        if (prompt.getOptions() instanceof ToolCallingChatOptions opts && !opts.getToolCallbacks().isEmpty()) {
            Map<String, ToolCallback> byName = opts.getToolCallbacks().stream()
                    .collect(Collectors.toMap(cb -> cb.getToolDefinition().name(), cb -> cb));
            ToolContext ctx = new ToolContext(opts.getToolContext());
            for (Call c : script.calls()) {
                ToolCallback cb = byName.get(c.tool());
                if (cb == null) throw new IllegalStateException("model called unregistered tool " + c.tool());
                toolResults.add(c.tool() + " -> " + cb.call(c.jsonArgs(), ctx));
            }
        }
        return new ChatResponse(List.of(new Generation(new AssistantMessage(script.answer()))));
    }

    @Override
    public ChatOptions getDefaultOptions() {
        return ToolCallingChatOptions.builder().build();
    }
}
