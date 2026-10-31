package dev.certagent.policy;

import dev.certagent.config.AgentProperties;
import dev.certagent.config.AgentProperties.Decision;
import dev.certagent.config.AgentProperties.Target;
import dev.certagent.model.Event;
import dev.certagent.store.EventLog;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sits between every tool call and every executor. The model proposes; this decides, from config alone.
 * Each decision is recorded as a POLICY event carrying the model's reasoning and a badge for the UI.
 */
@Component
public class PolicyGate {

    private final AgentProperties.Policy policy;
    private final EventLog events;
    private final Map<String, Integer> actionsByRun = new ConcurrentHashMap<>();

    public PolicyGate(AgentProperties props, EventLog events) {
        this.policy = props.policy();
        this.events = events;
    }

    public Decision decide(String runId, String tool, Target target, String reasoning) {
        int used = actionsByRun.merge(runId, 1, Integer::sum);
        Decision d = policy == null ? Decision.DENY : policy.decide(target.env(), tool);
        String why;
        if (policy != null && used > policy.maxActionsPerRun()) {
            d = Decision.DENY;
            why = "action budget exhausted (" + policy.maxActionsPerRun() + " per run)";
        } else {
            why = "policy " + target.env() + "." + tool + " = " + d;
        }

        events.append(runId, target.name(), Event.Kind.POLICY, tool + ": " + d + " — " + why,
                EventLog.details(
                        "tool", tool,
                        "decision", d.name(),
                        "env", target.env(),
                        "badge", badge(d, target.env()),
                        "reason", why,
                        "reasoning", reasoning));
        return d;
    }

    public void endRun(String runId) {
        actionsByRun.remove(runId);
    }

    static String badge(Decision d, String env) {
        return switch (d) {
            case ALLOW -> "AUTO · " + env;
            case DRY_RUN -> "DRY-RUN · " + env;
            case DENY -> "APPROVAL NEEDED · " + env;
        };
    }
}
