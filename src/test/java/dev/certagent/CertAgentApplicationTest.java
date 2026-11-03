package dev.certagent;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/** Catches wiring mistakes the unit tests can't: every bean must construct from application.yml. */
@SpringBootTest(properties = {
        "certagent.schedule.run-on-startup=false",
        "certagent.event-log=target/test-events.jsonl",
        "certagent.model=glimmer"})   // no API key needed to check the wiring
class CertAgentApplicationTest {

    @Test
    void contextLoads() {
    }
}
