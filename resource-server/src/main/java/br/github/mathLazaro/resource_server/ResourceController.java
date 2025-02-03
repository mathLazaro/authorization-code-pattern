package br.github.mathLazaro.resource_server;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class ResourceController {

    @GetMapping("test")
    String getTest(@AuthenticationPrincipal Jwt user) {
        return """
                <p>Test page</p>
                <p>%s</p>
                """.formatted(user.getClaims());
    }
}
