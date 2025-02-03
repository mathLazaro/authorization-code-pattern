package br.github.mahtlazaro.client_server.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@RestController
public class ClientController {

    private final WebClient webClient;

    public ClientController(WebClient.Builder webClient) {

        this.webClient = webClient
                .baseUrl("https://127.0.0.1:8090")
                .build();
    }

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public Mono<String> home(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient client,
                             @AuthenticationPrincipal OidcUser user) {

        return Mono.just("""
                <p> Access Token: %s </p>
                <p> Id Token: %s </p>
                <p> Claims: %s</p>
                """.formatted(
                client.getAccessToken().getTokenValue(),
                user.getIdToken(),
                user.getClaims()));
    }

    @GetMapping("test")
    public Mono<String> getTest(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient client) {
            return webClient
                    .get()
                    .uri("test")
                    .header("Authorization", "Bearer %s".formatted(client.getAccessToken().getTokenValue()))
                    .retrieve()
                    .bodyToMono(String.class);
    }
}
