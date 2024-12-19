package de.kleemann.calculationservice.client;

import org.springframework.web.reactive.function.client.WebClient;

/**
 * Class "UserServiceClient" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 19.12.2024
 */
public class UserServiceClient {

    private final WebClient webClient;

    public UserServiceClient(WebClient webClient) {
        this.webClient = webClient;
    }

    public String getUserIdFromToken(String token) {
        try {
            return webClient.get()
                    .uri("/users/current") // Endpoint im user-service für den aktuellen Benutzer
                    .header("Authorization", "Bearer " + token)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch userId from user-service: " + e.getMessage(), e);
        }
    }

}
