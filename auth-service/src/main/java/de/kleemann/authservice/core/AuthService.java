package de.kleemann.authservice.core;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/**
 * Class "AuthService" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 19.12.2024
 */
@Service
public class AuthService {

    private final RestTemplate restTemplate;
    @Value("${auth.token-url}")
    private String KEYCLOAK_TOKEN_URL;

    @Value("${auth.user-info-url}")
    private String KEYCLOAK_USERINFO_URL;

    @Value("${auth.user-creation-url}")
    private String KEYCLOAK_USERCREATION_URL;

    @Value("${auth.client-id}")
    private String CLIENT_ID;

    @Value("${auth.client-secret}")
    private String CLIENT_SECRET;

    public AuthService() {
        this.restTemplate = new RestTemplate();
    }

    public ResponseEntity<?> validateToken(String token) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", token);
            //headers.add("Authorization", "Bearer " + token);

            ResponseEntity<String> response = restTemplate.exchange(
                    KEYCLOAK_USERINFO_URL,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class
            );
            System.err.println(response);
            System.err.println(response.getBody());

            return response.getStatusCode() == HttpStatus.OK
                    ? ResponseEntity.ok("Token is valid")
                    : ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token validation failed: " + ex.getMessage());
        }
    }

    public ResponseEntity<?> login(String username, String password) {
        try {
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "password");
            body.add("client_id", CLIENT_ID);
            body.add("client_secret", CLIENT_SECRET);
            body.add("username", username);
            body.add("password", password);
            body.add("scope", "openid");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            //headers.set("Connection", "close");

            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    KEYCLOAK_TOKEN_URL,
                    HttpMethod.POST,
                    requestEntity,
                    String.class
            );

            System.err.println(response.getBody());
            return ResponseEntity.ok(response.getBody());
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body("Invalid username or password: " + ex.getMessage());
        }
    }

    public ResponseEntity<?> refreshToken(String refreshToken) {
        try {
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "refresh_token");
            body.add("client_id", CLIENT_ID);
            body.add("client_secret", CLIENT_SECRET);
            body.add("refresh_token", refreshToken);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            ResponseEntity<Map> response = restTemplate.postForEntity(
                    KEYCLOAK_TOKEN_URL,
                    new HttpEntity<>(body, headers),
                    Map.class
            );

            return ResponseEntity.ok(response.getBody());
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to refresh token: " + ex.getMessage());
        }
    }
}

