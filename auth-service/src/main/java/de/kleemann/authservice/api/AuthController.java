package de.kleemann.authservice.api;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * Class "AuthController" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 18.12.2024
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final String KEYCLOAK_TOKEN_URL = "http://217.160.66.229:8080/realms/emissionen-berechnen-realm/protocol/openid-connect/token";
    private static final String CLIENT_ID = "emissionen-berechnen-backend";
    private static final String CLIENT_SECRET = "psU4cnvokxEu9TVmiIWHEclMjKBOAHWJ";


    @GetMapping("/validate")
    public ResponseEntity<?> validateToken() {
        return ResponseEntity.ok("AuthController is available.");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('admin')")
    public String adminAccess() {
        return "Welcome Admin!";
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", CLIENT_ID);
        body.add("client_secret", CLIENT_SECRET);
        body.add("username", username);
        body.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        RestTemplate restTemplate = new RestTemplate();

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(KEYCLOAK_TOKEN_URL, request, String.class);
            return ResponseEntity.ok(response.getBody());
        } catch (Exception ex) {
            //ex.printStackTrace();
            return ResponseEntity.badRequest().body("Invalid username or password: " + ex.getMessage());
        }
    }


    /*
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            Keycloak keycloakLogin = Keycloak.getInstance(
                    keycloak.getServerInfo().getInfo().get("keycloak-server-url"),
                    realm,
                    loginRequest.getUsername(),
                    loginRequest.getPassword(),
                    clientId,
                    clientSecret
            );
            AccessTokenResponse tokenResponse = keycloakLogin.tokenManager().getAccessToken();
            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid credentials.");
        }
    }

    // Logout - Token-Invalidierung
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestParam String refreshToken) {
        try {
            keycloak.realm(realm).users().logout(refreshToken);
            return ResponseEntity.ok("Logout successful.");
        } catch (Exception e) {
            return ResponseEntity.status(400).body("Logout failed.");
        }
    }

    // Refresh Token - Generierung eines neuen Access Tokens
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestParam String refreshToken) {
        try {
            Keycloak keycloakRefresh = KeycloakBuilder.builder()
                    .serverUrl(keycloak.getServerInfo().getInfo().get("keycloak-server-url"))
                    .realm(realm)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .grantType("refresh_token")
                    .refreshToken(refreshToken)
                    .build();

            AccessTokenResponse tokenResponse = keycloakRefresh.tokenManager().refreshToken();
            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            return ResponseEntity.status(400).body("Failed to refresh token.");
        }
    }

    // Passwort vergessen - Trigger für Passwort-Reset-E-Mail
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        try {
            // Benutzer suchen
            UserRepresentation user = keycloak.realm(realm).users().search(email).stream()
                    .findFirst()
                    .orElse(null);

            if (user == null) {
                return ResponseEntity.status(404).body("User not found.");
            }

            // Passwort-Reset-E-Mail senden
            keycloak.realm(realm).users().get(user.getId()).executeActionsEmail(Collections.singletonList("UPDATE_PASSWORD"));
            return ResponseEntity.ok("Password reset email sent successfully.");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Failed to send password reset email.");
        }
    }

     */

}
