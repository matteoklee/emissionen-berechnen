package de.kleemann.authservice.api;

import de.kleemann.authservice.api.dto.LoginRequest;
import de.kleemann.authservice.api.dto.UserRequest;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.ws.rs.core.Response;
import java.util.Collections;

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

    @Autowired
    private Keycloak keycloak;

    @Value("${keycloak.realm}")
    private String realm;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRequest userRequest) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(userRequest.getUsername());
        user.setEmail(userRequest.getEmail());
        user.setEnabled(true);

        CredentialRepresentation passwordCred = new CredentialRepresentation();
        passwordCred.setTemporary(false);
        passwordCred.setValue(userRequest.getPassword());

        Response response = keycloak.realm(realm).users()
                .create(user);

        if (response.getStatus() == 201) {
            return ResponseEntity.ok("User registered successfully.");
        }
        return ResponseEntity.status(response.getStatus()).body("Failed to register user.");
    }

    @GetMapping("/validate")
    public ResponseEntity<?> validateToken() {
        return ResponseEntity.ok("Token is valid.");
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
