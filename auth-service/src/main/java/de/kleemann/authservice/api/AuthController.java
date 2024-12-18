package de.kleemann.authservice.api;

import de.kleemann.authservice.api.dto.UserRequest;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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

}
