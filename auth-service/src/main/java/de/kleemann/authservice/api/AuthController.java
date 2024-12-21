package de.kleemann.authservice.api;

import de.kleemann.authservice.core.AuthService;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * Class "AuthController" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 18.12.2024
 */
@RestController
@RequestMapping("/api/${api.version}/auth")
@Tag(name = "AuthController", description = "Verwaltet die Authentifizierungs- und Token-Funktionen")
public class AuthController {

    //TODO: Logging, outsource logic to core, Caching
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/greeting")
    public ResponseEntity<?> greeting() {
        return ResponseEntity.ok("AuthController is available.");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('admin')")
    public String adminAccess() {
        return "Welcome Admin!";
    }


    @GetMapping("/validate")
    @Operation(summary = "Token-Validierung", description = "Prüft, ob das übergebene Token gültig ist.")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String token) {
        return authService.validateToken(token);
    }

    @PostMapping("/login")
    @ApiResponse(responseCode = "200", description = "Login erfolgreich")
    @ApiResponse(responseCode = "400", description = "Ungültige Anmeldeinformationen")
    @RateLimiter(name = "loginLimiter", fallbackMethod = "loginFallback")
    @Operation(summary = "Benutzer-Login", description = "Authentifiziert einen Benutzer mit Benutzername und Passwort.")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        return authService.login(username, password);
    }

    @PostMapping("/refresh-token")
    @Operation(summary = "Token aktualisieren", description = "Aktualisiert ein JWT-Token mit einem Refresh-Token.")
    public ResponseEntity<?> refreshToken(@RequestParam String refreshToken) {
        return authService.refreshToken(refreshToken);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred: " + ex.getMessage());
    }

    public ResponseEntity<?> loginFallback(Throwable t) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body("Rate limit exceeded. Please try again later.");
    }

}
