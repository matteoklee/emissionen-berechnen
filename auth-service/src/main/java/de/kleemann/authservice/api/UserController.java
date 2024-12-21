package de.kleemann.authservice.api;

import de.kleemann.authservice.api.dto.UserRequest;
import de.kleemann.authservice.core.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

/**
 * Class "UserController" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 21.12.2024
 */
@RestController
@RequestMapping("/users")
@Tag(name = "UserController", description = "Verwaltet Benutzer und ihre Eigenschaften")
public class UserController {


    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/debug")
    public ResponseEntity<?> debugAuthorities() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(authentication.getAuthorities());
    }

    @GetMapping("/debug2")
    @PreAuthorize("hasAuthority('admin')")
    public ResponseEntity<?> debugAuthorities2() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(authentication.getAuthorities());
    }

    @GetMapping("/debug3")
    @PreAuthorize("hasRole('ROLE_admin')")
    public ResponseEntity<?> debugAuthorities3() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(authentication.getAuthorities());
    }

    @GetMapping("/debug4")
    @PreAuthorize("hasAuthority('ROLE_admin')")
    public ResponseEntity<?> debugAuthorities4() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(authentication.getAuthorities());
    }

    @GetMapping("/debug5")
    @PreAuthorize("hasRole('admin')")
    public ResponseEntity<?> debugAuthorities5() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(authentication.getAuthorities());
    }

    @GetMapping("/userinfo")
    public ResponseEntity<?> getUserInfoByToken(@RequestHeader("Authorization") String token) {
        return userService.getUserInfoByToken(token);
    }

    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('admin') or #userId == authentication.principal.userId")
    @Operation(summary = "Benutzerinformationen abrufen", description = "Ruft die Informationen eines Benutzers basierend auf der Benutzer-ID ab.")
    public ResponseEntity<?> getUserInfo(@PathVariable String userId) {
        return userService.getUserInfo(userId);
    }

    @GetMapping("/username/{username}")
    @PreAuthorize("hasRole('admin')")
    @Operation(summary = "Benutzerinformationen abrufen", description = "Ruft die Informationen eines Benutzers basierend auf dem Benutzernamen ab.")
    public ResponseEntity<?> getUserInfoByUsername(@PathVariable String username) {
        return userService.getUserInfoByUsername(username);
    }

    @PostMapping("/register")
    @PreAuthorize("hasRole('admin')")
    @Operation(summary = "Benutzer registrieren", description = "Erstellt einen neuen Benutzer im System.")
    public ResponseEntity<?> registerUser(@RequestBody UserRequest userRequest) {
        return userService.registerUser(userRequest);
    }

    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('admin')")
    @Operation(summary = "Benutzer löschen", description = "Löscht einen Benutzer basierend auf der Benutzer-ID.")
    public ResponseEntity<?> deleteUser(@PathVariable String userId) {
        return userService.deleteUser(userId);
    }

    @PostMapping("/change-password")
    @Operation(summary = "Passwort ändern", description = "Ändert das Passwort eines Benutzers.")
    public ResponseEntity<?> changePassword(
            @RequestHeader("Authorization") String token,
            @RequestParam String oldPassword,
            @RequestParam String newPassword) {
        return userService.changePassword(token, oldPassword, newPassword);
    }
}
