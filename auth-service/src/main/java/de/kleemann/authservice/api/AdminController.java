package de.kleemann.authservice.api;

import de.kleemann.authservice.core.AdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * Class "AdminController" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 21.12.2024
 */
@RestController
@RequestMapping("/api/${api.version}/admin")
@Tag(name = "AdminController", description = "Verwaltet administrative Funktionen wie Rollen und Benutzer.")
public class AdminController {

    private final AdminService adminService;

    public AdminController(AdminService adminService) {
        this.adminService = adminService;
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('admin')")
    @Operation(summary = "Alle Benutzer abrufen", description = "Liefert eine Liste aller Benutzer.")
    public ResponseEntity<?> getAllUsers() {
        return adminService.getAllUsers();
    }

    @GetMapping("/roles")
    @PreAuthorize("hasRole('admin')")
    @Operation(summary = "Alle Rollen abrufen", description = "Liefert eine Liste aller Rollen.")
    public ResponseEntity<?> getAllRoles() {
        return adminService.getAllRoles();
    }

    @PostMapping("/roles")
    @PreAuthorize("hasRole('admin')")
    @Operation(summary = "Rolle erstellen", description = "Erstellt eine neue Rolle.")
    public ResponseEntity<?> createRole(@RequestParam String roleName) {
        return adminService.createRole(roleName);
    }

    @DeleteMapping("/roles/{roleName}")
    @PreAuthorize("hasRole('admin')")
    @Operation(summary = "Rolle löschen", description = "Löscht eine Rolle.")
    public ResponseEntity<?> deleteRole(@PathVariable String roleName) {
        return adminService.deleteRole(roleName);
    }

    @PostMapping("/roles/{roleName}/users/{userId}")
    @PreAuthorize("hasRole('admin')")
    @Operation(summary = "Benutzer zu einer Rolle hinzufügen", description = "Fügt einen Benutzer zu einer Rolle hinzu.")
    public ResponseEntity<?> addUserToRole(@PathVariable String roleName, @PathVariable String userId) {
        return adminService.addUserToRole(roleName, userId);
    }

    @DeleteMapping("/roles/{roleName}/users/{userId}")
    @PreAuthorize("hasRole('admin')")
    @Operation(summary = "Benutzer aus einer Rolle entfernen", description = "Entfernt einen Benutzer aus einer Rolle.")
    public ResponseEntity<?> removeUserFromRole(@PathVariable String roleName, @PathVariable String userId) {
        return adminService.removeUserFromRole(roleName, userId);
    }
}

