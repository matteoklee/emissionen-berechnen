package de.kleemann.authservice.core;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/**
 * Class "AdminService" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 21.12.2024
 */
@Service
public class AdminService {

    private final RestTemplate restTemplate;
    @Value("${auth.token-url}")
    private String KEYCLOAK_TOKEN_URL;

    @Value("${auth.users-url}")
    private String KEYCLOAK_USERS_URL;

    @Value("${auth.roles-url}")
    private String KEYCLOAK_ROLES_URL;

    @Value("${auth.client-id}")
    private String CLIENT_ID;

    @Value("${auth.client-secret}")
    private String CLIENT_SECRET;

    public AdminService() {
        this.restTemplate = new RestTemplate();
    }

    public ResponseEntity<?> getAllUsers() {
        String adminToken = getAdminToken();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + adminToken);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    KEYCLOAK_USERS_URL,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class
            );
            return ResponseEntity.ok(response.getBody());
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to fetch users: " + ex.getMessage());
        }
    }

    public ResponseEntity<?> getAllRoles() {
        String adminToken = getAdminToken();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + adminToken);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    KEYCLOAK_ROLES_URL,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class
            );
            return ResponseEntity.ok(response.getBody());
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to fetch roles: " + ex.getMessage());
        }
    }

    public ResponseEntity<?> createRole(String roleName) {
        String adminToken = getAdminToken();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("Authorization", "Bearer " + adminToken);

        Map<String, String> rolePayload = Map.of("name", roleName);

        try {
            restTemplate.postForEntity(
                    KEYCLOAK_ROLES_URL,
                    new HttpEntity<>(rolePayload, headers),
                    Void.class
            );
            return ResponseEntity.ok("Role created successfully.");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to create role: " + ex.getMessage());
        }
    }

    public ResponseEntity<?> deleteRole(String roleName) {
        String adminToken = getAdminToken();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + adminToken);

        String roleUrl = KEYCLOAK_ROLES_URL + "/" + roleName;

        try {
            restTemplate.exchange(roleUrl, HttpMethod.DELETE, new HttpEntity<>(headers), Void.class);
            return ResponseEntity.ok("Role deleted successfully.");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to delete role: " + ex.getMessage());
        }
    }

    public ResponseEntity<?> addUserToRole(String roleName, String userId) {
        String adminToken = getAdminToken();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("Authorization", "Bearer " + adminToken);

        String roleMappingUrl = KEYCLOAK_ROLES_URL + "/" + roleName + "/users/" + userId;

        try {
            restTemplate.postForEntity(
                    roleMappingUrl,
                    new HttpEntity<>(headers),
                    Void.class
            );
            return ResponseEntity.ok("User added to role successfully.");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to add user to role: " + ex.getMessage());
        }
    }

    public ResponseEntity<?> removeUserFromRole(String roleName, String userId) {
        String adminToken = getAdminToken();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + adminToken);

        String roleMappingUrl = KEYCLOAK_ROLES_URL + "/" + roleName + "/users/" + userId;

        try {
            restTemplate.exchange(roleMappingUrl, HttpMethod.DELETE, new HttpEntity<>(headers), Void.class);
            return ResponseEntity.ok("User removed from role successfully.");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to remove user from role: " + ex.getMessage());
        }
    }

    private String getAdminToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");
        body.add("client_id", CLIENT_ID);
        body.add("client_secret", CLIENT_SECRET);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(
                    KEYCLOAK_TOKEN_URL,
                    new HttpEntity<>(body, headers),
                    Map.class
            );
            return (String) response.getBody().get("access_token");
        } catch (Exception ex) {
            throw new RuntimeException("Failed to retrieve admin token: " + ex.getMessage(), ex);
        }
    }

}
