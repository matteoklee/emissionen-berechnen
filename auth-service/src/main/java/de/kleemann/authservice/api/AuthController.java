package de.kleemann.authservice.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.kleemann.authservice.api.dto.UserRequest;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
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
@Tag(name = "AuthController", description = "Verwaltet die Authentifizierungs- und Token-Funktionen")
public class AuthController {

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
    //TODO: Logging, outsource logic to core, Caching

    @GetMapping("/greeting")
    public ResponseEntity<?> validateToken() {
        return ResponseEntity.ok("AuthController is available.");
    }

    @GetMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);

        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<String> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(KEYCLOAK_USERINFO_URL, HttpMethod.GET, request, String.class);
            if (response.getStatusCode() == HttpStatus.OK) {
                return ResponseEntity.ok("Token is valid");
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
            }
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token validation failed: " + ex.getMessage());
        }
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('admin')")
    public String adminAccess() {
        return "Welcome Admin!";
    }

    @PostMapping("/login")
    @RateLimiter(name = "loginLimiter", fallbackMethod = "registerFallback")
    @Operation(summary = "Benutzer-Login", description = "Authentifiziert einen Benutzer mit Benutzername und Passwort.")
    @ApiResponse(responseCode = "200", description = "Login erfolgreich")
    @ApiResponse(responseCode = "400", description = "Ungültige Anmeldeinformationen")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", CLIENT_ID);
        body.add("client_secret", CLIENT_SECRET);
        body.add("scope", "openid");
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

    @GetMapping("/userinfo")
    public ResponseEntity<?> getUserInfo(@RequestHeader("Authorization") String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);

        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<String> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(KEYCLOAK_USERINFO_URL, HttpMethod.GET, request, String.class);
            return ResponseEntity.ok(response.getBody());
        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.badRequest().body("Failed to retrieve user info: " + ex.getMessage());
        }
    }

    //TODO: @PreAuthorize("hasRole('admin')")
    @GetMapping("/userinfo/{username}")
    public ResponseEntity<?> getUserInfoByUsername(@PathVariable String username) {
        final String adminToken = getAdminToken();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + adminToken);

        String url = KEYCLOAK_USERCREATION_URL + "?username=" + username;

        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<String> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<Map[]> response = restTemplate.exchange(url, HttpMethod.GET, request, Map[].class);
            if (response.getBody() != null && response.getBody().length > 0) {
                return ResponseEntity.ok(response.getBody()[0]);
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
            }
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error retrieving user info: " + ex.getMessage());
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestParam String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("client_id", CLIENT_ID);
        body.add("client_secret", CLIENT_SECRET);
        body.add("refresh_token", refreshToken);

        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(KEYCLOAK_TOKEN_URL, request, Map.class);
            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to refresh token: " + e.getMessage());
        }
    }

    @PostMapping("/register")
    @RateLimiter(name = "registerLimiter", fallbackMethod = "registerFallback")
    public ResponseEntity<?> registerUser(@RequestBody UserRequest userRequest) {
        String username = userRequest.getUsername();
        String email = userRequest.getEmail();
        String password = userRequest.getPassword();
        String firstName = userRequest.getFirstName();
        String lastName = userRequest.getLastName();

        final String ADMIN_TOKEN = getAdminToken();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + ADMIN_TOKEN);
        headers.add("Content-Type", "application/json");

        Map<String, Object> user = new HashMap<>();
        user.put("username", username);
        user.put("email", email);
        user.put("enabled", true);
        user.put("firstName", firstName);
        user.put("lastName", lastName);
        user.put("attributes", Map.of("customAttr", "value"));

        try {
            RestTemplate restTemplate = new RestTemplate();

            HttpEntity<Map<String, Object>> createUserRequest = new HttpEntity<>(user, headers);
            restTemplate.postForEntity(KEYCLOAK_USERCREATION_URL, createUserRequest, String.class);

            String userId = getUserId(username, ADMIN_TOKEN);
            setUserPassword(userId, password, ADMIN_TOKEN);

            return ResponseEntity.ok("User " + username + " registered successfully.");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Failed to register user: " + e.getMessage());
        }
    }

    @DeleteMapping("/user/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable String userId) {
        String adminToken = getAdminToken();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + adminToken);

        RestTemplate restTemplate = new RestTemplate();
        String deleteUserUrl = KEYCLOAK_USERCREATION_URL + "/" + userId;

        try {
            restTemplate.exchange(deleteUserUrl, HttpMethod.DELETE, new HttpEntity<>(headers), Void.class);
            return ResponseEntity.ok("User deleted successfully.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to delete user: " + e.getMessage());
        }
    }


    public ResponseEntity<?> registerFallback(UserRequest userRequest, Throwable t) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body("Rate limit exceeded. Please try again later.");
    }

    private String getAdminToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");
        body.add("client_id", "emissionen-berechnen-backend");
        body.add("client_secret", "psU4cnvokxEu9TVmiIWHEclMjKBOAHWJ");

        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(KEYCLOAK_TOKEN_URL, request, Map.class);
            System.err.println(response);
            System.err.println(response.getBody());
            System.err.println(response.getBody().get("access_token"));
            return (String) response.getBody().get("access_token");
        } catch (Exception e) {
            throw new RuntimeException("Failed to retrieve admin token: " + e.getMessage(), e);
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestHeader("Authorization") String token,
            @RequestParam String oldPassword,
            @RequestParam String newPassword) {
        String userId = null;
        try {
            userId = getUserIdFromToken(token);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        if (!validateOldPassword(userId, oldPassword, token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Old password is incorrect.");
        }

        try {
            setUserPassword(userId, newPassword, token);
            return ResponseEntity.ok("Password changed successfully.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to change password: " + e.getMessage());
        }
    }

    private boolean validateOldPassword(String userId, String oldPassword, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", CLIENT_ID);
        body.add("username", userId);
        body.add("password", oldPassword);

        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            restTemplate.postForEntity(KEYCLOAK_TOKEN_URL, request, String.class);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


    private String getUserIdFromToken(String token) throws JsonProcessingException {
        String[] parts = token.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("Invalid token format");

        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
        Map<String, Object> claims = new ObjectMapper().readValue(payload, Map.class);

        return claims.get("sub").toString();
    }



    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred: " + ex.getMessage());
    }

    private String getUserId(String username, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);

        RestTemplate restTemplate = new RestTemplate();
        String userSearchUrl = KEYCLOAK_USERCREATION_URL + "?username=" + username;
        System.err.println(userSearchUrl);

        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

        try {
            ResponseEntity<Map[]> response = restTemplate.exchange(
                    userSearchUrl,
                    HttpMethod.GET,
                    requestEntity,
                    Map[].class
            );

            if (response.getBody() != null && response.getBody().length > 0) {
                return (String) response.getBody()[0].get("id");
            } else {
                throw new RuntimeException("User ID not found for username: " + username);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to retrieve user ID: " + e.getMessage(), e);
        }
    }


    private void setUserPassword(String userId, String password, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);
        headers.add("Content-Type", "application/json");

        Map<String, Object> passwordPayload = new HashMap<>();
        passwordPayload.put("type", "password");
        passwordPayload.put("value", password);
        passwordPayload.put("temporary", false);

        RestTemplate restTemplate = new RestTemplate();
        String passwordUrl = KEYCLOAK_USERCREATION_URL + "/" + userId + "/reset-password";
        System.err.println(passwordUrl);

        HttpEntity<Map<String, Object>> passwordRequest = new HttpEntity<>(passwordPayload, headers);
        restTemplate.put(passwordUrl, passwordRequest);
    }

}
