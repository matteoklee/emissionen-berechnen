package de.kleemann.authservice.api;

import de.kleemann.authservice.api.dto.UserRequest;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import org.springframework.http.*;
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
    private static final String KEYCLOAK_USERINFO_URL = "http://217.160.66.229:8080/realms/emissionen-berechnen-realm/protocol/openid-connect/userinfo";
    private static final String KEYCLOAK_USERCREATION_URL = "http://217.160.66.229:8080/admin/realms/emissionen-berechnen-realm/users";
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
    @RateLimiter(name = "loginLimiter", fallbackMethod = "registerFallback")
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

    /*
    private String getUserId(String username, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);

        RestTemplate restTemplate = new RestTemplate();
        String userSearchUrl = KEYCLOAK_USERCREATION_URL + "?username=" + username;

        ResponseEntity<Map[]> response = restTemplate.getForEntity(userSearchUrl, Map[].class, headers);
        if (response.getBody() != null && response.getBody().length > 0) {
            return (String) response.getBody()[0].get("id");
        } else {
            throw new RuntimeException("User ID not found for username: " + username);
        }
    }*/

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
