package de.kleemann.authservice.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.kleemann.authservice.api.dto.UserRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Class "UserService" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 21.12.2024
 */
@Service
public class UserService {

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

    public UserService() {
        this.restTemplate = new RestTemplate();
    }

    public ResponseEntity<?> getUserInfoByToken(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(KEYCLOAK_USERINFO_URL, HttpMethod.GET, request, String.class);
            return ResponseEntity.ok(response.getBody());
        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.badRequest().body("Failed to retrieve user info: " + ex.getMessage());
        }
    }

    /*
    public ResponseEntity<?> getUserInfo(String userId) {
        String url = KEYCLOAK_USERINFO_URL + "/" + userId;
        try {
            return restTemplate.getForEntity(url, String.class);
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found: " + ex.getMessage());
        }
    }*/

    public ResponseEntity<?> getUserInfo(String userId) { //604dd6b8-1ab3-40e6-a882-98c15ac1553c
        String url = KEYCLOAK_USERCREATION_URL + "/" + userId;
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + getAdminToken());
        //headers.add("Authorization", getAdminToken());

        HttpEntity<String> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, request, String.class);
            return ResponseEntity.ok(response.getBody());
        } catch (HttpClientErrorException.Unauthorized e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized: " + e.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to retrieve user info: " + ex.getMessage());
        }
    }

    public ResponseEntity<?> getUserInfoByUsername(String username) {
        String url = KEYCLOAK_USERCREATION_URL + "?username=" + username;
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + getAdminToken());

        HttpEntity<Void> request = new HttpEntity<>(headers);
        try {
            ResponseEntity<Map[]> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    request,
                    Map[].class
            );

            if (response.getBody() != null && response.getBody().length > 0) {
                return ResponseEntity.ok(response.getBody()[0]);
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found for username: " + username);
            }
        } catch (HttpClientErrorException.Unauthorized e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized: " + e.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to retrieve user info: " + ex.getMessage());
        }
    }

    public ResponseEntity<?> registerUser(UserRequest userRequest) {
        try {
            String adminToken = getAdminToken();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.add("Authorization", "Bearer " + adminToken);

            Map<String, Object> userPayload = new HashMap<>();
            userPayload.put("username", userRequest.getUsername());
            userPayload.put("email", userRequest.getEmail());
            userPayload.put("enabled", true);
            userPayload.put("firstName", userRequest.getFirstName());
            userPayload.put("lastName", userRequest.getLastName());
            userPayload.put("attributes", Map.of("customAttr", "value"));

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(userPayload, headers);
            restTemplate.postForEntity(KEYCLOAK_USERCREATION_URL, request, String.class);

            String userId = getUserId(userRequest.getUsername(), adminToken);
            System.err.println("UserId: " + userId);

            //Token, Id, Password
            //setUserPassword(userId, userRequest.getPassword(), adminToken);
            setUserPassword(adminToken, userId, userRequest.getPassword());

            return ResponseEntity.ok("User " + userRequest.getUsername() + " registered successfully.");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to register user: " + ex.getMessage());
        }
    }

    public ResponseEntity<?> deleteUser(String userId) {
        try {
            String adminToken = getAdminToken();

            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Bearer " + adminToken);

            String deleteUserUrl = KEYCLOAK_USERCREATION_URL + "/" + userId;
            restTemplate.exchange(deleteUserUrl, HttpMethod.DELETE, new HttpEntity<>(headers), Void.class);

            return ResponseEntity.ok("User deleted successfully.");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to delete user: " + ex.getMessage());
        }
    }

    private String getAdminToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");
        body.add("client_id", CLIENT_ID);
        body.add("client_secret", CLIENT_SECRET);
        //body.add("scope", "openid");

        try {
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(KEYCLOAK_TOKEN_URL, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                System.err.println("Admin Token: " + (String) response.getBody().get("access_token"));
                return (String) response.getBody().get("access_token");
            } else {
                throw new RuntimeException("Failed to retrieve admin token: " + response.getBody());
            }
        } catch (Exception ex) {
            throw new RuntimeException("Failed to retrieve admin token: " + ex.getMessage(), ex);
        }
    }

    /*
    public ResponseEntity<?> changePassword(String token, String oldPassword, String newPassword) {
        try {
            String userId = extractUserIdFromToken(token);

            if (!validateOldPassword(userId, oldPassword, token)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Old password is incorrect.");
            }

            setUserPassword(userId, newPassword, token);
            return ResponseEntity.ok("Password changed successfully.");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to change password: " + ex.getMessage());
        }
    }
    */

    public ResponseEntity<?> changePassword(String token, String oldPassword, String newPassword) {
        try {
            String username = extractUsernameFromToken(token);
            System.err.println("Old: " + oldPassword);
            System.err.println("New: " + newPassword);
            System.err.println("User: " + username);

            if (!validateOldPassword(username, oldPassword)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Old password is incorrect.");
            }

            String userId = extractUserIdFromToken(token);
            System.err.println("UserId: " + userId);
            //setUserPassword(userId, newPassword, token);
            setUserPassword(token, userId, newPassword);

            return ResponseEntity.ok("Password changed successfully.");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to change password: " + ex.getMessage());
        }
    }


    private String getUserId(String username, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);

        String userSearchUrl = KEYCLOAK_USERCREATION_URL + "?username=" + username;

        try {
            ResponseEntity<Map[]> response = restTemplate.exchange(
                    userSearchUrl,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    Map[].class
            );

            if (response.getBody() != null && response.getBody().length > 0) {
                return (String) response.getBody()[0].get("id");
            } else {
                throw new RuntimeException("User ID not found for username: " + username);
            }
        } catch (Exception ex) {
            throw new RuntimeException("Failed to retrieve user ID: " + ex.getMessage(), ex);
        }
    }

    /*
    private void setUserPassword(String userId, String password, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);
        headers.add("Content-Type", "application/json");

        Map<String, Object> passwordPayload = new HashMap<>();
        passwordPayload.put("type", "password");
        passwordPayload.put("value", password);
        passwordPayload.put("temporary", false);

        String passwordUrl = KEYCLOAK_USERCREATION_URL + "/" + userId + "/reset-password";

        try {
            restTemplate.put(passwordUrl, new HttpEntity<>(passwordPayload, headers));
        } catch (Exception ex) {
            throw new RuntimeException("Failed to set user password: " + ex.getMessage(), ex);
        }
    }
    */

    /*
    private void setUserPassword(String token, String userId, String password) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + getAdminToken());
        //headers.add("Authorization", "Bearer " + token);
        //headers.add("Authorization", token);
        headers.add("Content-Type", "application/json");

        Map<String, Object> passwordPayload = new HashMap<>();
        passwordPayload.put("type", "password");
        passwordPayload.put("value", password);
        passwordPayload.put("temporary", false);

        String passwordUrl = KEYCLOAK_USERCREATION_URL + "/" + userId + "/reset-password";

        try {
            restTemplate.put(passwordUrl, new HttpEntity<>(passwordPayload, headers));
        } catch (HttpClientErrorException.Unauthorized e) {
            throw new RuntimeException("Failed to set user password: Unauthorized access. Check token permissions.", e);
        } catch (HttpClientErrorException.Forbidden e) {
            throw new RuntimeException("Failed to set user password: Forbidden access. Verify roles and Keycloak policies.", e);
        } catch (HttpClientErrorException.NotFound e) {
            throw new RuntimeException("Failed to set user password: User ID not found. Verify the user exists.", e);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to set user password: An unexpected error occurred.", ex);
        }
    }
    */

    private void setUserPassword(String token, String userId, String password) {
        HttpHeaders headers = new HttpHeaders();
        //headers.add("Authorization", "Bearer " + token);
        headers.add("Authorization", "Bearer " + getAdminToken());
        //headers.add("Authorization", token);
        headers.add("Content-Type", "application/json");

        Map<String, Object> passwordPayload = new HashMap<>();
        passwordPayload.put("type", "password");
        passwordPayload.put("value", password);
        passwordPayload.put("temporary", false);

        String passwordUrl = KEYCLOAK_USERCREATION_URL + "/" + userId + "/reset-password";
        System.err.println(userId);
        System.err.println(passwordUrl);

        try {
            HttpEntity<Map<String, Object>> request = new HttpEntity<>(passwordPayload, headers);
            ResponseEntity<Void> response = restTemplate.exchange(
                    passwordUrl,
                    HttpMethod.PUT,
                    request,
                    Void.class
            );

            if (response.getStatusCode() != HttpStatus.NO_CONTENT) {
                throw new RuntimeException("Failed to set user password: Unexpected response status: " + response.getStatusCode());
            }
        } catch (HttpClientErrorException.Unauthorized e) {
            throw new RuntimeException("Failed to set user password: Unauthorized access. Check token permissions.", e);
        } catch (HttpClientErrorException.Forbidden e) {
            throw new RuntimeException("Failed to set user password: Forbidden access. Verify roles and Keycloak policies.", e);
        } catch (HttpClientErrorException.NotFound e) {
            throw new RuntimeException("Failed to set user password: User ID not found. Verify the user exists.", e);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to set user password: An unexpected error occurred.", ex);
        }
    }


    private String extractUserIdFromToken(String token) throws JsonProcessingException {
        System.err.println("Token: " + token);
        String[] parts = token.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("Invalid token format");

        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
        Map<String, Object> claims = new ObjectMapper().readValue(payload, Map.class);

        String userId = claims.get("sub").toString();
        System.err.println("Id: " + userId);
        return userId;
    }

    private String extractUsernameFromToken(String token) throws JsonProcessingException {
        String[] parts = token.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("Invalid token format");

        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
        Map<String, Object> claims = new ObjectMapper().readValue(payload, Map.class);

        return claims.get("preferred_username").toString(); // Extrahiere den Username
    }


    /*
    private boolean validateOldPassword(String userId, String oldPassword, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", CLIENT_ID);
        body.add("username", userId);
        body.add("password", oldPassword);

        try {
            restTemplate.postForEntity(KEYCLOAK_TOKEN_URL, new HttpEntity<>(body, headers), String.class);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
    */

    private boolean validateOldPassword(String username, String oldPassword) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", CLIENT_ID);
        body.add("client_secret", CLIENT_SECRET);
        body.add("username", username);
        body.add("password", oldPassword);
        body.add("scope", "openid");

        System.err.println("Old2: " + oldPassword);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(KEYCLOAK_TOKEN_URL, new HttpEntity<>(body, headers), String.class);
            System.err.println(response);
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }



}

