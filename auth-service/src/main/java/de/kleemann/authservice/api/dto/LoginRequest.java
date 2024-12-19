package de.kleemann.authservice.api.dto;

import lombok.Data;

/**
 * Class "LoginRequest" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 19.12.2024
 */
@Data
public class LoginRequest {
    private String username;
    private String password;
}
