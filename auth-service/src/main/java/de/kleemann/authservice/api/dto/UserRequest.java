package de.kleemann.authservice.api.dto;

import lombok.Data;

/**
 * Class "UserRequestDTO" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 18.12.2024
 */
@Data
public class UserRequest {
    private String username;
    private String password;
    private String email;
}
