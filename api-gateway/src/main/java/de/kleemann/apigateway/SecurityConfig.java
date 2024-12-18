package de.kleemann.apigateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Class "SecurityConfig" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 18.12.2024
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange()
                .pathMatchers("/v1/hotels/**").hasRole("USER")
                .pathMatchers("/v1/calculations/**").hasRole("USER")
                .pathMatchers("/v1/evidence/**").hasRole("MODERATOR")
                .anyExchange().authenticated()
                .and()
                .oauth2ResourceServer()
                .jwt();
        return http.build();
    }

}
