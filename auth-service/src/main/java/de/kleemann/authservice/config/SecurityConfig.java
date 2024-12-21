package de.kleemann.authservice.config;

import de.kleemann.authservice.config.util.KeycloakJwtAuthenticationConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

/**
 * Class "SecurityConfig" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 19.12.2024
 */
@Configuration
@EnableGlobalMethodSecurity(jsr250Enabled = true, prePostEnabled = true)
public class SecurityConfig {

    //TODO: IP-basiertes-Rate-Limiting
    @Value("${api.version}")
    private String apiVersion;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests ->
            requests
                .requestMatchers("/swagger-ui-custom.html").permitAll()
                .requestMatchers("/swagger-ui/**").permitAll()
                .requestMatchers("/api-docs/**").permitAll()

                .requestMatchers("/api/" + apiVersion + "/auth/greeting").permitAll()
                .requestMatchers("/api/" + apiVersion + "/auth/admin").permitAll()
                .requestMatchers("/api/" + apiVersion + "/auth/validate").permitAll()
                .requestMatchers("/api/" + apiVersion + "/auth/login").permitAll()
                .requestMatchers("/api/" + apiVersion + "/auth/refresh-token").permitAll()

                .requestMatchers("/api/" + apiVersion + "/users/register").permitAll()
                .requestMatchers("/api/" + apiVersion + "/users/change-password").permitAll()
                .requestMatchers("/api/" + apiVersion + "/users/username/{username}/**").authenticated()
                .requestMatchers("/api/" + apiVersion + "/users/{userId}/**").permitAll()
                .requestMatchers("/api/" + apiVersion + "/users/userinfo").permitAll()
                .requestMatchers("/api/" + apiVersion + "/users/roles").authenticated()

                .requestMatchers("/api/" + apiVersion + "/admin/**").authenticated()
                .requestMatchers("/users/debug").permitAll()

                .anyRequest().authenticated())
                //.oauth2ResourceServer(oAuth -> oAuth.jwt(Customizer.withDefaults()));
                //.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())));


        http.cors(AbstractHttpConfigurer::disable);
        http.csrf(AbstractHttpConfigurer::disable);
        /*
        http.setSharedObject(ContentNegotiationStrategy.class, new
                HeaderContentNegotiationStrategy());
                */
        return http.build();

    }
}
