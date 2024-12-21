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

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests ->
            requests
                .requestMatchers("/swagger-ui-custom.html").permitAll()
                .requestMatchers("/swagger-ui/**").permitAll()
                .requestMatchers("/api-docs/**").permitAll()

                .requestMatchers("/auth/greeting").permitAll()
                .requestMatchers("/auth/admin").permitAll()
                .requestMatchers("/auth/validate").permitAll()
                .requestMatchers("/auth/login").permitAll()
                .requestMatchers("/auth/refresh-token").permitAll()

                .requestMatchers("/users/register").permitAll()
                .requestMatchers("/users/change-password").permitAll()
                .requestMatchers("/users/username/{username}/**").authenticated()
                .requestMatchers("/users/{userId}/**").permitAll()
                .requestMatchers("/users/userinfo").permitAll()

                .requestMatchers("/users/debug").permitAll()
                //.requestMatchers("/admin/**").hasRole("admin")
                //.requestMatchers("/moderator/**").hasRole("moderator")
                //.requestMatchers("/user/**").hasAnyRole("user", "admin", "moderator")
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

    /*
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("realm_access.roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
        authenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return authenticationConverter;
    }
    */
}
