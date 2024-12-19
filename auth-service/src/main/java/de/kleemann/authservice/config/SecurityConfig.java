package de.kleemann.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Class "SecurityConfig" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 19.12.2024
 */
@Configuration
@EnableGlobalMethodSecurity(jsr250Enabled = true)
public class SecurityConfig {

    //TODO: IP-basiertes-Rate-Limiting
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .requestMatchers("/actuator/resilience4jratelimiter").permitAll()
                .requestMatchers("/auth/validate").permitAll()
                .requestMatchers("/auth/login").permitAll()
                .requestMatchers("/auth/register").permitAll()
                .requestMatchers("/admin/**").hasRole("admin")
                .requestMatchers("/moderator/**").hasRole("moderator")
                .requestMatchers("/user/**").hasAnyRole("user", "admin", "moderator")
                .anyRequest().authenticated()
                //.and()
                //.httpBasic()
                .and().csrf().disable()
                .oauth2ResourceServer()
                .jwt();
        return http.build();
    }


}
