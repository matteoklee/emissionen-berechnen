package de.kleemann.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

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
        http.authorizeHttpRequests(requests ->
            requests
                .requestMatchers("/swagger-ui-custom.html").permitAll()
                .requestMatchers("/swagger-ui/**").permitAll()
                .requestMatchers("/api-docs/**").permitAll()

                .requestMatchers("/auth/greeting").permitAll()
                .requestMatchers("/auth/admin").permitAll()
                .requestMatchers("/auth/validate").permitAll()
                .requestMatchers("/auth/login").permitAll()
                .requestMatchers("/auth/register").permitAll()
                .requestMatchers("/auth/refresh-token").permitAll()
                //.requestMatchers("/admin/**").hasRole("admin")
                //.requestMatchers("/moderator/**").hasRole("moderator")
                //.requestMatchers("/user/**").hasAnyRole("user", "admin", "moderator")
                .anyRequest().authenticated())
                .oauth2ResourceServer(oAuth -> oAuth.jwt(Customizer.withDefaults()));

        http.cors(AbstractHttpConfigurer::disable);
        http.csrf(AbstractHttpConfigurer::disable);
        /*
        http.setSharedObject(ContentNegotiationStrategy.class, new
                HeaderContentNegotiationStrategy());
                */
        return http.build();
        /*
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/swagger-ui-custom.html").permitAll()
                .requestMatchers("/swagger-ui/**").permitAll()
                .requestMatchers("/api-docs/**").permitAll()

                .requestMatchers("/auth/greeting").permitAll()
                .requestMatchers("/auth/admin").permitAll()
                .requestMatchers("/auth/validate").permitAll()
                .requestMatchers("/auth/login").permitAll()
                .requestMatchers("/auth/register").permitAll()
                .requestMatchers("/auth/refresh-token").permitAll()
                //.requestMatchers("/admin/**").hasRole("admin")
                //.requestMatchers("/moderator/**").hasRole("moderator")
                //.requestMatchers("/user/**").hasAnyRole("user", "admin", "moderator")
                .anyRequest().authenticated()
                //.and()
                //.httpBasic()
                .and().csrf().disable()
                .oauth2ResourceServer()
                .jwt());
        return http.build();
         */
    }

}
