package de.kleemann.apigateway;

import org.springframework.context.annotation.Configuration;

/**
 * Class "SecurityConfig" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 18.12.2024
 */
@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled = true)
public class SecurityConfig {

    /*
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // ...
                .csrf((csrf) -> csrf
                        .ignoringRequestMatchers("/**")
                )
                .httpBasic().disable()
                .oauth2ResourceServer()
                .jwt();
        return http.build();
    }
    */

}
