package de.kleemann.authservice.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Class "SwaggerConfig" is used for ...
 *
 * @author Matteo Kleemann
 * @version 1.0
 * @since 19.12.2024
 */
@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Auth Service API")
                        .version("1.0")
                        .description("API-Dokumentation für den Authentifizierungsservice")
                );
    }

}
