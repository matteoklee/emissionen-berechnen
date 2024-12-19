package de.kleemann.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServiceApplication {
    //@EnableRateLimiter
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }

}
