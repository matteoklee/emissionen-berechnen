package de.kleemann.calculationservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
@RequestMapping("/v1/calculations")
public class CalculationServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(CalculationServiceApplication.class, args);
	}

	@GetMapping("/greeting")
	public ResponseEntity<?> greeting() {
		return ResponseEntity.ok("Calculation-Service is available.");
	}

}
