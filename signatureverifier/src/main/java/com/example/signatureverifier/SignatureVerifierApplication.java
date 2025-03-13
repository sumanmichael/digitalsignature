package com.example.signatureverifier;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

@SpringBootApplication
public class SignatureVerifierApplication {

	public static void main(String[] args) {
		SpringApplication.run(SignatureVerifierApplication.class, args);
	}

	@Configuration
	public class JacksonConfig {
		@Bean
		public ObjectMapper objectMapper() {
			ObjectMapper objectMapper = new ObjectMapper();
			objectMapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
			return objectMapper;
		}
	}
}
