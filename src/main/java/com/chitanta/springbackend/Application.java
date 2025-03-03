package com.chitanta.springbackend;

import com.chitanta.springbackend.auth.AuthenticationService;
import com.chitanta.springbackend.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.chitanta.springbackend.user.Role.*;

@SpringBootApplication
public class Application {
	//TODO: refactor all strings and integers out of all methods and make CONSTANTS, too lazy now C:<
	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(AuthenticationService authService) {
		return args -> {
			RegisterRequest admin = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.email("admin@mail.com")
					.password("password")
					.role(ADMIN)
					.build();

			RegisterRequest manager = RegisterRequest.builder()
					.firstname("Manager")
					.lastname("Manager")
					.email("manager@mail.com")
					.password("password")
					.role(MANAGER)
					.build();

			RegisterRequest user = RegisterRequest.builder()
					.firstname("User")
					.lastname("User")
					.email("user@mail.com")
					.password("1234")
					.role(USER)
					.build();

			System.out.println("Admin registered: " + authService.registerWithoutCookies(admin).getEmail());
			System.out.println("Manager registered: " + authService.registerWithoutCookies(manager).getEmail());
			System.out.println("User registered: " + authService.registerWithoutCookies(user).getEmail());
		};
	}
}