package com.neotech.auth.controller;

import com.neotech.auth.dto.AuthRequest;
import com.neotech.auth.dto.AuthResponse;
import com.neotech.auth.dto.LoginRequest;
import com.neotech.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for handling authentication-related requests, such as user registration and login.
 * This controller exposes endpoints under the "/api/auth" path.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {
    /**
     * The authentication service, responsible for handling the business logic of user registration and login.
     * Injected via constructor injection.
     */
    private final AuthService authService;

    /**
     * Endpoint for registering a new user.
     *
     * @param request The {@link AuthRequest} containing the user's registration details.  The request body
     *                is validated using {@link Valid}.
     * @return A {@link ResponseEntity} containing the {@link AuthResponse} with the JWT token and a success message.
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody AuthRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    /**
     * Endpoint for logging in an existing user.
     *
     * @param request The {@link LoginRequest} containing the user's login credentials (email and password).
     *                The request body is validated using {@link Valid}.
     * @return A {@link ResponseEntity} containing the {@link AuthResponse} with the JWT token and a success message.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}
