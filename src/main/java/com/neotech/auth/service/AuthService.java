package com.neotech.auth.service;

import com.neotech.auth.dto.AuthRequest;
import com.neotech.auth.dto.AuthResponse;
import com.neotech.auth.dto.LoginRequest;
import com.neotech.auth.model.User;
import com.neotech.auth.repository.UserRepository;
import com.neotech.auth.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;


/**
 * Service class for handling authentication-related operations, such as user registration and login.
 * This service interacts with the {@link UserRepository} for user data access and the
 * {@link JwtUtil} for JWT token generation.
 */
@Service
@RequiredArgsConstructor
public class AuthService {
    /**
     * Repository for accessing user data.  Used for checking email existence, saving new users,
     * and retrieving user details during login.  Injected via constructor injection.
     */
    private final UserRepository userRepository;
    /**
     * Utility class for JWT operations (generating tokens).  Used for creating JWT tokens
     * upon successful registration or login.  Injected via constructor injection.
     */
    private final JwtUtil jwtUtil;
    /**
     * Password encoder for hashing and verifying passwords.  Used to securely store user passwords
     * during registration and to verify passwords during login.  A BCryptPasswordEncoder is
     * instantiated here.  Consider making this injectable.
     */
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * Registers a new user in the system.
     *
     * @param request The {@link AuthRequest} containing the user's registration details.
     * @return An {@link AuthResponse} containing the JWT token and a success message.
     * @throws RuntimeException If the email is already in use.
     */
    public AuthResponse register(AuthRequest request) {
        // Check if email already in use
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email is already in use.");
        }

        // Hash Password
        String hashedPassword = passwordEncoder.encode(request.getPassword());

        // Assign default role if no one is provided.
        Set<String> roles = request.getRoles() != null ? request.getRoles() : new HashSet<>();
        if (roles.isEmpty()) {
            roles.add("USER");
        }

        // Create User
        User user = new User(null, request.getUsername(), request.getEmail(), hashedPassword, roles);
        userRepository.save(user);

        // Generate JWT Token
        String token = jwtUtil.generateToken(user.getEmail());

        return new AuthResponse(token, "User registered successfully!");
    }

    /**
     * Logs in an existing user.
     *
     * @param request The {@link LoginRequest} containing the user's email and password.
     * @return An {@link AuthResponse} containing the JWT token and a success message.
     * @throws RuntimeException If the email or password is invalid.
     */
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new RuntimeException("Invalid email or password"));

        // Verify Password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid email or Password");
        }

        // Generate JWT Token
        String token = jwtUtil.generateToken(user.getEmail());

        return new AuthResponse(token, "Login Successful");
    }
}
