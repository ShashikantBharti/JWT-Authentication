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

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    // Register a new user
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

    // Login Existing User
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
