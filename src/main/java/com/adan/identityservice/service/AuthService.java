package com.adan.identityservice.service;

import com.adan.identityservice.entity.UserCredential;
import com.adan.identityservice.repository.UserCredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class AuthService {

    @Autowired
    private UserCredentialRepository repository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    public ResponseEntity<Map<String, String>> saveUser(UserCredential credential) {
        Map<String, String> response = new HashMap<>();

        if (credential.getFirstName() == null || credential.getFirstName().isEmpty()) {
            response.put("message", "First name is required");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        if (credential.getLastName() == null || credential.getLastName().isEmpty()) {
            response.put("message", "Last name is required");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        if (credential.getPassword() == null || credential.getPassword().isEmpty()) {
            response.put("message", "Password is required");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        if (credential.getConfirmPassword() == null || credential.getConfirmPassword().isEmpty()) {
            response.put("message", "Confirm Password is required");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        if (!credential.getPassword().equals(credential.getConfirmPassword())) {
            response.put("message", "Password and Confirm Password must match");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        credential.setPassword(passwordEncoder.encode(credential.getPassword()));
        credential.setRole("USER");
        repository.save(credential);

        response.put("message", "User added to the system with role USER");
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    public Map<String, String> login(String username) {
        UserCredential user = repository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        String accessToken = jwtService.login(username, user.getRole(), user.getFirstName(), user.getLastName());
        String refreshToken = jwtService.generateRefreshToken(username);
        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);
        tokens.put("message", "Login successful");
        return tokens;
    }

    public void validateToken(String token) {
        jwtService.validateToken(token);
    }

    public String updateRole(String username, String role) {
        List<String> allowedRoles = Arrays.asList("USER", "ADMIN", "HeadTeacher");
        if (!allowedRoles.contains(role)) {
            return "Invalid role: " + role;
        }
        Optional<UserCredential> optionalUser = repository.findByUsername(username);
        if (optionalUser.isPresent()) {
            UserCredential user = optionalUser.get();
            user.setRole(role);
            repository.save(user);
            return "User role updated to " + role;
        } else {
            return "User not found";
        }
    }
}

