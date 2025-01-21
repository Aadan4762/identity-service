package com.adan.identityservice.service;

import com.adan.identityservice.entity.UserCredential;
import com.adan.identityservice.repository.UserCredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
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


    public String saveUser(UserCredential credential) {
        if (credential.getFirstName() == null || credential.getFirstName().isEmpty()) {
            return "First name is required";
        }
        if (credential.getLastName() == null || credential.getLastName().isEmpty()) {
            return "Last name is required";
        }
        if (credential.getPassword() == null || credential.getPassword().isEmpty()) {
            return "Password is required";
        }
        credential.setPassword(passwordEncoder.encode(credential.getPassword()));
        credential.setRole("USER");
        repository.save(credential);

        return "User added to the system with role USER";
    }


    public Map<String, String> login(String username) {
        UserCredential user = repository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        String accessToken = jwtService.login(username, user.getRole(), user.getFirstName(), user.getLastName());
        String refreshToken = jwtService.generateRefreshToken(username);
        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);
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
