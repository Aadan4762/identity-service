package com.adan.identityservice.controller;

import com.adan.identityservice.dto.AuthRequest;
import com.adan.identityservice.entity.UserCredential;
import com.adan.identityservice.repository.UserCredentialRepository;
import com.adan.identityservice.service.AuthService;
import com.adan.identityservice.service.JwtService;
import com.adan.identityservice.service.TokenBlacklistService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserCredentialRepository repository;

    @Autowired
    private AuthService service;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> addNewUser(@RequestBody UserCredential user) {
        return service.saveUser(user);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> getToken(@RequestBody AuthRequest authRequest) {
        try {
            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
            if (authenticate.isAuthenticated()) {
                return ResponseEntity.ok(service.login(authRequest.getUsername()));
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Invalid credentials"));
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Invalid credentials"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshAccessToken(@RequestParam String refreshToken) {
        try {
            String username = jwtService.validateAndGetUsername(refreshToken);
            UserCredential user = repository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            String newAccessToken = jwtService.login(username, user.getRole(), user.getFirstName(), user.getLastName());
            return ResponseEntity.ok(Map.of("accessToken", newAccessToken, "message", "Access token refreshed successfully"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("message", "Invalid refresh token: " + e.getMessage()));
        }
    }

    @GetMapping("/validate")
    public ResponseEntity<Map<String, String>> validateToken(@RequestParam("token") String token) {
        try {
            service.validateToken(token);
            return ResponseEntity.ok(Map.of("message", "Token is valid"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Token validation failed: " + e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            tokenBlacklistService.addToken(token);
            return ResponseEntity.ok(Map.of("message", "Logged out successfully!"));
        }
        return ResponseEntity.badRequest().body(Map.of("message", "Invalid request!"));
    }


    @PutMapping("/role")
    public ResponseEntity<Map<String, String>> updateRole(@RequestParam("username") String username, @RequestParam("role") String role) {
        String result = service.updateRole(username, role);
        if (result.startsWith("User role updated")) {
            return ResponseEntity.ok(Map.of("message", result));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", result));
        }
    }
}
