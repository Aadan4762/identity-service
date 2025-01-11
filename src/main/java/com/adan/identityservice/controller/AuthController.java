package com.adan.identityservice.controller;

import com.adan.identityservice.dto.AuthRequest;
import com.adan.identityservice.entity.UserCredential;
import com.adan.identityservice.repository.UserCredentialRepository;
import com.adan.identityservice.service.AuthService;
import com.adan.identityservice.service.JwtService;
import com.adan.identityservice.service.TokenBlacklistService;
import org.springframework.beans.factory.annotation.Autowired;
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
    public String addNewUser(@RequestBody UserCredential user) {
        return service.saveUser(user); // Default role will be assigned here
    }

    @PostMapping("/login")
    public Map<String, String> getToken(@RequestBody AuthRequest authRequest) {
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if (authenticate.isAuthenticated()) {
            return service.login(authRequest.getUsername());
        } else {
            throw new RuntimeException("Invalid access");
        }
    }

    @PostMapping("/refresh")
    public Map<String, String> refreshAccessToken(@RequestParam String refreshToken) {
        String username = jwtService.validateAndGetUsername(refreshToken);
        UserCredential user = repository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        String newAccessToken = jwtService.login(username, user.getRole(), user.getFirstName(), user.getLastName());
        Map<String, String> response = new HashMap<>();
        response.put("accessToken", newAccessToken);
        return response;
    }



    @GetMapping("/validate")
    public String validateToken(@RequestParam("token") String token) {
        try {
            service.validateToken(token);
            return "Token is valid";
        } catch (Exception e) {
            return "Token validation failed: " + e.getMessage();
        }
    }

    @PostMapping("/logout")
    public String logout(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            tokenBlacklistService.addToken(token);
            return "Logged out successfully!";
        }
        return "Invalid request!";
    }


    @PutMapping("/role")
    public String updateRole(@RequestParam("username") String username, @RequestParam("role") String role) {
        return service.updateRole(username, role);
    }
}
