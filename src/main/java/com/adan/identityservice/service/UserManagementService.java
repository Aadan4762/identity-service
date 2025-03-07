package com.adan.identityservice.service;

import com.adan.identityservice.entity.Role;
import com.adan.identityservice.entity.UserCredential;
import com.adan.identityservice.repository.UserCredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class UserManagementService {

    @Autowired
    private UserCredentialRepository userRepository;

    public ResponseEntity<Map<String, String>> assignRole(String username, String roleName) {
        Map<String, String> response = new HashMap<>();

        // Check if role exists
        Role role;
        try {
            role = Role.fromValue(roleName);
        } catch (IllegalArgumentException e) {
            response.put("message", "Invalid role: " + roleName);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        // Find user
        Optional<UserCredential> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            response.put("message", "User not found: " + username);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }

        // Update user role
        UserCredential user = userOpt.get();
        user.setRole(role);
        userRepository.save(user);

        response.put("message", "Role " + roleName + " assigned to user " + username + " successfully");
        return ResponseEntity.ok(response);
    }
}