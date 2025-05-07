package com.adan.identityservice.service;

import com.adan.identityservice.dto.AuthRequest;
import com.adan.identityservice.dto.UserRegistrationDTO;
import com.adan.identityservice.entity.Role;
import com.adan.identityservice.entity.UserCredential;
import com.adan.identityservice.repository.UserCredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

@Service

public class AuthService {

    @Autowired
    private UserCredentialRepository repository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private EmailService emailService;

    @Autowired
    private TwoFactorAuthService twoFactorAuthService;


    public ResponseEntity<Map<String, String>> registerUser(UserRegistrationDTO registrationDTO) {
        Map<String, String> response = new HashMap<>();

        if (registrationDTO.getFirstName() == null || registrationDTO.getFirstName().isEmpty()) {
            response.put("message", "First name is required");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        if (registrationDTO.getLastName() == null || registrationDTO.getLastName().isEmpty()) {
            response.put("message", "Last name is required");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        if (registrationDTO.getUsername() == null || registrationDTO.getUsername().isEmpty()) {
            response.put("message", "Username is required");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        if (registrationDTO.getEmail() == null || registrationDTO.getEmail().isEmpty()) {
            response.put("message", "Email is required");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        String emailRegex = "^[a-zA-Z0-9._%+-]+@gmail\\.com$";
        if (!Pattern.matches(emailRegex, registrationDTO.getEmail())) {
            response.put("message", "Email must be a valid Gmail address");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        if (registrationDTO.getPassword() == null || registrationDTO.getPassword().isEmpty()) {
            response.put("message", "Password is required");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        if (registrationDTO.getConfirmPassword() == null || registrationDTO.getConfirmPassword().isEmpty()) {
            response.put("message", "Confirm Password is required");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        if (!registrationDTO.getPassword().equals(registrationDTO.getConfirmPassword())) {
            response.put("message", "Password and Confirm Password must match");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        if (repository.existsByUsername(registrationDTO.getUsername())) {
            response.put("message", "Username already exists");
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }
        if (repository.existsByEmail(registrationDTO.getEmail())) {
            response.put("message", "Email already exists");
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }

        UserCredential user = new UserCredential();
        user.setFirstName(registrationDTO.getFirstName());
        user.setLastName(registrationDTO.getLastName());
        user.setUsername(registrationDTO.getUsername());
        user.setEmail(registrationDTO.getEmail());
        user.setPassword(passwordEncoder.encode(registrationDTO.getPassword()));

        try {
            repository.save(user);

            // Send confirmation email
            emailService.sendRegistrationConfirmationEmail(
                    user.getEmail(),
                    user.getUsername()
            );

            response.put("message", "User added to the system with role USER");
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (DataIntegrityViolationException e) {
            response.put("message", "Username or email already exists");
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }
    }


    public Map<String, String> login(String username) {
        UserCredential user = repository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String roleValue = user.getRole().getValue();
        String accessToken = jwtService.login(username, roleValue, user.getFirstName(), user.getLastName());
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

    public String updateRole(String username, String roleStr) {
        try {
            Role role = Role.fromValue(roleStr);
            Optional<UserCredential> optionalUser = repository.findByUsername(username);
            if (optionalUser.isPresent()) {
                UserCredential user = optionalUser.get();

                // Check if the role is actually changing
                boolean isRoleChanged = user.getRole() == null || !user.getRole().equals(role);

                user.setRole(role);
                repository.save(user);

                // Send email notification only if role has changed
                if (isRoleChanged) {
                    emailService.sendRoleAssignmentEmail(
                            user.getEmail(),
                            user.getUsername(),
                            role.getValue()
                    );
                }

                return "User role updated to " + role.getValue();
            } else {
                return "User not found";
            }
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        }
    }

    /**
     * Step 1 of login: Validate credentials and send OTP
     */
    public ResponseEntity<Map<String, String>> login(AuthRequest loginRequest) {
        Map<String, String> response = new HashMap<>();

        try {
            Optional<UserCredential> userOpt = repository.findByUsername(loginRequest.getUsername());

            if (userOpt.isEmpty()) {
                response.put("message", "Invalid username or password");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            UserCredential user = userOpt.get();

            // Validate password
            if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                response.put("message", "Invalid username or password");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            // Generate and send OTP
            twoFactorAuthService.generateAndSendOtp(user.getUsername(), user.getEmail());

            response.put("message", "OTP sent to your registered email");
            response.put("username", user.getUsername());
            response.put("status", "OTP_REQUIRED");

            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception e) {
            response.put("message", "Login failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Step 2 of login: Verify OTP and issue tokens
     */
    public ResponseEntity<Map<String, String>> verifyOtpAndLogin(String username, String otpCode) {
        Map<String, String> response = new HashMap<>();

        // Validate OTP
        if (!twoFactorAuthService.validateOtp(username, otpCode)) {
            response.put("message", "Invalid or expired OTP");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        try {
            // Generate tokens
            UserCredential user = repository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            String roleValue = user.getRole() != null ? user.getRole().getValue() : "USER";
            String accessToken = jwtService.login(username, roleValue, user.getFirstName(), user.getLastName());
            String refreshToken = jwtService.generateRefreshToken(username);

            response.put("accessToken", accessToken);
            response.put("refreshToken", refreshToken);
            response.put("message", "Login successful");

            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception e) {
            response.put("message", "Login failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }


    // Method to resend OTP if needed
    public ResponseEntity<Map<String, String>> resendOtp(String username) {
        Map<String, String> response = new HashMap<>();

        try {
            Optional<UserCredential> userOpt = repository.findByUsername(username);

            if (userOpt.isEmpty()) {
                response.put("message", "User not found");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }

            UserCredential user = userOpt.get();

            // Generate and send new OTP
            twoFactorAuthService.generateAndSendOtp(user.getUsername(), user.getEmail());

            response.put("message", "New OTP sent to your registered email");
            response.put("username", user.getUsername());

            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception e) {
            response.put("message", "Failed to resend OTP: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}

