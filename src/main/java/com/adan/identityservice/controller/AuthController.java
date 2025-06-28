package com.adan.identityservice.controller;

import com.adan.identityservice.dto.AuthRequest;
import com.adan.identityservice.dto.OtpVerificationDTO;
import com.adan.identityservice.dto.PasswordChangeDTO;
import com.adan.identityservice.dto.UserRegistrationDTO;
import com.adan.identityservice.entity.UserCredential;
import com.adan.identityservice.repository.UserCredentialRepository;
import com.adan.identityservice.service.AuthService;
import com.adan.identityservice.service.JwtService;
import com.adan.identityservice.service.TokenBlacklistService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "Authentication and Authorization API")
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

    @Operation(summary = "Register a new user", description = "Register a new user with USER role")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User successfully registered"),
            @ApiResponse(responseCode = "400", description = "Invalid input data")
    })
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> registerUser(@RequestBody UserRegistrationDTO registrationDTO) {
        return service.registerUser(registrationDTO);
    }

//    @Operation(summary = "User login", description = "Invalid user credentials")
//    @ApiResponses(value = {
//            @ApiResponse(responseCode = "200", description = "Successfully logged In"),
//            @ApiResponse(responseCode = "400", description = "Invalid user credentials")
//    })
//
//    @PostMapping("/login")
//    public ResponseEntity<Map<String, String>> getToken(@RequestBody AuthRequest authRequest) {
//        try {
//            Authentication authenticate = authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
//            if (authenticate.isAuthenticated()) {
//                return ResponseEntity.ok(service.login(authRequest.getUsername()));
//            } else {
//                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Invalid credentials"));
//            }
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Invalid credentials"));
//        }
//    }
    /**
     * Step 1: Initiate login with username and password.
     * This will validate credentials and send OTP if valid.
     */
    @Operation(summary = "Initiate login with 2FA", description = "Step 1: Validate credentials and send OTP if valid")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Credentials validated, OTP sent"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials")
    })
    @PostMapping("/login/initiate")
    public ResponseEntity<Map<String, String>> initiateLogin(@RequestBody AuthRequest authRequest) {
        return service.login(authRequest);
    }

    /**
     * Step 2: Verify OTP and complete login process.
     * This will validate OTP and generate tokens if valid.
     */
    @Operation(summary = "Verify OTP and complete login", description = "Step 2: Validate OTP and generate tokens if valid")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP verified, tokens generated"),
            @ApiResponse(responseCode = "401", description = "Invalid or expired OTP")
    })
    @PostMapping("/login/verify-otp")
    public ResponseEntity<Map<String, String>> verifyOtpAndLogin(@RequestBody OtpVerificationDTO verificationDTO) {
        return service.verifyOtpAndLogin(verificationDTO.getUsername(), verificationDTO.getOtpCode());
    }

    @Operation(summary = "Resend OTP", description = "Resend OTP if it was not received or expired")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "New OTP sent"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @PostMapping("/login/resend-otp")
    public ResponseEntity<Map<String, String>> resendOtp(@RequestParam String username) {
        return service.resendOtp(username);
    }


    @Operation(summary = "Refresh access token", description = "Get a new access token using a valid refresh token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Access token refreshed successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid refresh token")
    })
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshAccessToken(@RequestParam String refreshToken) {
        try {
            String username = jwtService.validateAndGetUsername(refreshToken);
            UserCredential user = repository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Get the role value as a string from the Role enum
            String roleStr = user.getRole().getValue();

            String newAccessToken = jwtService.login(username, roleStr, user.getFirstName(), user.getLastName());
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

    @Operation(summary = "User logout", description = "Invalidate the current JWT token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully logged out"),
            @ApiResponse(responseCode = "400", description = "Invalid token")
    })
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            tokenBlacklistService.addToken(token);
            return ResponseEntity.ok(Map.of("message", "Logged out successfully!"));
        }
        return ResponseEntity.badRequest().body(Map.of("message", "Invalid request!"));
    }

    @Operation(summary = "Update user role", description = "Update a user's role (requires SUPER_ADMIN privileges)")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User role updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid role or username")
    })
    @PutMapping("/role")
    @PreAuthorize("hasAuthority('SUPER_ADMIN')") // Match the authority format used in your security config
    public ResponseEntity<Map<String, String>> updateRole(@RequestParam("username") String username, @RequestParam("role") String roleStr) {
        String result = service.updateRole(username, roleStr);
        if (result.startsWith("User role updated")) {
            return ResponseEntity.ok(Map.of("message", result));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", result));
        }
    }

    @Operation(summary = "Change password", description = "Change user password and send email notification")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password changed successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "401", description = "Current password is incorrect"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @PostMapping("/change-password")
    public ResponseEntity<Map<String, String>> changePassword(@RequestBody PasswordChangeDTO passwordChangeDTO) {
        return service.changePassword(passwordChangeDTO);
    }
}
