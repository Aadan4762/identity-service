package com.adan.identityservice.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
public class TwoFactorAuthService {

    @Autowired
    private EmailService emailService;

    // Store OTP codes with expiration times (in a production app, use a database)
    private final Map<String, OtpData> otpStorage = new HashMap<>();

    // Inner class to store OTP data
    private static class OtpData {
        private final String code;
        private final LocalDateTime expiryTime;

        public OtpData(String code, LocalDateTime expiryTime) {
            this.code = code;
            this.expiryTime = expiryTime;
        }

        public String getCode() {
            return code;
        }

        public LocalDateTime getExpiryTime() {
            return expiryTime;
        }

        public boolean isExpired() {
            return LocalDateTime.now().isAfter(expiryTime);
        }
    }

    /**
     * Generates a 6-digit OTP code for the given username
     * @param username The username to generate code for
     * @param email Email to send the code to
     * @return The generated OTP code
     */
    public String generateAndSendOtp(String username, String email) {
        // Generate a random 6-digit code
        String otpCode = generateRandomCode();

        // Store the code with a 5-minute expiration
        otpStorage.put(username, new OtpData(otpCode, LocalDateTime.now().plusMinutes(5)));

        // Send the code via email
        sendOtpEmail(email, username, otpCode);

        return otpCode;
    }

    /**
     * Validates the OTP code for a user
     * @param username The username to validate code for
     * @param otpCode The OTP code to validate
     * @return true if valid, false otherwise
     */
    public boolean validateOtp(String username, String otpCode) {
        OtpData otpData = otpStorage.get(username);

        // Check if OTP exists and is valid
        if (otpData == null) {
            return false;
        }

        // Check if OTP is expired
        if (otpData.isExpired()) {
            otpStorage.remove(username); // Clean up expired OTP
            return false;
        }

        // Check if OTP matches
        boolean isValid = otpData.getCode().equals(otpCode);

        // Remove OTP after validation attempt
        if (isValid) {
            otpStorage.remove(username);
        }

        return isValid;
    }

    /**
     * Generates a random 6-digit code
     * @return A 6-digit code as string
     */
    private String generateRandomCode() {
        SecureRandom random = new SecureRandom();
        int code = 100000 + random.nextInt(900000); // Generates a number between 100000 and 999999
        return String.valueOf(code);
    }

    /**
     * Sends the OTP code via email
     * @param email Recipient email
     * @param username Username
     * @param otpCode The OTP code
     */
    private void sendOtpEmail(String email, String username, String otpCode) {
        try {
            emailService.sendOtpEmail(email, username, otpCode);
        } catch (Exception e) {
            // Log the error but don't throw it
            System.err.println("Failed to send OTP email: " + e.getMessage());
        }
    }
}