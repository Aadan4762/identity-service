package com.adan.identityservice.service;

public interface EmailService {
    void sendRegistrationConfirmationEmail(String to, String username);
    void sendRoleAssignmentEmail(String to, String username, String role);
    void sendOtpEmail(String to, String username, String otpCode);
    void sendPasswordChangeEmail(String to, String username);
}
