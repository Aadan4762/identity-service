package com.adan.identityservice.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {

    @Autowired
    private JavaMailSender emailSender;

    @Override
    public void sendRegistrationConfirmationEmail(String to, String username) {
        try {
            MimeMessage message = emailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setTo(to);
            helper.setSubject("Registration Confirmation");

            String emailContent =
                    "<html><body>" +
                            "<h2>Registration Confirmation</h2>" +
                            "<p>Dear " + username + ",</p>" +
                            "<p>Your registration for our system is successful.</p>" +
                            "<p>Thank you for joining us!</p>" +
                            "<p>Regards,<br/>Your Application Team</p>" +
                            "</body></html>";

            helper.setText(emailContent, true); // true indicates HTML content

            emailSender.send(message);
            System.out.println("Registration confirmation email sent to: " + to);
        } catch (MessagingException e) {
            System.err.println("Failed to send registration email: " + e.getMessage());
        }
    }
    @Override
    public void sendPasswordChangeEmail(String to, String username) {
        try {
            MimeMessage message = emailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setTo(to);
            helper.setSubject("Password Change Notification");

            String emailContent =
                    "<html><body>" +
                            "<h2>Password Change Notification</h2>" +
                            "<p>Dear " + username + ",</p>" +
                            "<p>Your password has been successfully changed.</p>" +
                            "<p>If you did not initiate this password change, please contact our support team immediately.</p>" +
                            "<p>For security reasons, you may want to:</p>" +
                            "<ul>" +
                            "<li>Log in with your new password</li>" +
                            "<li>Review your recent account activity</li>" +
                            "<li>Update your password on any other devices you use</li>" +
                            "</ul>" +
                            "<p>Thank you for helping us keep your account secure.</p>" +
                            "<p>Regards,<br/>Your Application Team</p>" +
                            "</body></html>";

            helper.setText(emailContent, true);

            emailSender.send(message);
            System.out.println("Password change email sent to: " + to);
        } catch (MessagingException e) {
            System.err.println("Failed to send password change email: " + e.getMessage());
        }
    }

    @Override
    public void sendRoleAssignmentEmail(String to, String username, String role) {
        try {
            MimeMessage message = emailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setTo(to);
            helper.setSubject("Role Assignment Notification");

            String emailContent =
                    "<html><body>" +
                            "<h2>Role Assignment Notification</h2>" +
                            "<p>Dear " + username + ",</p>" +
                            "<p>We are pleased to inform you that you have been assigned the role of <strong>" + role + "</strong> in our system.</p>" +
                            "<p>This role grants you the following privileges:</p>";

            // Add role-specific details
            switch (role) {
                case "ADMIN":
                    emailContent += "<ul>" +
                            "<li>Manage user accounts</li>" +
                            "<li>Access system settings</li>" +
                            "<li>Generate reports</li>" +
                            "<li>All USER privileges</li>" +
                            "</ul>";
                    break;
                case "SUPER_ADMIN":
                    emailContent += "<ul>" +
                            "<li>Full system administration rights</li>" +
                            "<li>Manage all user roles</li>" +
                            "<li>Configure system parameters</li>" +
                            "<li>All ADMIN privileges</li>" +
                            "</ul>";
                    break;
                case "HEAD_TEACHER":
                    emailContent += "<ul>" +
                            "<li>Manage curriculum content</li>" +
                            "<li>Review and approve educational materials</li>" +
                            "<li>Access teacher and student performance reports</li>" +
                            "</ul>";
                    break;
                default: // USER
                    emailContent += "<ul>" +
                            "<li>Access basic system features</li>" +
                            "<li>Update your profile information</li>" +
                            "<li>View available resources</li>" +
                            "</ul>";
            }

            emailContent += "<p>If you have any questions about your new role, please contact the system administrator.</p>" +
                    "<p>Thank you!</p>" +
                    "<p>Regards,<br/>Your Application Team</p>" +
                    "</body></html>";

            helper.setText(emailContent, true);

            emailSender.send(message);
            System.out.println("Role assignment email sent to: " + to);
        } catch (MessagingException e) {
            System.err.println("Failed to send role assignment email: " + e.getMessage());
        }
    }
    @Override
    public void sendOtpEmail(String to, String username, String otpCode) {
        try {
            MimeMessage message = emailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setTo(to);
            helper.setSubject("Your One-Time Password (OTP)");

            String emailContent =
                    "<html><body>" +
                            "<h2>Two-Factor Authentication</h2>" +
                            "<p>Dear " + username + ",</p>" +
                            "<p>Your one-time password (OTP) for login is:</p>" +
                            "<div style='background-color: #f2f2f2; padding: 15px; font-size: 24px; " +
                            "font-weight: bold; text-align: center; letter-spacing: 5px; margin: 20px 0;'>" +
                            otpCode +
                            "</div>" +
                            "<p>This code is valid for 5 minutes. Please do not share this code with anyone.</p>" +
                            "<p>If you did not request this code, please ignore this email and consider changing your password.</p>" +
                            "<p>Regards,<br/>Your Application Team</p>" +
                            "</body></html>";

            helper.setText(emailContent, true);

            emailSender.send(message);
            System.out.println("OTP email sent to: " + to);
        } catch (MessagingException e) {
            System.err.println("Failed to send OTP email: " + e.getMessage());
        }
    }
}

