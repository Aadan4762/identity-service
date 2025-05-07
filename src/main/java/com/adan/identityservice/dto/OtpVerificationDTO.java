package com.adan.identityservice.dto;

public class OtpVerificationDTO {
    private String username;
    private String otpCode;

    public OtpVerificationDTO() {
    }

    public OtpVerificationDTO(String username, String otpCode) {
        this.username = username;
        this.otpCode = otpCode;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getOtpCode() {
        return otpCode;
    }

    public void setOtpCode(String otpCode) {
        this.otpCode = otpCode;
    }
}