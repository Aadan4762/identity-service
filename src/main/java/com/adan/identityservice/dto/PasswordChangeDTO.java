package com.adan.identityservice.dto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PasswordChangeDTO {
    private String username;
    private String currentPassword;
    private String newPassword;
    private String confirmNewPassword;
}
