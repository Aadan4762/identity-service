package com.adan.identityservice.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import jakarta.validation.constraints.Pattern;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(uniqueConstraints = {
        @UniqueConstraint(columnNames = "username", name = "uk_username"),
        @UniqueConstraint(columnNames = "email", name = "uk_email")
})
public class UserCredential {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String firstName;
    private String lastName;

    @Column(unique = true)
    private String username;

    @Pattern(regexp = "^[a-zA-Z0-9._%+-]+@gmail\\.com$", message = "Email must be a valid Gmail address")
    @Column(unique = true)
    private String email;

    private String password;

    @Transient // This makes sure the field is not persisted to the database
    private String confirmPassword;

    @Enumerated(EnumType.STRING)
    private Role role = Role.USER;
}