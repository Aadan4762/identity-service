package com.adan.identityservice.config;


import com.adan.identityservice.entity.Role;
import com.adan.identityservice.entity.UserCredential;
import com.adan.identityservice.repository.UserCredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SuperAdminConfig {

    @Autowired
    private UserCredentialRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner initSuperAdmin() {
        return args -> {
            // Check if super admin already exists
            if (!userRepository.existsByUsername("superadmin")) {
                // Create super admin if it doesn't exist
                UserCredential superAdmin = new UserCredential();
                superAdmin.setFirstName("Super");
                superAdmin.setLastName("Admin");
                superAdmin.setUsername("superadmin");
                superAdmin.setEmail("superadmin@gmail.com");
                superAdmin.setPassword(passwordEncoder.encode("Admin@123")); // Strong default password
                superAdmin.setRole(Role.SUPER_ADMIN); // Assuming ADMIN is the highest role

                userRepository.save(superAdmin);
                System.out.println("Super Admin account created successfully!");
            } else {
                System.out.println("Super Admin account already exists.");
            }
        };
    }
}