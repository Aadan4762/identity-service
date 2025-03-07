package com.adan.identityservice.repository;

import com.adan.identityservice.entity.UserCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserCredentialRepository extends JpaRepository<UserCredential, Integer> {

    Optional<UserCredential> findByUsername(String username);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
