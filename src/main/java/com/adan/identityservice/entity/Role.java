package com.adan.identityservice.entity;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public enum Role {
    USER("USER"),
    ADMIN("ADMIN"),
    SUPER_ADMIN("SUPER_ADMIN"),
    HEAD_TEACHER("HeadTeacher");

    private final String value;

    Role(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static Role fromValue(String value) {
        for (Role role : values()) {
            if (role.value.equals(value)) {
                return role;
            }
        }
        throw new IllegalArgumentException("Invalid role: " + value);
    }

    public static List<String> getAllowedRoles() {
        return Arrays.stream(values())
                .map(Role::getValue)
                .collect(Collectors.toList());
    }
}