package com.crescent.auth.dto;

import lombok.Data;

import java.util.Set;

@Data
public class SignupRequest {
    private String username;
    private String password;
    private Set<String> role;
    private String department;
    // getters and setters
}