package com.crescent.auth.controller;


import com.crescent.auth.dto.JwtResponse;
import com.crescent.auth.dto.LoginRequest;
import com.crescent.auth.dto.MessageResponse;
import com.crescent.auth.dto.SignupRequest;
import com.crescent.auth.model.Role;
import com.crescent.auth.model.Roles;
import com.crescent.auth.model.User;
import com.crescent.auth.repository.RoleRepository;
import com.crescent.auth.repository.UserRepository;
import com.crescent.auth.security.JwtUtils;
import com.crescent.auth.security.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(), roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        // Create new user's account
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setPassword(encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(Roles.ROLE_PATIENT)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(Roles.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "doctor":
                        Role docRole = roleRepository.findByName(Roles.ROLE_DOCTOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(docRole);
                        break;
                    case "employee":
                        Role empRole = roleRepository.findByName(Roles.ROLE_EMPLOYEE)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(empRole);
                        break;
                    case "nurse":
                        Role nurseRole = roleRepository.findByName(Roles.ROLE_NURSE)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(nurseRole);
                        break;
                    case "pharmacist":
                        Role pharmRole = roleRepository.findByName(Roles.ROLE_PHARMACIST)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(pharmRole);
                        break;
                    default:
                        Role patientRole = roleRepository.findByName(Roles.ROLE_PATIENT)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(patientRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
