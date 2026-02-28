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
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

//@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    RestTemplate restTemplate; // 2. Inject the Bean created in WebSecurityConfig

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
        // Variable to store the detected role string for the Doctor Service check
        AtomicReference<String> detectedRole = new AtomicReference<>("PATIENT");
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(Roles.ROLE_PATIENT)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "ROLE_ADMIN":
                        Role adminRole = roleRepository.findByName(Roles.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        detectedRole.set("ADMIN");
                        break;
                    case "ROLE_DOCTOR":
                        Role docRole = roleRepository.findByName(Roles.ROLE_DOCTOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(docRole);
                        detectedRole.set("DOCTOR");
                        break;
                    case "ROLE_EMPLOYEE":
                        Role empRole = roleRepository.findByName(Roles.ROLE_EMPLOYEE)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(empRole);
                        break;
                    case "ROLE_NURSE":
                        Role nurseRole = roleRepository.findByName(Roles.ROLE_NURSE)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(nurseRole);
                        break;
                    case "ROLE_PHARMACIST":
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
        // --- NEW: INTEGRATION WITH DOCTOR SERVICE ---
        if ("DOCTOR".equals(detectedRole.get())) {
            try {
                // Prepare payload for Doctor Service
                // We send Username and Department (which maps to Specialty in Doctor Service)
                Map<String, String> doctorData = new HashMap<>();
                doctorData.put("username", user.getUsername());
                doctorData.put("specialty", signUpRequest.getDepartment());

                // Call Doctor Service directly (Port 8082)
                String doctorServiceUrl = "http://localhost:8082/api/doctor/internal/register";
                        //"http://localhost:8091/api/doctor/internal/register";

                // Make the request. We don't care about the response body, just that it doesn't crash.
               restTemplate.postForObject(doctorServiceUrl, doctorData, ResponseEntity.class);
                System.out.println("----------------------------");
            } catch (Exception e) {
                // Log error but don't fail the whole request if User was created
                System.err.println("Error creating Doctor Profile: " + e.getMessage());
                // Optionally:
                return ResponseEntity.status(500).body("User created, but Doctor profile failed.");
            }
        }
        // ---------------------------------------------
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
    // --- ADMIN MANAGEMENT ENDPOINTS ---

    // 1. Get All Users (For Admin Dashboard)
    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userRepository.findAll();
        // Clear password from response for security
        users.forEach(u -> u.setPassword(null));
        return ResponseEntity.ok(users);
    }

    // 2. Soft Delete / Toggle Active Status
    @PutMapping("/users/{id}/status")
    public ResponseEntity<?> toggleUserStatus(@PathVariable Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setActive(!user.isActive()); // Toggle true/false
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User status updated to " + (user.isActive() ? "Active" : "Inactive")));
    }

    // 3. Update User Role
    @PutMapping("/users/{id}/role")
    public ResponseEntity<?> updateUserRole(@PathVariable Long id, @RequestBody Map<String, String> roleRequest) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String newRoleStr = roleRequest.get("role");
        Set<Role> roles = new HashSet<>();

        switch (newRoleStr.toLowerCase()) {
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
            case "nurse":
                Role nurseRole = roleRepository.findByName(Roles.ROLE_NURSE)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(nurseRole);
                break;
            case "receptionist": // Assuming you might add this role later, or map to EMPLOYEE
                Role recpRole = roleRepository.findByName(Roles.ROLE_RECEPTIONIST)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(recpRole);
                break;
            case "pharmacist": // Assuming you might add this role later, or map to EMPLOYEE
                Role pharmRole = roleRepository.findByName(Roles.ROLE_PHARMACIST)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                break;
            case "employee": // Assuming you might add this role later, or map to EMPLOYEE
                Role empRole = roleRepository.findByName(Roles.ROLE_EMPLOYEE)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(empRole);
                break;
            default:
                Role userRole = roleRepository.findByName(Roles.ROLE_PATIENT)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(userRole);
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User role updated successfully!"));
    }
}
