package com.crescent.auth.repository;


import com.crescent.auth.model.Role;
import com.crescent.auth.model.Roles;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(Roles name);
}