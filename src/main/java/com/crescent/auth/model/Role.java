package com.crescent.auth.model;

import jakarta.persistence.*;

//import javax.persistence.*;
import java.util.Objects;

@Entity
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(unique = true)
    private Roles name;

    // Getters, Setters, equals, hashCode
    public Roles getName() { return name; }
    public void setName(Roles name) { this.name = name; }
}