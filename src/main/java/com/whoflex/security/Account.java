package com.whoflex.security;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
public class Account {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String name;
    private String password;
    @Enumerated
    private RoleType roleType;
    public Account(String name, String password, RoleType roleType) {
        this.name = name;
        this.password = password;
        this.roleType = roleType;
    }
}
