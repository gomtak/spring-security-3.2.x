package com.whoflex.security;

import com.whoflex.security.oauth2.ProviderType;
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
    private ProviderType providerType;
    @Enumerated
    private RoleType roleType;
    public Account(String name, String password, RoleType roleType, ProviderType providerType) {
        this.name = name;
        this.password = password;
        this.roleType = roleType;
        this.providerType = providerType == null ? ProviderType.LOCAL : providerType;
    }
}
