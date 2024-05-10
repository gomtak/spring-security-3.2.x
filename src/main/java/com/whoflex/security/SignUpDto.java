package com.whoflex.security;

import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.management.relation.Role;

@Getter
@NoArgsConstructor
public class SignUpDto {
    private String name;
    private String password;
    private RoleType roleType;
}
