package com.whoflex.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final AccountRepository accountRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountRepository.findByName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return CustomUserDetails.builder()
                .name(account.getName())
                .password(account.getPassword())
                .roleType(account.getRoleType())
                .build();
    }
}
