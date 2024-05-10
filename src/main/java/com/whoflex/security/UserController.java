package com.whoflex.security;

import com.whoflex.security.Account;
import com.whoflex.security.AccountRepository;
import com.whoflex.security.CurrentUser;
import com.whoflex.security.SignUpDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/users")
@RequiredArgsConstructor
@RestController
public class UserController {
    private final AccountRepository accountRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    @GetMapping
    public ResponseEntity<Object> getUsers(@CurrentUser String name) {
        System.out.println(name);
        return ResponseEntity.ok(accountRepository.findAll());
    }

    @PostMapping
    public ResponseEntity<Object> createUser(@RequestBody SignUpDto signUpDto) {
        return ResponseEntity.ok(accountRepository.save(new Account(signUpDto.getName(), passwordEncoder.encode(signUpDto.getPassword()), signUpDto.getRoleType(), null)));
    }
}
