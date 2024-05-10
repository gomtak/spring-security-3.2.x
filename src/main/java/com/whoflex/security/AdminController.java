package com.whoflex.security;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    @GetMapping
    public String getAdmin() {
        return "Hello Admin!";
    }
}
