package com.ex;

import com.ex.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class Api {
    @Autowired
    private UserService userService;

    @PostMapping("/run")
    @PreAuthorize("hasRole('ADMIN')")
    public String run(@RequestParam String cmd) {
        userService.run(cmd);
        return "ok";
    }

    @GetMapping("/health")
    public String health() {
        return "ok";
    }
}
