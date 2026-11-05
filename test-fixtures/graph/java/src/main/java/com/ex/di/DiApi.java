package com.ex.di;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/di")
public class DiApi {
    @Autowired
    private UserService userService;

    @PostMapping("/run")
    public String run(@RequestParam String cmd) throws java.io.IOException {
        userService.run(cmd);
        return "ok";
    }
}

interface UserService {
    void run(String cmd) throws java.io.IOException;
}

class UserServiceImpl implements UserService {
    public void run(String cmd) throws java.io.IOException {
        Runtime.getRuntime().exec(cmd); /* VULN */
    }
}
