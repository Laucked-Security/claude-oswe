package com.ex.service;

public class UserService {
    public void run(String cmd) {
        exec(cmd);
    }

    public void exec(String c) throws java.io.IOException {
        Runtime.getRuntime().exec(c); /* VULN */
    }

    public void run(String cmd, int retries) {
        Runnable r = () -> exec(cmd);
        r.run();
    }
}
