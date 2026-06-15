// Hardened Spring controller (negative fixture). DO NOT DEPLOY.
package com.example;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SafeController {

    // Safe: authorization compares against a secret read from the ENVIRONMENT only — there is NO
    // hardcoded/default secret in the source (a white-box reader cannot recover it). If the env token
    // is unset, deny. The X-User-Role header is never trusted.
    private static final String ADMIN_TOKEN = System.getenv("ADMIN_TOKEN");

    private boolean isAdmin(HttpServletRequest request) {
        if (ADMIN_TOKEN == null || ADMIN_TOKEN.isEmpty()) {
            return false; // no server-side token configured -> deny
        }
        String token = request.getHeader("X-Auth-Token");
        return token != null && token.equals(ADMIN_TOKEN);
    }

    @GetMapping("/admin/eval")
    public String eval(@RequestParam("q") String q, HttpServletRequest request) {
        if (!isAdmin(request)) {
            return "Forbidden";
        }
        // Safe: the input is treated as literal DATA — it is never parsed/evaluated as SpEL.
        return "Echo: " + q;
    }
}
