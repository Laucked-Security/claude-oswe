// Intentionally vulnerable Spring controller for OSWE auditor validation. DO NOT DEPLOY.
package com.example;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VulnController {

    // VULN (step 1 - trusted request header for authz): the admin decision is read from a
    // client-controllable header, with no validation by a trusted proxy.
    private boolean isAdmin(HttpServletRequest request) {
        return "admin".equals(request.getHeader("X-User-Role"));
    }

    @GetMapping("/admin/eval")
    public String eval(@RequestParam("q") String q, HttpServletRequest request) {
        if (!isAdmin(request)) {
            return "Forbidden";
        }
        // VULN (step 2 - SpEL injection -> RCE): an attacker-controlled expression is parsed and
        // evaluated, e.g. q = T(java.lang.Runtime).getRuntime().exec("id")
        SpelExpressionParser parser = new SpelExpressionParser();
        Expression expression = parser.parseExpression(q);
        return String.valueOf(expression.getValue());
    }
}
