package com.example;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Trust-boundary (CWE-501) hygiene fixture: attacker-controlled request data written into the
// trusted session store. This is NOT an exploit chain — it is a Low/Info hygiene finding.
public class TrustBoundary {
    public void store(HttpServletRequest request, HttpServletResponse response) {
        // VULN (CWE-501 trust-boundary): attacker-controlled parameter written into trusted session state.
        String userid = request.getParameter("uid");
        request.getSession().setAttribute("userid", userid);
    }
}
