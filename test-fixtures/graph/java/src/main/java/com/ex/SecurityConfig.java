package com.ex;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/health", "/public/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/di/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .formLogin(login -> login.loginPage("/login").permitAll());
        return http.build();
    }
}
