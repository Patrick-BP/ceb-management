package com.cebmanagment.userservice.config;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private final String jwtSecret;
    private final int jwtExpirationMs;


    public JwtUtils(UserDetailsService userDetailsService, @Value("${app.jwt-Secret}") String jwtSecret, @Value("${app.jwt-Expiration-ms}") int jwtExpirationMs) {
        this.jwtSecret = jwtSecret;
        this.jwtExpirationMs = jwtExpirationMs;
    }

    // Generate JWT Token
    public String generateJwtToken(String email, String role) {
        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        return Jwts.builder()
                .setSubject(email)
                .claim("role", "ROLE_" + role) // Add role with the ROLE_ prefix
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key)
                .compact();
    }

    // Get username from the token
    public String getEmailFromJwtToken(String token) {
        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes()); // Generate the key using the secret
        return Jwts.parserBuilder() // Use parserBuilder()
                .setSigningKey(key) // Use the Key object
                .build() // Build the JwtParser instance
                .parseClaimsJws(token) // Parse the JWT
                .getBody() // Get the claims body
                .getSubject(); // Extract the subject (email in this case)
    }

    // Validate the token
    public boolean validateJwtToken(String token) {
        try {
            Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes()); // Generate the Key object
            Jwts.parserBuilder() // Use the parserBuilder()
                    .setSigningKey(key) // Set the Key object
                    .build() // Build the JwtParser
                    .parseClaimsJws(token); // Validate and parse the JWT
            return true; // If parsing succeeds, the token is valid
        } catch (JwtException | IllegalArgumentException e) {
            return false; // If any exception occurs, the token is invalid
        }
    }

    // New method to get the signing key
    public Key getSecretKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }


}
