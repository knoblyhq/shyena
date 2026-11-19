package com.example.demo;

import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;

public class JwtService {

    // ruleid: shyena.java.hardcoded-jwt-secret
    @Value("${jwt.secret:my-super-secret-signing-key-0123456789}")
    private String secret;

    // ok: shyena.java.hardcoded-jwt-secret
    @Value("${jwt.secret}")
    private String goodSecret;

    // ok: shyena.java.hardcoded-jwt-secret
    @Value("${jwt.expiry-minutes:30}")
    private int expiry;

    SecretKey key() {
        // ruleid: shyena.java.hardcoded-jwt-secret
        return Keys.hmacShaKeyFor("my-super-secret-signing-key-0123456789".getBytes(StandardCharsets.UTF_8));
    }

    SecretKey fromConfig() {
        // ok: shyena.java.hardcoded-jwt-secret
        return Keys.hmacShaKeyFor(goodSecret.getBytes(StandardCharsets.UTF_8));
    }

    Algorithm algo() {
        // ruleid: shyena.java.hardcoded-jwt-secret
        return Algorithm.HMAC256("changeme");
    }
}
