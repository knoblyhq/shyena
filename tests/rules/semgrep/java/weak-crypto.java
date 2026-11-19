package com.example.demo;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class Crypto {

    @Bean
    PasswordEncoder encoder() {
        // ruleid: shyena.java.weak-password-encoder
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    PasswordEncoder good() {
        // ok: shyena.java.weak-password-encoder
        return new BCryptPasswordEncoder();
    }

    Object user() {
        // ruleid: shyena.java.weak-password-encoder
        return User.withUsername("admin").password("{noop}admin123").roles("ADMIN").build();
    }

    void hashes() throws Exception {
        // ruleid: shyena.java.weak-crypto
        MessageDigest.getInstance("MD5");
        // ruleid: shyena.java.weak-crypto
        MessageDigest.getInstance("SHA-1");
        // ok: shyena.java.weak-crypto
        MessageDigest.getInstance("SHA-256");
    }

    void ciphers() throws Exception {
        // ruleid: shyena.java.weak-crypto
        Cipher.getInstance("AES");
        // ruleid: shyena.java.weak-crypto
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ruleid: shyena.java.weak-crypto
        Cipher.getInstance("DESede/CBC/PKCS5Padding");
        // ok: shyena.java.weak-crypto
        Cipher.getInstance("AES/GCM/NoPadding");
        // ok: shyena.java.weak-crypto
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }
}
