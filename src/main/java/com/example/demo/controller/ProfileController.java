package com.example.demo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.demo.util.JwtUtil;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ProfileController {

    @GetMapping("/profile")
    public ResponseEntity<?> profile(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        String username = JwtUtil.validateTokenAndGetUsername(token);
        if (username == null) {
            return ResponseEntity.status(401).body("Invalid token");
        }

        return ResponseEntity.ok(Map.of("username", username));
    }
}