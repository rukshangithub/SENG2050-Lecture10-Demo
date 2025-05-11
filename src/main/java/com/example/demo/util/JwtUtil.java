package com.example.demo.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;



import java.util.Map;

public class JwtUtil {

    // NOTE: Demo purposes only
    // Typically these parameters should be stored application.yaml file or environment variables
    // Secret-key should be stored securely 
    private static final String SECRET_KEY = "my-secret-key";
    private static final long ACCESS_EXPIRATION_MS = 5 * 60 * 1000; // 5 min
    private static final long REFRESH_EXPIRATION_MS = 60 * 60 * 1000; // 1 hour


    // NOTE: Demo purposes only
    // If refresh tokens are stored in server side, they need to be stored securely
    // (e.g. in a database). This allows the server to manage and revoke tokens as needed. 
    private static final Map<String, String> refreshTokens = new ConcurrentHashMap<>();

    public static String generateAccessToken(String username) {
          
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + ACCESS_EXPIRATION_MS))
            .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
            .compact();
    }

    public static String generateRefreshToken(String username) {

        String refreshToken = Jwts.builder()
            .setSubject(username)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + REFRESH_EXPIRATION_MS))
            .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
            .compact();
        refreshTokens.put(refreshToken, username);
        return refreshToken;
    }

    public static String validateAccessToken(String token) {
        try {
            // Throws exception if not valid
            Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
            
            // Check whether token is expired
            if (claims.getExpiration().after(new Date()))
                return claims.getSubject();
            else    
                return null;
        } catch (Exception e) {
            return null;
        }
    }

    public static String validateRefreshToken(String token) {
        try {
            // Throws exception if not valid
            if (!refreshTokens.containsKey(token)) return null;
            
            Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();

            // Check whether token is expired
            if (claims.getExpiration().after(new Date()))
                return claims.getSubject();
            else    
                return null;
        } catch (Exception e) {
            return null;
        }
    }

    public static void invalidateRefreshToken(String token) {
        refreshTokens.remove(token);
    }

    public static String validateTokenAndGetUsername(String token) {

        try {
            // Throws exception if not valid
            Claims claims = Jwts.parser()
                                .setSigningKey(SECRET_KEY)
                                .parseClaimsJws(token)
                                .getBody();

            // Check whether token is expired
            if (claims.getExpiration().after(new Date()))
                return claims.getSubject();
            else    
                return null;
            
        } catch (JwtException | IllegalArgumentException e) {
            return null;
        }
    }
}