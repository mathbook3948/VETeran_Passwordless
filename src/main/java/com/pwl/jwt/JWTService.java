package com.pwl.jwt;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.pwl.domain.Login.UserInfo;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JWTService {

    private final SecretKey key;

    @Value("${jwt.userTokenExpiration}")
    private Long userTokenExpiration;

    public JWTService(@Value("${jwt.secret}") String secret) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    // 토큰 생성
    public String createToken(UserInfo userInfo) {
        Long managerNum = userInfo.getManagerNum(); 

        String token = Jwts.builder()
                .claim("managerNum", managerNum)
                .setIssuedAt(new Date()) 
                .setExpiration(new Date(System.currentTimeMillis() + userTokenExpiration)) // 만료 시간
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
        return token;
    }
}
