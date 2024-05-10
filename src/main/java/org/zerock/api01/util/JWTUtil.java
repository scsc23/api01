package org.zerock.api01.util;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
@Log4j2
public class JWTUtil {

    @Value("${org.zerock.jwt.secret}")   // application-property 설정된 값을 불러오는 @
    private String key;

    private final SecretKey secretKey = Keys.hmacShaKeyFor(key.getBytes());

    public String generateToken(Map<String, Object> valueMap, int days) {
        log.info("generateKey....." + key);


        // header 부분
        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");
        headers.put("alg", "HS256");    // HS256 = 길이값

        // payload 부분
        Map<String, Object> payload = new HashMap<>();
        payload.putAll(valueMap);

        // token 생성 시간 설정
        int time = (60 * 24) * days;

//        return Jwts.builder()
//                .signWith(secretKey)
//                .issuedAt(Date.from(ZonedDateTime.now().toInstant()))
//                .expiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant()))
//                .compact();

//        return Jwts.builder()
//                .setHeader(headers)
//                .setClaims(payload)
//                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
//                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant()))
//                .signWith(SignatureAlgorithm.HS256, key.getBytes())
//                .compact();

        return Jwts.builder()
                .header()
                .add("typ", "JWT")
                .add("alg", "256")
                .and()
                .claims(valueMap)
                .signWith(secretKey)
                .issuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .expiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant()))
                .compact();
    }




    // token 검증 메서드
    public Map<String, Object> validateToken(String token) throws JwtException {
        Map<String, Object> claim = null;

//        claim = Jwts.parser()
//                .verifyWith(secretKey)
//                .build()
//                .parseSignedClaims(token)
//                .getPayload();

        claim = Jwts.parser()
                .setSigningKey(key.getBytes())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claim;
    }
}
