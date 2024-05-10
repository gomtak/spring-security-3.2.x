package com.whoflex.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import javax.crypto.SecretKey;
import java.security.Key;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtProcessorTest {
    private static final String AUTH = "auth";

    @Test
    void test() {
        CustomUserDetails customUserDetails = CustomUserDetails.builder()
                .name("test")
                .password("test")
                .roleType(RoleType.USER)
                .build();
        String authorities = customUserDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        long now = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);

        SecretKey key = Jwts.SIG.HS256.key().build(); //or HS384.key() or HS512.key()
        String keys = Encoders.BASE64.encode(key.getEncoded());
        SecretKey key2 = Keys.hmacShaKeyFor(Decoders.BASE64.decode(keys));
        String jws = Jwts.builder()
                .subject("access-token")
                .claim("name", customUserDetails.getName())
                .claim(AUTH, authorities)
                .expiration(Date.from(Instant.ofEpochSecond(now + 60 * 60 * 24)))
                .signWith(key)
                .compact();
        Object payload = Jwts.parser().verifyWith(key2).build().parse(jws).getPayload();
        Map temp = (Map) payload;
        assert temp.get("sub").equals("access-token");
    }

    @Test
    void decode() {
        String secretKey = "soPacaTU03yEaVHStTKobRtox3hL2NiDk19PVi9XR7I=";
//        String secretKey = "d2hvZmxleC1kaW5vLXByb2plY3Qtand0LXNlY3JldGtleS1iYXNlNjQK==";
        byte[] decodedBytes = Decoders.BASE64.decode(secretKey);
        String decodedString = new String(decodedBytes);
        System.out.println("Decoded String: " + decodedString);
    }

    @Test
    void encode() {
        String sample = "abcdefghijklmnopqrstuvwxyzabcdef";
        System.out.println("Original String: " + sample.length());
        // 예제 문자열을 seed로 사용하여 SecretKey를 생성
        byte[] seed = sample.getBytes();
        Key key = Keys.hmacShaKeyFor(seed); // HS256에 해당하는 SecretKey 생성

        // SecretKey를 Base64로 인코딩
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("Encoded String: " + encodedKey);

        // Base64로 인코딩된 문자열을 디코딩하여 다시 SecretKey로 변환
        byte[] decodedBytes = Base64.getDecoder().decode(encodedKey);
        Key decodedKey = Keys.hmacShaKeyFor(decodedBytes);

        // 다시 Base64로 인코딩된 문자열 출력 (디코딩 후 다시 인코딩한 결과)
        String reencodedKey = Base64.getEncoder().encodeToString(decodedKey.getEncoded());
        System.out.println("Reencoded String: " + reencodedKey);
    }

    @Test
    void createSecret() {
        String sentence = "gomtak make a awesome app for security";
        assert sentence.length() < 32;
        String encode = Encoders.BASE64.encode(sentence.getBytes());
        System.out.println(encode);
        String doubleIt = Encoders.BASE64.encode(encode.getBytes());
        System.out.println(doubleIt);
        String decode = new String(Decoders.BASE64.decode(doubleIt));
        System.out.println(decode);
        String decode2 = new String(Decoders.BASE64.decode(decode));
        System.out.println(decode2);
    }

    @Test
    void epo() throws Exception {
        // Given
        long l = System.currentTimeMillis();
        long now = LocalDateTime.now().toEpochSecond(ZoneOffset.ofHours(9));
        System.out.println(l);
        System.out.println(now);
        System.out.println(new Date(l));
        System.out.println(new Date(now * 1000));
        // When
        // Then
    }

    @Test
    void DateTest() throws Exception {
        // Given
        Date from = Date.from(Instant.now());
        Date to = Date.from(Instant.now().plusSeconds(1800));
        // When
        System.out.println(from);
        System.out.println(to);
        // Then
    }

    @Test
    void JwtProcessorTest() throws Exception {
        // Given
        CustomUserDetails customUserDetails = CustomUserDetails.builder()
                .name("test")
                .password("test")
                .roleType(RoleType.USER)
                .build();
        String authorities = customUserDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode("soPacaTU03yEaVHStTKobRtox3hL2NiDk19PVi9XR7I="));
        int accessTokenLifetimeInSeconds = 1800;
        int refreshTokenLifetimeInSeconds = 86400;
        // When
        var accessToken =
                Jwts.builder()
                        .subject(String.valueOf(customUserDetails.getName()))
                        .claim(AUTH, authorities)
                        .issuedAt(Date.from(Instant.now()))
                        .expiration(Date.from(Instant.now().plusSeconds(accessTokenLifetimeInSeconds)))
                        .signWith(key)
                        .compact();
        var refreshToken =
                Jwts.builder()
                        .subject(String.valueOf(customUserDetails.getName()))
                        .issuedAt(Date.from(Instant.now()))
                        .expiration(Date.from(Instant.now().plusSeconds(refreshTokenLifetimeInSeconds)))
                        .signWith(key)
                        .compact();
        // Then
        System.out.println(accessToken);
        System.out.println(refreshToken);
    }

    @Test
    void StringJoinTest() throws Exception {
        // Given
        String a = "a";
        String b = "b";
        String c = "c";
        // When
        String join = String.join(" ", a, b, c);
        // Then
        System.out.println(join);
    }

    @Test
    void parseTest() throws Exception {
        // Given
        CustomUserDetails customUserDetails = CustomUserDetails.builder()
                .name("test")
                .password("test")
                .roleType(RoleType.USER)
                .build();
        String authorities = customUserDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode("soPacaTU03yEaVHStTKobRtox3hL2NiDk19PVi9XR7I="));
        int accessTokenLifetimeInSeconds = 1800;
        int refreshTokenLifetimeInSeconds = 86400;
        // When
        var accessToken =
                Jwts.builder()
                        .subject(String.valueOf(customUserDetails.getName()))
                        .claim(AUTH, authorities)
                        .issuedAt(Date.from(Instant.now()))
                        .expiration(Date.from(Instant.now().plusSeconds(accessTokenLifetimeInSeconds)))
                        .signWith(key)
                        .compact();
        System.out.println(accessToken);
        var refreshToken =
                Jwts.builder()
                        .subject(String.valueOf(customUserDetails.getName()))
                        .issuedAt(Date.from(Instant.now()))
                        .expiration(Date.from(Instant.now().plusSeconds(refreshTokenLifetimeInSeconds)))
                        .signWith(key)
                        .compact();
        // When
        // Then
        assertThrows(ExpiredJwtException.class, () -> {
            String subject = Jwts.parser().verifyWith(key).build().parseSignedClaims(accessToken).getPayload().getSubject();
        });
    }

    @Test
    void InvalidToken() throws Exception {
        // Given
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode("soPacaTU03yEaVHStTKobRtox3hL2NiDk19PVi9XR7I="));
        String accessToken = "eyJzdWIiOiJ0ZXN0IiwiYXV0aCI6IlJPTEVfVVNFUiIsImlhdCI6MTcxNTMxNTg1NiwiZXhwIjoxNzE1MzE3NjU2fQ.PKrGJzcwV4TTiSCBleMbdLy1rzDX-_ZyLiQZTPvqtEs";
        // When
        String subject = Jwts.parser().verifyWith(key).build().parseSignedClaims(accessToken).getPayload().getSubject();
        // Then
        System.out.println(subject);
    }
}