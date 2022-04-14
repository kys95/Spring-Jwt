package com.kys95.jwt.config.jwt;

public interface JwtProperties {
    String SECRET = "kys95";    //우리 서버만 알고 있는 비밀값
    int EXPIRATION_TIME = 60000*100; // //token 만료시간(10분)
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
