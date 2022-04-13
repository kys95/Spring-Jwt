package com.kys95.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * spring security 에서 UsernamePasswordAuthenticationFilter가 있음.
 * /login 요청해서 username,password post로 전송하면
 * UsernamePasswordAuthenticationFilter 가 동작함함 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 login 시도를 위해서 실행되는 함수
   @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

       System.out.println("JwtAuthenticationFilter : 로그인 시도중");

       //1.username, password 받아서

       //2.정상인지 login 시도를 함. authenticationManager로 login 시도를 하면
       // PrincipalDetailsService가 호출 loadUserByUsername() 함수 실행됨.

       //3.PrincipalDetails를 session에 담음(권한 관리 위해서)

       //4.JWT token을 만들어서 응답해주면 됨됨
       return super.attemptAuthentication(request, response);
    }
}
