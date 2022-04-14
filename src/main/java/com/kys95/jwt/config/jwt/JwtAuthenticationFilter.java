package com.kys95.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kys95.jwt.config.auth.PrincipalDetails;
import com.kys95.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;



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



       //1.username, password 받아서
       try {
           ObjectMapper om = new ObjectMapper(); //json data 파싱
           User user = om.readValue(request.getInputStream(),User.class);

           UsernamePasswordAuthenticationToken  authenticationToken =
                   new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());

           //PrincipalDetailsService의 loadUserByUsername()함수가 실행된 후 정상이면 authentication이 return됨
           //db에 있는 username,password가 일치함
           Authentication authentication = authenticationManager.authenticate(authenticationToken);
           PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

           //authentication 객체가 session영역에 저장을 해야하고 그 방법이 return 해주는 것.
           //return 의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것임.
           //굳이 Jwt token을 사용하면서 session을 만들 이유가 없지만 단지 권한 처리때문에 session을 넣어줌.
           return authentication;

       }catch (IOException e){
           e.printStackTrace();
       }
       return null;

   }

    //attemptAuthentication 실행 후 인증이 정상적으로 되었다면 successfulAuthentication 가 실행됨
    //Jwt token을 만들어서 request 요청한 사용자에게 Jwt token을 response해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //hash암호화방식
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+60000*10))   //token 만료시간(10분)
                .withClaim("id",principalDetails.getUser().getId())
                .withClaim("username",principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("kys95"));

        response.addHeader("Authorization","Bearer "+jwtToken);
    }
}
