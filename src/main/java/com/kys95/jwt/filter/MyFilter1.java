package com.kys95.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.LogRecord;

public class MyFilter1 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;

        /**
         *  token : kys95를 만들어줘야 함. id,pw 정상적으로 들어와서 로그인 완료되면 token을 만들어주고 그것을 응답해줌.
         *  요청할 때 마다 header에 Authorization에 value값으로 token을 가지고 옴.
         *  그때 token이 넘어오면 이 token이 내가 만든 token이 맞는지만 검증만 하면 됨.(RSA, HS256)
         */

        if(req.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터1");

            if(headerAuth.equals("kys95")){
                chain.doFilter(req, res);
            }else{
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }



    }
}
