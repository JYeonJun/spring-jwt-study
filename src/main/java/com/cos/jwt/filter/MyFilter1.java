package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티 필터가 실행되기 전 먼저 실행되어야한다.
public class MyFilter1 implements Filter {


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // if) 토큰 == cos -> 인증
        // cos 토큰을 생성해줘야 함. -> id, pw가 정상적으로 들어와 로그인이 완료 된다면
        // 요청할 때마다 header Authorization에 value 값으로 토큰을 가져온다.
        // 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지 검증만 하면 된다. (RSA, HS256)
        if (httpRequest.getMethod().equals("POST")) {
            String headerAuth = httpRequest.getHeader("Authorization");
            System.out.println("headerAuth = " + headerAuth);

            if (headerAuth.equals("cos")) {
                chain.doFilter(httpRequest, httpResponse);
            } else {
                httpResponse.getWriter().println("인증안됨");
            }
        }

    }
}
