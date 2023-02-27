package com.cos.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 존재
// login 요청시 username과 password를 전송하면 (post)
// UsernamePasswordAuthenticationFilter가 동작한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter 로그인 시도중");

        // 1. username, password를 받아
        // 2. 정상인지 로그인 시도
        // 가장 간단한 방법은 authenticationManager로 로그인 시도해 PrincipalDetailsService가 호출됨 -> loadUserByUsername()이 실행된다.

        // 3. PrincipalDetails를 세션에 담는다. -> 세션에 담지 않으면 권환 관리가 되지 않는다. (즉, 권한 관리를 위해)
        // 4. JWT 토큰을 만들어 응답한다.
        return super.attemptAuthentication(request, response);
    }
}
