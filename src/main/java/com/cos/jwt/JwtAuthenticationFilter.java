package com.cos.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

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
        try {

            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("user = " + user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된다.
            // DB에 존재하는 username과 password 일치
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨: " + principalDetails.getUser().getUsername());

            // authentication 객체가 session 영역에 저장된다. => 로그인이 되었다는 뜻
            // authentication 객체를 session 영역에 저장해야 하는데 그 방법은 return 하는 것이다.
            // return의 이유는 권한 관리를 security가 대신 해주기 때문이다.
            // 굳이 JWT 토큰을 사용하며 세션을 생성할 이유가 없다. 단지 권한 처리 때문에 session을 넣어준다.

            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // 2. 정상인지 로그인 시도
        // 가장 간단한 방법은 authenticationManager로 로그인 시도해 PrincipalDetailsService가 호출됨 -> loadUserByUsername()이 실행된다.

        // 3. PrincipalDetails를 세션에 담는다. -> 세션에 담지 않으면 권환 관리가 되지 않는다. (즉, 권한 관리를 위해)
        // 4. JWT 토큰을 만들어 응답한다.
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 수행되면 successfulAuthentication 함수가 실행된다.
    // JWT 토큰을 생성해  request 요청한 사용자에게 JWT 토큰을 response 해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨: 인증 완료!!");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // build.gradle 파일 - implementation group: 'com.auth0', name: 'java-jwt', version: '4.2.1'
        /*String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));*/

        // RSA 방식이 아닌 Hash 암호화 방식
        String jwtToken = JWT.create()
                .withSubject("cos 토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10))) // 토큰 만료시간은 10분
                .withClaim("id", principalDetails.getUser().getId()) // withClaim에는 넣고 싶은 key + value 값
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos")); // 개인키를 가지고 있어야 한다.

        response.addHeader("Authorization", "Bearer " + jwtToken);

        // 유저네임, 패스워드 로그인 정상

        // 서버쪽 세션ID 생성
        // 클라이언트 쿠키 세션ID 응답

        // 요청할 때마다 쿠키값 세션ID를 항상 들고 서버쪽으로 요청하기 때문에
        // 서버는 세션ID가 유효한지 판단해 유효하면 인증이 필요한 페이지로 접근하게 하면 된다.

        //=================================================================
        // 유저네임, 패스워드 로그인 정상
        // JWT 토큰 생성
        // 클라이언트로 JWT 토큰 응답
        // 요청할 때마다 JWT 토큰을 가지고 요청해야 한다.
        // 서버는 JWT 토큰이 유효한지 판단해야 한다. (필터 생성 필요)
    }
}
