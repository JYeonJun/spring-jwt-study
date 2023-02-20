package com.cos.jwt.config;

import lombok.RequiredArgsConstructor;
import org.apache.catalina.filters.CorsFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfigurationSource corsConfigurationSource;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .sessionManagement() // 세션 관리 기능 작동
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 스프링 시큐리티가 생성하지 않고 존재해도 사용 X

        http
                .csrf().disable();

        // @CrossOrigin(인증X), 시큐리티 필터에 등록 인증(O)
        http
                .cors()
                .configurationSource(corsConfigurationSource); // cors 정책 설정

        http
                .authorizeHttpRequests((authz) -> authz
                        .antMatchers("/api/v1/user/**").hasAnyRole("USER", "MANAGER", "ADMIN")
                        .antMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
                        .antMatchers("/api/v1/admin/**").hasAnyRole("ADMIN")
                        .anyRequest().permitAll()
                )
                .formLogin().disable() // jwt 서버라 ID, PW를 formLogin 방식으로 인증하지 않는다.
                .httpBasic().disable();

        return http.build();
    }
}
