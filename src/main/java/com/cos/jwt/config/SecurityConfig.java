package com.cos.jwt.config;

import com.cos.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter1;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfigurationSource corsConfigurationSource;

    private AuthenticationConfiguration authenticationConfiguration;


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return (ProviderManager)authenticationConfiguration.getAuthenticationManager();
    }

    // jwt Bearer - [http 헤더] Authorization: jwt 토큰 (유효시간 존재)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 직접 생성한 필터는 시큐리티 필터가 실행되기 전에 먼저 동작해야 한다.
        http.addFilter(new JwtAuthenticationFilter(authenticationManager(authenticationConfiguration))); // AuthenticationManager를 파라미터로 전달해줘야 한다.
        http.addFilterBefore(new MyFilter1(), SecurityContextPersistenceFilter.class);

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

        // formLogin 방식이 disable 비활성화 상태이므로 localhost:8080/login에서 동작하지 않는다.

        return http.build();
    }
}
