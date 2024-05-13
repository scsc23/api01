package org.zerock.api01.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zerock.api01.security.APIUserDetailsService;
import org.zerock.api01.security.filter.APILoginFilter;
import org.zerock.api01.security.filter.RefreshTokenFilter;
import org.zerock.api01.security.filter.TokenCheckFilter;
import org.zerock.api01.security.handler.APILoginSuccessHandler;
import org.zerock.api01.util.JWTUtil;


@Configuration
@Log4j2
@RequiredArgsConstructor
@EnableMethodSecurity
public class CustomSecurityConfig {

    // 주입 - 실제 인증 처리를 위한 AuthenticationManager 객체 설정이 필요
    private final APIUserDetailsService apiUserDetailsService;

    private final JWTUtil jwtUtil;
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        log.info("--------------------------web configurer-----------------------------");

        // 정적 리소스 필터링 제외
        return (web) -> web.ignoring()
                .requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()
                );
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        log.info("-------------------configure------------------------");

        // AuthenticationManager 설정
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder
                .userDetailsService(apiUserDetailsService)
                        .passwordEncoder(passwordEncoder());

        // Get AuthenticationManager
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();
        // 인증 메니저 등록...
        http.authenticationManager(authenticationManager);
        // APILoginFilter 설정....
        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        apiLoginFilter.setAuthenticationManager(authenticationManager);
        // APILoginFilter 위치 조정 - UsernamePasswordAuthenticationFilter 이전에 동작해야함
        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);
        // APILoginSuccessHandler
        APILoginSuccessHandler successHandler = new APILoginSuccessHandler(jwtUtil);
        // SuccessHandler 설정
        apiLoginFilter.setAuthenticationSuccessHandler(successHandler);
        // API 로 동작하는 모든 경로에 TokenCheckFilter 동작
        http.addFilterBefore(tokenCheckFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
        // RefreshToken 호출 처리(TokenCheckFilter 다음 배치하는게 중요) "/refreshToken"
        http.addFilterBefore(new RefreshTokenFilter("/refreshToken", jwtUtil), TokenCheckFilter.class);
        // CSRF 토큰 비활성화
        http.csrf(AbstractHttpConfigurer::disable);
        // 세션 사용 비활성화
        http.sessionManagement(httpSecuritySessionManagementConfigurer ->
                httpSecuritySessionManagementConfigurer.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS
                ));

//        // remember-me 설정
//        http.rememberMe(httpSecurityRememberMeConfigurer -> {
//           httpSecurityRememberMeConfigurer.key("12345678")
//                   .tokenRepository(persistentTokenRepository())
//                   .userDetailsService(userDetailsService)  // PasswordEncoder에 의한 순환 구조가 발생할 수 있음...
//                   .tokenValiditySeconds(60*60*24*30);
//        });
//
//        // exceptionHandler 설정
//        http.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
//            httpSecurityExceptionHandlingConfigurer.accessDeniedHandler(accessDeniedHandler());
//        });
//
//        http.oauth2Login(httpSecurityOauth2LoginConfigurer -> {
//            httpSecurityOauth2LoginConfigurer.loginPage("/member/login");
//            httpSecurityOauth2LoginConfigurer.successHandler(authenticationSuccessHandler());
//        });

        return http.build();
    }

    // Token Check Filter 생성
    private TokenCheckFilter tokenCheckFilter (JWTUtil jwtUtil) {
        return new TokenCheckFilter(jwtUtil);
    }
//    @Bean
//    public AuthenticationSuccessHandler authenticationSuccessHandler() {
//        return new CustomerSocialLoginSuccessHandler(passwordEncoder);
//    }
//
//    // AccessDeniedHandler 빈등록...
//    @Bean
//    public AccessDeniedHandler accessDeniedHandler() {
//        return new Custom403Handler();
//    }
//
//

//
//    //PersistentTokenRepository
//    @Bean
//    public PersistentTokenRepository persistentTokenRepository() {
//        JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
//        repo.setDataSource(dataSource);
//        return repo;
//    }

}
