package com.whoflex.security;

import com.whoflex.security.jwt.*;
import com.whoflex.security.oauth2.CustomOAuth2UserService;
import com.whoflex.security.oauth2.OAuth2AuthenticationFailureHandler;
import com.whoflex.security.oauth2.OAuth2AuthenticationSuccessHandler;
import com.whoflex.security.oauth2.OAuth2AuthorizationRequestBasedOnCookieRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsUtils;

import java.util.Arrays;
import java.util.List;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {
    @Value("${authorizedRedirectUris}")
    private final List<String> authorizedRedirectUris;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final CustomUserDetailsService customUserDetailsService;
    private final ObjectPostProcessor<Object> objectPostProcessor;
    private final JwtProcessor jwtProcessor;
    private final PasswordEncoder passwordEncoder;
    private final CustomOAuth2UserService oAuth2UserService;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .cors(getCorsConfigurerCustomizer())
                .logout(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(
                        (session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(
                        authenticationEntryPoint -> {
                            authenticationEntryPoint.authenticationEntryPoint(jwtAuthenticationEntryPoint);
                            authenticationEntryPoint.accessDeniedHandler(jwtAccessDeniedHandler);
                        })
                .authorizeHttpRequests(
                        authorizeHttpRequests ->
                                authorizeHttpRequests
                                        .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                                        .requestMatchers(HttpMethod.POST, "/login").permitAll()
                                        .requestMatchers(HttpMethod.POST, "/users").permitAll()
                                        .requestMatchers("/admin").hasRole("ADMIN")
                                        .requestMatchers(
                                                "/",
                                                "/swagger-ui/**",
                                                "/v3/api-docs/**"
                                        ).permitAll()
                                        .anyRequest().authenticated())
                .addFilter(getAuthenticationFilter())
                .addFilterBefore(getAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                .oauth2Login((oauth2) -> {
                    oauth2
                            .authorizationEndpoint(
                                    authorizationEndpointConfig ->
                                            authorizationEndpointConfig
                                                    .baseUri("/oauth2/authorization")
                                                    .authorizationRequestRepository(
                                                            oAuth2AuthorizationRequestBasedOnCookieRepository()))
                            .redirectionEndpoint(
                                    redirectionEndpointConfig ->
                                            redirectionEndpointConfig.baseUri("/*/oauth2/code/*"))
                            .userInfoEndpoint(
                                    userInfoEndpointConfig ->
                                            userInfoEndpointConfig.userService(oAuth2UserService));
                    oauth2.successHandler(oAuth2AuthenticationSuccessHandler());
                    oauth2.failureHandler(oAuth2AuthenticationFailureHandler());
                });

        return httpSecurity.build();
    }

    private static Customizer<CorsConfigurer<HttpSecurity>> getCorsConfigurerCustomizer() {
        return (cors) -> {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedOrigins(List.of("*"));
            config.setAllowedHeaders(List.of("*"));
            config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "OPTIONS", "DELETE", "PATCH"));
            config.setAllowCredentials(true);
            cors.configurationSource(request -> config);
        };
    }

    public AuthenticationManager authenticationManager(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder);
        return authenticationManagerBuilder.build();
    }

    private JwtAuthenticationFilter getAuthenticationFilter() throws Exception {
        AuthenticationManagerBuilder builder = new AuthenticationManagerBuilder(objectPostProcessor);
        return new JwtAuthenticationFilter(authenticationManager(builder), jwtProcessor);
    }

    private JwtAuthorizationFilter getAuthorizationFilter() {
        return new JwtAuthorizationFilter(jwtProcessor);
    }
    public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
        return new OAuth2AuthorizationRequestBasedOnCookieRepository();
    }

    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler(authorizedRedirectUris, oAuth2AuthorizationRequestBasedOnCookieRepository());
    }

    public OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler() {
        return new OAuth2AuthenticationFailureHandler(oAuth2AuthorizationRequestBasedOnCookieRepository());
    }
}
