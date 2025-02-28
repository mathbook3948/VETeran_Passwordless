package com.pwl.config;
import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        
        config.setAllowedOrigins(Arrays.asList("http://localhost:3002"));  // ✅ 허용할 도메인 지정
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));  // ✅ 허용할 HTTP 메서드
        config.setAllowCredentials(true);  // ✅ 세션 및 쿠키 허용
        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));  // ✅ 허용할 헤더
        config.setMaxAge(3600L);  // ✅ preflight 요청을 1시간 동안 캐싱

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}