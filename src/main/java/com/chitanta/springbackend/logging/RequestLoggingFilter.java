package com.chitanta.springbackend.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@Component
public class RequestLoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String requestId = generateRandomUUID();
        long startTime = System.currentTimeMillis();

        log.info("HTTP-REQUEST [{}] {} {}", requestId, request.getMethod(), request.getRequestURI());

        try {
            filterChain.doFilter(request, response);

            long duration = System.currentTimeMillis() - startTime;
            log.info("HTTP-RESPONSE [{}] {} {} completed with status {} in {}ms",
                    requestId, request.getMethod(), request.getRequestURI(),
                    response.getStatus(), duration);

        } catch (Exception exception) {
            log.error(
                    "HTTP-REQUEST [{}] {} {} failed: {}",
                    requestId, request.getMethod(), request.getRequestURI(), exception.getMessage()
            );
            throw exception;
        }
    }

    private static String generateRandomUUID() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}