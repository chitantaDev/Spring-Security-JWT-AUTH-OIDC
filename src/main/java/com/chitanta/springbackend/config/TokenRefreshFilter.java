package com.chitanta.springbackend.config;

import com.chitanta.springbackend.token.TokenRepository;
import com.chitanta.springbackend.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

import static com.chitanta.springbackend.helper.Constants.ACCESS_TOKEN;
import static com.chitanta.springbackend.helper.Constants.REFRESH_TOKEN;


@Component
@Slf4j
@RequiredArgsConstructor
public class TokenRefreshFilter extends OncePerRequestFilter {
    private final JWTService jwtService;
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            filterChain.doFilter(request, response);
            return;
        }

        //TODO: Repetetive code, mightaswell refactor into a method
        String accessToken = Arrays.stream(cookies)
                .filter(cookie -> ACCESS_TOKEN.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        String refreshToken = Arrays.stream(cookies)
                .filter(cookie -> REFRESH_TOKEN.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if (accessToken == null || refreshToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String userEmail = jwtService.extractUsername(accessToken);
        if (userEmail != null && jwtService.isTokenExpired(accessToken)) {
            try {
                var user = userRepository.findByEmail(userEmail)
                        .orElseThrow();
                if (jwtService.isTokenValid(refreshToken, user)) {
                    String newAccessToken = jwtService.generateToken(user);

                    tokenRepository.findByToken(accessToken)
                            .ifPresent(token -> {
                                token.setExpired(true);
                                token.setRevoked(true);
                                tokenRepository.save(token);
                            });

                    jwtService.saveUserToken(user, newAccessToken);

                    response.addHeader("Set-Cookie",
                            jwtService.createJwtCookie(newAccessToken).toString());
                }
            } catch (Exception e) {
                log.error("Failed to generate refresh token for user: {}, error: {}", userEmail, e.getMessage());
                filterChain.doFilter(request, response);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}