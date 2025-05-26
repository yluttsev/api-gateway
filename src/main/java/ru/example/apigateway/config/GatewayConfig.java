package ru.example.apigateway.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.ServerResponse;
import ru.example.apigateway.payload.MessageResponse;

import java.util.List;

@Configuration
public class GatewayConfig {

    @Value("${security.access.secret}")
    private String accessSecret;

    @Bean
    public List<String> permittedRoutes() {
        return List.of(
                "/auth/sign-in",
                "/auth/sign-up",
                "/auth/update-credentials"
        );
    }

    @Bean
    public HandlerFilterFunction<ServerResponse, ServerResponse> jwtFilter() {
        return (request, next) -> {
            String authHeader = request.headers().header(HttpHeaders.AUTHORIZATION)
                    .stream()
                    .findFirst()
                    .orElse(null);
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                try {
                    JWT.require(Algorithm.HMAC256(accessSecret)).build().verify(token);
                } catch (TokenExpiredException e) {
                    return ServerResponse
                            .status(HttpStatus.UNAUTHORIZED)
                            .body(new MessageResponse("Access токен просрочен"));
                } catch (Exception e) {
                    return ServerResponse
                            .status(HttpStatus.UNAUTHORIZED)
                            .body(new MessageResponse("Неверный access токен"));
                }
                return next.handle(request);
            } else {
                return ServerResponse
                        .status(HttpStatus.UNAUTHORIZED)
                        .body(new MessageResponse("Запрос требует аутентификации"));
            }
        };
    }
}
