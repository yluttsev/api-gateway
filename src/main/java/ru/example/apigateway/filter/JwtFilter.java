package ru.example.apigateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.example.apigateway.payload.MessageResponse;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter implements GatewayFilter {

    private final ObjectMapper objectMapper;

    @Value("${security.access.secret}")
    private String accessSecret;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authHeader = Objects.requireNonNull(exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION))
                .stream()
                .findFirst()
                .orElse(null);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                JWT.require(Algorithm.HMAC256(accessSecret)).build().verify(token);
                return chain.filter(exchange);
            } catch (TokenExpiredException e) {
                return buildResponse(HttpStatus.UNAUTHORIZED, "Access токен просрочен", exchange);
            } catch (Exception e) {
                return buildResponse(HttpStatus.UNAUTHORIZED, "Неверный access токен", exchange);
            }
        } else {
            return buildResponse(HttpStatus.UNAUTHORIZED, "Неверный формат access токена", exchange);
        }
    }

    @SneakyThrows
    private Mono<Void> buildResponse(HttpStatus status, String message, ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.toString());
        DataBuffer buffer = exchange.getResponse()
                .bufferFactory()
                .wrap(objectMapper.writeValueAsString(new MessageResponse(message)).getBytes(StandardCharsets.UTF_8));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
