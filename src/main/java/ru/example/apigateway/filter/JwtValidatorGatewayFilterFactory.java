package ru.example.apigateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.example.apigateway.payload.MessageResponse;

import java.nio.charset.StandardCharsets;

@Component
public class JwtValidatorGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtValidatorGatewayFilterFactory.Config> {

    private final ObjectMapper objectMapper;

    @Value("${security.access.secret}")
    private String accessSecret;

    public JwtValidatorGatewayFilterFactory(ObjectMapper objectMapper) {
        super(Config.class);
        this.objectMapper = objectMapper;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders()
                    .getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                try {
                    String token = authHeader.substring(7);
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
        };
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

    public static class Config {
    }
}
