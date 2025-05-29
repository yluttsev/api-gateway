package ru.example.apigateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

@Component
public class JwtValidatorGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtValidatorGatewayFilterFactory.Config> {

    private final JwtFilter jwtFilter;

    public JwtValidatorGatewayFilterFactory(JwtFilter jwtFilter) {
        super(Config.class);
        this.jwtFilter = jwtFilter;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return jwtFilter;
    }

    public static class Config {
    }
}
