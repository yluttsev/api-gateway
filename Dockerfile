FROM eclipse-temurin:17-jdk
COPY build/libs/api-gateway.jar .
ENTRYPOINT ["java", "-jar", "api-gateway.jar"]