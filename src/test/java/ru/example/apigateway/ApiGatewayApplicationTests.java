package ru.example.apigateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
		"security.access.secret=test"
})
class ApiGatewayApplicationTests {

	@Test
	void contextLoads() {
	}

}
