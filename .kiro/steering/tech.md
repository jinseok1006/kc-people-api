# Technology Stack

## Build System
- **Maven**: Standard Java build tool with `pom.xml` configuration
- **Java**: Core programming language
- **JUnit 3.8.1**: Testing framework (currently configured)

## Key Dependencies & Frameworks
- **Keycloak SPI**: Custom authenticator implementation for post-login flows
- **Google People API**: External API integration for user profile retrieval
- **HTTP Client**: Required for Google API calls (to be added)
- **JSON Processing**: For handling API responses (to be added)

## Required Keycloak Dependencies
When implementing the SPI, add these Maven dependencies:
```xml
<dependency>
    <groupId>org.keycloak</groupId>
    <artifactId>keycloak-core</artifactId>
</dependency>
<dependency>
    <groupId>org.keycloak</groupId>
    <artifactId>keycloak-server-spi</artifactId>
</dependency>
<dependency>
    <groupId>org.keycloak</groupId>
    <artifactId>keycloak-services</artifactId>
</dependency>
```

## Common Commands
- **Build**: `mvn clean compile`
- **Test**: `mvn test`
- **Package**: `mvn clean package`
- **Install**: `mvn clean install`

## Deployment
- Package as JAR and deploy to Keycloak's `providers/` directory
- Restart Keycloak server to load the SPI
- Configure through Keycloak Admin Console