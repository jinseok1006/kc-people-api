# Project Structure

## Maven Standard Layout
```
src/
├── main/java/com/jigsso/idsync/     # Main source code
└── test/java/com/jigsso/idsync/     # Unit tests
```

## Package Organization
- **Base Package**: `com.jigsso.idsync`
- **Main Class**: `App.java` (placeholder, will be replaced with SPI implementation)
- **Test Package**: Mirror structure of main package

## Key Files
- **pom.xml**: Maven build configuration and dependencies
- **spec.md**: Korean language specification document
- **App.java**: Entry point (to be replaced with Keycloak SPI classes)
- **AppTest.java**: JUnit test cases

## Expected SPI Structure
When implementing the Keycloak SPI:
- Create authenticator classes in main package
- Implement `Authenticator` and `AuthenticatorFactory` interfaces
- Add META-INF/services configuration for SPI discovery
- Package as JAR for Keycloak deployment

## Deployment Structure
- Build artifact: `target/idsync-1.0-SNAPSHOT.jar`
- Deploy to: Keycloak `providers/` directory
- Configuration: Through Keycloak Admin Console