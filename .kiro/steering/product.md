# Product Overview

## Purpose
Keycloak Post Login Flow integration with Google People API - a proof of concept (PoC) for identity synchronization.

## Core Functionality
- Custom Keycloak SPI (Service Provider Interface) authenticator
- Post-login flow execution after Google IDP authentication
- Access token extraction from federated identity
- Google People API integration for user profile retrieval
- Minimal viable implementation for token flow validation

## Key Components
- **Custom Authenticator SPI**: Implements post-login processing
- **Google IDP Integration**: Leverages stored access tokens
- **People API Client**: Makes HTTP calls to Google's People API
- **Token Management**: Extracts and utilizes federated identity tokens

## Success Criteria
- Post login flow executes successfully
- Access token extraction from `FederatedIdentityModel`
- HTTP requests attempted to Google People API
- Complete login flow maintains success state regardless of API call results