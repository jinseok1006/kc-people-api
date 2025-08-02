package com.jigsso.idsync;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.FederatedIdentityModel;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Google People API Post Login Authenticator
 * 
 * Google IDP 로그인 후 저장된 access token으로 People API를 호출하는 SPI
 */
public class GooglePeopleApiAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(GooglePeopleApiAuthenticator.class);
    private static final String GOOGLE_PEOPLE_API_URL = "https://people.googleapis.com/v1/people/me?personFields=organizations,externalIds";
    private static final String GOOGLE_PROVIDER_ID = "google";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // 강제로 ERROR 레벨로 출력
        System.err.println(">>> [SPI] 진입 테스트 (System.err)");
        logger.error("=== Google People API 인증기 시작 ===");
        logger.info("Google People API 인증기 시작");

        UserModel user = context.getUser();

        if (user == null) {
            logger.error("=== 사용자가 null - 이것이 문제의 원인 ===");
            logger.warn("인증 컨텍스트에서 사용자가 null입니다 - 이는 Post Login Flow 실행 조건이 맞지 않음을 의미");

            // PoC 목적: 실패해도 성공으로 처리하되, 로그는 남김
            logger.info("PoC 목적으로 성공 처리하지만, 실제로는 사용자 생성 단계에서 문제 발생");
            context.success();
            return;
        }

        logger.info("사용자 처리 중: " + user.getUsername() + " (ID: " + user.getId() + ")");

        try {
            // Google IDP에서 저장된 access token 추출
            String accessToken = extractGoogleAccessToken(context, user);

            if (accessToken != null && !accessToken.trim().isEmpty()) {
                logger.info("사용자 " + user.getUsername() + "의 액세스 토큰 추출 성공");

                // Google People API 호출
                callGooglePeopleApi(accessToken, user.getUsername(), context, user);
            } else {
                logger.warn("사용자 " + user.getUsername() + "의 유효한 Google 액세스 토큰을 찾을 수 없습니다");
            }

        } catch (Exception e) {
            logger.error("사용자 " + user.getUsername() + "의 Google People API 인증 중 예상치 못한 오류 발생", e);
            // 심각한 오류의 경우 실패 처리를 고려할 수 있지만, 일단 성공으로 처리
            // context.failure("Google People API 처리 중 오류 발생");
        }

        // 성공/실패 관계없이 흐름 성공 처리
        logger.info("사용자 " + user.getUsername() + "의 Google People API 인증기 처리 완료");
        context.success();
    }

    private String extractGoogleAccessToken(AuthenticationFlowContext context, UserModel user) {
        logger.info("=== 토큰 추출 시작 ===");
        logger.info("사용자: " + user.getUsername() + " (ID: " + user.getId() + ")");
        logger.info("Realm: " + context.getRealm().getName());
        logger.info("Google Provider ID: " + GOOGLE_PROVIDER_ID);

        try {
            // FederatedIdentityModel에서 Google access token 추출
            logger.info("FederatedIdentity 조회 시도...");
            FederatedIdentityModel federatedIdentity = context.getSession()
                    .users()
                    .getFederatedIdentity(context.getRealm(), user, GOOGLE_PROVIDER_ID);

            if (federatedIdentity != null) {
                logger.info("FederatedIdentity 찾음!");
                logger.info("Identity Provider: " + federatedIdentity.getIdentityProvider());
                logger.info("User ID: " + federatedIdentity.getUserId());
                logger.info("Username: " + federatedIdentity.getUserName());

                String token = federatedIdentity.getToken();
                if (token != null && !token.trim().isEmpty()) {
                    logger.info("원본 토큰 추출 성공!");
                    logger.info("원본 토큰 길이: " + token.length());
                    logger.info("원본 토큰 시작 부분: " + token.substring(0, Math.min(50, token.length())) + "...");

                    // JSON 형태인지 확인하고 access_token 추출
                    String actualToken = extractAccessTokenFromJson(token);

                    if (actualToken != null) {
                        logger.info("실제 액세스 토큰 추출 성공!");
                        logger.info("실제 토큰 길이: " + actualToken.length());
                        logger.info(
                                "실제 토큰 시작: " + actualToken.substring(0, Math.min(20, actualToken.length())) + "...");

                        if (actualToken.startsWith("ya29.")) {
                            logger.info("Google OAuth2 토큰 형식 확인됨");
                        } else {
                            logger.warn(
                                    "예상과 다른 토큰 형식: " + actualToken.substring(0, Math.min(10, actualToken.length())));
                        }

                        return actualToken;
                    } else {
                        logger.error("JSON에서 access_token 추출 실패");
                        return null;
                    }
                } else {
                    logger.error("FederatedIdentity는 있지만 토큰이 null이거나 비어있음!");
                    logger.error("토큰 값: " + token);
                }
            } else {
                logger.error("FederatedIdentity를 찾을 수 없음!");
                logger.error("Google Provider ID로 조회했지만 결과가 null입니다");
                logger.error("사용자 ID: " + user.getId());
                logger.error("사용자명: " + user.getUsername());
                logger.error("Realm: " + context.getRealm().getName());
                logger.error("사용된 Provider ID: " + GOOGLE_PROVIDER_ID);
            }
        } catch (Exception e) {
            logger.error("토큰 추출 중 예외 발생!", e);
        }

        logger.error("=== 토큰 추출 실패 ===");
        return null;
    }

    /**
     * JSON 형태의 토큰에서 실제 access_token 값을 추출
     */
    private String extractAccessTokenFromJson(String tokenString) {
        try {
            // JSON 형태인지 확인
            if (tokenString.trim().startsWith("{") && tokenString.trim().endsWith("}")) {
                logger.info("JSON 형태의 토큰 감지, access_token 추출 시도");

                // 간단한 JSON 파싱 (Jackson 사용하지 않고 문자열 처리)
                String searchKey = "\"access_token\":\"";
                int startIndex = tokenString.indexOf(searchKey);

                if (startIndex != -1) {
                    startIndex += searchKey.length();
                    int endIndex = tokenString.indexOf("\"", startIndex);

                    if (endIndex != -1) {
                        String accessToken = tokenString.substring(startIndex, endIndex);
                        logger.info("JSON에서 access_token 추출 성공: "
                                + accessToken.substring(0, Math.min(10, accessToken.length())) + "...");
                        return accessToken;
                    } else {
                        logger.error("access_token 값의 끝을 찾을 수 없음");
                    }
                } else {
                    logger.error("JSON에서 access_token 키를 찾을 수 없음");
                }
            } else {
                // JSON이 아닌 경우 그대로 반환
                logger.info("JSON이 아닌 일반 토큰으로 판단, 그대로 사용");
                return tokenString;
            }
        } catch (Exception e) {
            logger.error("토큰 JSON 파싱 중 오류 발생", e);
        }

        return null;
    }

    private void callGooglePeopleApi(String accessToken, String username, AuthenticationFlowContext context,
            UserModel user) {
        logger.info("=== Google People API 호출 시작 ===");
        logger.info("사용자: " + username);
        logger.info("API URL: " + GOOGLE_PEOPLE_API_URL);
        logger.info("토큰 길이: " + accessToken.length());
        logger.info("토큰 시작: " + accessToken.substring(0, Math.min(30, accessToken.length())) + "...");

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(GOOGLE_PEOPLE_API_URL);
            request.setHeader("Authorization", "Bearer " + accessToken);
            request.setHeader("Accept", "application/json");
            request.setHeader("User-Agent", "Keycloak-SPI/1.0");

            logger.info("HTTP 요청 헤더 설정 완료");
            logger.info(
                    "Authorization: Bearer " + accessToken.substring(0, Math.min(20, accessToken.length())) + "...");

            logger.info("HTTP 요청 실행 중...");
            var response = httpClient.execute(request);

            int statusCode = response.getStatusLine().getStatusCode();
            String statusMessage = response.getStatusLine().getReasonPhrase();
            String responseBody = EntityUtils.toString(response.getEntity());

            logger.info("=== API 응답 상세 정보 ===");
            logger.info("상태 코드: " + statusCode);
            logger.info("상태 메시지: " + statusMessage);
            logger.info("응답 본문 길이: " + responseBody.length());
            logger.info("응답 본문: " + responseBody);

            // 응답 헤더도 출력
            logger.info("=== 응답 헤더 ===");
            for (var header : response.getAllHeaders()) {
                logger.info(header.getName() + ": " + header.getValue());
            }

            if (statusCode == 401) {
                logger.error("=== 401 Unauthorized 분석 ===");
                logger.error("토큰이 만료되었거나 유효하지 않을 수 있습니다");
                logger.error("토큰 전체 길이: " + accessToken.length());
                if (responseBody.contains("invalid_token")) {
                    logger.error("응답에 'invalid_token' 포함됨");
                }
                if (responseBody.contains("expired")) {
                    logger.error("응답에 'expired' 포함됨 - 토큰 만료");
                }
            } else if (statusCode == 200) {
                logger.info("=== API 호출 성공! ===");
                // 응답 데이터를 파싱하여 사용자 프로필 업데이트
                updateUserProfile(responseBody, context, user);
            }

        } catch (Exception e) {
            logger.error("=== Google People API 호출 중 예외 발생 ===", e);
            logger.error("예외 타입: " + e.getClass().getSimpleName());
            logger.error("예외 메시지: " + e.getMessage());
        }

        logger.info("=== Google People API 호출 완료 ===");
    }

    /**
     * Google People API 응답을 파싱하여 사용자 프로필 업데이트
     */
    private void updateUserProfile(String responseBody, AuthenticationFlowContext context, UserModel user) {
        logger.info("=== 사용자 프로필 업데이트 시작 ===");

        try {
            // externalId 추출 및 업데이트
            String externalId = extractExternalId(responseBody);
            if (externalId != null && !externalId.trim().isEmpty()) {
                logger.info("External ID 추출 성공: " + externalId);
                user.setSingleAttribute("externalId", externalId);
                logger.info("사용자 프로필에 externalId 설정 완료");
            } else {
                logger.warn("External ID를 찾을 수 없습니다");
            }

            // department 추출 및 업데이트
            String department = extractDepartment(responseBody);
            if (department != null && !department.trim().isEmpty()) {
                logger.info("Department 추출 성공: " + department);
                user.setSingleAttribute("department", department);
                logger.info("사용자 프로필에 department 설정 완료");
            } else {
                logger.warn("Department를 찾을 수 없습니다");
            }

            logger.info("=== 사용자 프로필 업데이트 완료 ===");

        } catch (Exception e) {
            logger.error("사용자 프로필 업데이트 중 오류 발생", e);
        }
    }

    /**
     * JSON 응답에서 첫 번째 externalId 값 추출
     */
    private String extractExternalId(String responseBody) {
        try {
            logger.info("External ID 추출 시도 중...");
            
            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(responseBody);
            
            if (json.has("externalIds")) {
                JsonNode externalIds = json.get("externalIds");
                
                if (externalIds.isArray() && externalIds.size() > 0) {
                    JsonNode firstExternalId = externalIds.get(0);
                    
                    if (firstExternalId.has("value")) {
                        String externalId = firstExternalId.get("value").asText();
                        logger.info("External ID 파싱 성공: " + externalId);
                        return externalId;
                    }
                }
            }
            
            logger.warn("External ID를 찾을 수 없습니다");
            return null;

        } catch (Exception e) {
            logger.error("External ID 추출 중 오류 발생", e);
            return null;
        }
    }

    /**
     * JSON 응답에서 첫 번째 organization의 department 값 추출
     */
    private String extractDepartment(String responseBody) {
        try {
            logger.info("Department 추출 시도 중...");
            
            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(responseBody);
            
            if (json.has("organizations")) {
                JsonNode organizations = json.get("organizations");
                
                if (organizations.isArray() && organizations.size() > 0) {
                    JsonNode firstOrg = organizations.get(0);
                    
                    if (firstOrg.has("department")) {
                        String department = firstOrg.get("department").asText();
                        logger.info("Department 파싱 성공: " + department);
                        return department;
                    }
                }
            }
            
            logger.warn("Department를 찾을 수 없습니다");
            return null;

        } catch (Exception e) {
            logger.error("Department 추출 중 오류 발생", e);
            return null;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Post Login Flow에서는 action 불필요
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        String email = user.getEmail();
        if (email == null || !email.endsWith("@jbnu.ac.kr")) return false;
    
        FederatedIdentityModel federatedIdentity =
            session.users().getFederatedIdentity(realm, user, "google");
        return (federatedIdentity != null && federatedIdentity.getToken() != null);
    }
    

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Required actions 없음
    }

    @Override
    public void close() {
        // 리소스 정리 불필요
    }
}
