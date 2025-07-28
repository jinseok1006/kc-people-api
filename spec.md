# ✅ Keycloak Post Login Flow + Google People API PoC 요구사항

## 🎯 목적
Google IDP 로그인 후, 저장된 access token으로 Google People API 호출하는 최소 기능 검증.

---

## 🛠 실행 흐름
1. 사용자가 Google IDP로 로그인
2. Keycloak이 `store token` 기능으로 access token 저장
3. Post Login Flow 내 Custom Authenticator SPI 실행
4. SPI 내부에서:
   - `FederatedIdentityModel.getToken()` → access token 추출
   - access token으로 People API 호출 시도
5. 호출 성공/실패 관계없이 `context.success()` 호출

---

## 🔧 구성 요건
- **Keycloak 설정**
  - `Store Tokens`: ✅ On
  - `Scope`: `https://www.googleapis.com/auth/userinfo.profile`
  - `Post Login Flow`: Custom SPI 포함 플로우 지정

- **SPI 최소 구현**
  - `authenticate()` 내에서:
    - `user` → `FederatedIdentityModel` 접근
    - `access_token` 추출 → People API 호출
    - 실패해도 흐름은 성공 처리

---

## ✅ 성공 기준
- Post Login Flow가 실행됨
- access token 추출 성공
- Google API에 실제 HTTP 요청 시도됨
- 로그인 전체 흐름 성공 처리됨

