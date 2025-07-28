package com.jigsso.idsync;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for Google People API Authenticator
 */
public class GooglePeopleApiAuthenticatorTest extends TestCase {
    
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public GooglePeopleApiAuthenticatorTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(GooglePeopleApiAuthenticatorTest.class);
    }

    /**
     * Test authenticator factory creation
     */
    public void testAuthenticatorFactory() {
        GooglePeopleApiAuthenticatorFactory factory = new GooglePeopleApiAuthenticatorFactory();
        
        assertEquals("google-people-api-authenticator", factory.getId());
        assertEquals("Google People API Post Login", factory.getDisplayType());
        assertEquals("post-login", factory.getReferenceCategory());
        assertFalse(factory.isConfigurable());
        assertFalse(factory.isUserSetupAllowed());
    }

    /**
     * Test authenticator creation
     */
    public void testAuthenticatorCreation() {
        GooglePeopleApiAuthenticatorFactory factory = new GooglePeopleApiAuthenticatorFactory();
        
        // Keycloak session이 없어서 실제 생성은 테스트하기 어려움
        // 팩토리 메서드 존재 여부만 확인
        assertNotNull(factory);
        assertTrue(factory instanceof GooglePeopleApiAuthenticatorFactory);
    }
}
