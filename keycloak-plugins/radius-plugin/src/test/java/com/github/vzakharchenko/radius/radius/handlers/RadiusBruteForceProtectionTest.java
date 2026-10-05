package com.github.vzakharchenko.radius.radius.handlers;

import com.github.vzakharchenko.radius.test.AbstractRadiusTest;
import org.keycloak.services.managers.BruteForceProtector;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class RadiusBruteForceProtectionTest extends AbstractRadiusTest {

    @Mock
    private BruteForceProtector bruteForceProtector;

    @BeforeMethod
    public void beforeMethods() {
        when(session.getProvider(BruteForceProtector.class)).thenReturn(bruteForceProtector);
        when(realmModel.isBruteForceProtected()).thenReturn(true);
    }

    @Test
    public void testNotLockedOut() {
        assertFalse(RadiusBruteForceProtection.isLockedOut(session, radiusUserInfoGetter));
    }

    @Test
    public void testTemporarilyLockedOut() {
        when(bruteForceProtector.isTemporarilyDisabled(session, realmModel, userModel))
                .thenReturn(true);
        assertTrue(RadiusBruteForceProtection.isLockedOut(session, radiusUserInfoGetter));
    }

    @Test
    public void testPermanentlyLockedOut() {
        when(bruteForceProtector.isPermanentlyLockedOut(session, realmModel, userModel))
                .thenReturn(true);
        assertTrue(RadiusBruteForceProtection.isLockedOut(session, radiusUserInfoGetter));
    }

    @Test
    public void testBruteForceDisabledInRealm() {
        when(realmModel.isBruteForceProtected()).thenReturn(false);
        when(bruteForceProtector.isTemporarilyDisabled(session, realmModel, userModel))
                .thenReturn(true);
        assertFalse(RadiusBruteForceProtection.isLockedOut(session, radiusUserInfoGetter));
        RadiusBruteForceProtection.recordLogin(session, radiusUserInfoGetter, false);
        verify(bruteForceProtector, never()).failedLogin(any(), any(), any(), any(), anySet());
    }

    @Test
    public void testWithoutUserInfo() {
        assertFalse(RadiusBruteForceProtection.isLockedOut(session, null));
        RadiusBruteForceProtection.recordLogin(session, null, false);
        verify(bruteForceProtector, never()).failedLogin(any(), any(), any(), any(), anySet());
    }

    @Test
    public void testRecordFailedLogin() {
        RadiusBruteForceProtection.recordLogin(session, radiusUserInfoGetter, false);
        verify(bruteForceProtector).failedLogin(eq(realmModel), eq(userModel),
                eq(clientConnection), isNull(), anySet());
    }

    @Test
    public void testRecordSuccessfulLogin() {
        RadiusBruteForceProtection.recordLogin(session, radiusUserInfoGetter, true);
        verify(bruteForceProtector).successfulLogin(eq(realmModel), eq(userModel),
                eq(clientConnection), isNull(), anySet());
    }

    @Override
    protected List<? extends Object> resetMock() {
        return Arrays.asList(bruteForceProtector);
    }
}
