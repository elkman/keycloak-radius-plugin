package com.github.vzakharchenko.radius.radius.handlers;

import com.github.vzakharchenko.radius.radius.holder.IRadiusUserInfo;
import com.github.vzakharchenko.radius.radius.holder.IRadiusUserInfoGetter;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.services.managers.BruteForceProtector;

import java.util.Set;

/**
 * Applies the realm's brute force detection to RADIUS logins, so that failed
 * RADIUS attempts are counted and locked out users are rejected without checking
 * their password.
 */
public final class RadiusBruteForceProtection {

    private static final Logger LOGGER = Logger.getLogger(RadiusBruteForceProtection.class);

    private static final Set<String> CATEGORIES = Set.of(PasswordCredentialModel.TYPE);

    private RadiusBruteForceProtection() {
    }

    private static BruteForceProtector protector(KeycloakSession session,
                                                 IRadiusUserInfoGetter userInfoGetter) {
        if (userInfoGetter == null) {
            return null;
        }
        RealmModel realm = userInfoGetter.getRadiusUserInfo().getRealmModel();
        if (realm == null || !realm.isBruteForceProtected()) {
            return null;
        }
        return session.getProvider(BruteForceProtector.class);
    }

    public static boolean isLockedOut(KeycloakSession session,
                                      IRadiusUserInfoGetter userInfoGetter) {
        BruteForceProtector protector = protector(session, userInfoGetter);
        if (protector == null) {
            return false;
        }
        IRadiusUserInfo info = userInfoGetter.getRadiusUserInfo();
        RealmModel realm = info.getRealmModel();
        UserModel user = info.getUserModel();
        boolean lockedOut = protector.isTemporarilyDisabled(session, realm, user) ||
                protector.isPermanentlyLockedOut(session, realm, user);
        if (lockedOut) {
            LOGGER.warn("RADIUS login rejected, user " + user.getUsername()
                    + " is locked out by brute force detection");
        }
        return lockedOut;
    }

    public static void recordLogin(KeycloakSession session,
                                   IRadiusUserInfoGetter userInfoGetter,
                                   boolean success) {
        BruteForceProtector protector = protector(session, userInfoGetter);
        if (protector == null) {
            return;
        }
        IRadiusUserInfo info = userInfoGetter.getRadiusUserInfo();
        if (success) {
            protector.successfulLogin(info.getRealmModel(), info.getUserModel(),
                    info.getClientConnection(), null, CATEGORIES);
        } else {
            protector.failedLogin(info.getRealmModel(), info.getUserModel(),
                    info.getClientConnection(), null, CATEGORIES);
        }
    }
}
