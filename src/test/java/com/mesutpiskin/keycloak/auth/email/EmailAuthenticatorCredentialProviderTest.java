package com.mesutpiskin.keycloak.auth.email;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EmailAuthenticatorCredentialProviderTest {

    private EmailAuthenticatorCredentialProvider provider;
    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;
    private SubjectCredentialManager credentialManager;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        user = mock(UserModel.class);
        credentialManager = mock(SubjectCredentialManager.class);
        when(user.credentialManager()).thenReturn(credentialManager);
        provider = new EmailAuthenticatorCredentialProvider(session);
    }

    @Test
    void testIsConfiguredFor_WithStoredCredentialAndEmail() {
        when(user.getEmail()).thenReturn("user@example.com");
        var credential = new EmailAuthenticatorCredentialModel();
        when(credentialManager.getStoredCredentialsByTypeStream(EmailAuthenticatorCredentialModel.TYPE_ID))
                .thenReturn(Stream.of(credential));

        boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

        assertTrue(result, "Should be configured when email is present and a stored credential exists");
    }

    @Test
    void testIsConfiguredFor_WithBlankEmail() {
        when(user.getEmail()).thenReturn("   ");
        when(credentialManager.getStoredCredentialsByTypeStream(EmailAuthenticatorCredentialModel.TYPE_ID))
                .thenReturn(Stream.of(new EmailAuthenticatorCredentialModel()));

        boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

        assertFalse(result, "Should not be configured when the email is blank");
    }

    @Test
    void testIsConfiguredFor_WithNullEmail() {
        when(user.getEmail()).thenReturn(null);
        when(credentialManager.getStoredCredentialsByTypeStream(EmailAuthenticatorCredentialModel.TYPE_ID))
                .thenReturn(Stream.of(new EmailAuthenticatorCredentialModel()));

        boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

        assertFalse(result, "Should not be configured when the email is null");
    }

    @Test
    void testIsConfiguredFor_WithNoStoredCredential() {
        when(user.getEmail()).thenReturn("user@example.com");
        when(credentialManager.getStoredCredentialsByTypeStream(EmailAuthenticatorCredentialModel.TYPE_ID))
                .thenReturn(Stream.empty());

        boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

        assertFalse(result, "Should not be configured when no stored credential exists");
    }

    @Test
    void testIsConfiguredFor_WrongCredentialType() {
        when(user.getEmail()).thenReturn("user@example.com");

        boolean result = provider.isConfiguredFor(realm, user, "wrong-type");

        assertFalse(result, "Should return false for unsupported credential type");
    }
}