package com.furdei.furdroid.security.encryption;

/**
 * Implementation of this class need to provide encryption settings upon request. It does not
 * need to hold an instance of settings and implement caching because this functionality is
 * already implemented in {@link com.furdei.furdroid.security.encryption.EncryptionUtils}
 *
 * @author Stepan Furdey
 */
public interface EncryptionSettingsProvider  {

    /**
     * Creates and returns encryption settings. Don't implement caching here.
     */
    public EncryptionSettings getEncryptionSettings();
}
