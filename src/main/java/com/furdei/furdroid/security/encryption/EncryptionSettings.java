package com.furdei.furdroid.security.encryption;

import java.util.HashMap;
import java.util.Map;

/**
 * This class describes how your app's storage is encrypted: which tables and which columns
 * have to be encrypted and decrypted.
 *
 * @author Stepan Furdey
 */
public class EncryptionSettings {

    private Map<String, EncryptedTableSettings> encryptedTables;

    public EncryptionSettings() {
        this.encryptedTables = new HashMap<String, EncryptedTableSettings>();
    }

    /**
     * Returns the list of encrypted tables. A key of the list is the name of the table.
     * Key is case-sensitive.
     */
    public Map<String, EncryptedTableSettings> getEncryptedTables() {
        return encryptedTables;
    }

    /**
     * Set the list of encrypted tables.
     *
     * @param encryptedTables a new list of encrypted tables
     */
    public void setEncryptedTables(Map<String, EncryptedTableSettings> encryptedTables) {
        this.encryptedTables = encryptedTables;
    }
}
