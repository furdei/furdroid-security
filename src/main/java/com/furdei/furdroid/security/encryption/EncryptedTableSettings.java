package com.furdei.furdroid.security.encryption;

import java.util.HashSet;
import java.util.Set;

/**
 * Class describes encryption setting for a single database table. It contains a table name and a
 * list of table columns that are encrypted.
 *
 * @author Stepan Furdey
 */
public class EncryptedTableSettings {

    private String tableName;
    private Set<String> encColumns;

    public EncryptedTableSettings(String tableName) {
        this.tableName = tableName;
        encColumns = new HashSet<String>();
    }

    /**
     * Get a name of encrypted table
     */
    public String getTableName() {
        return tableName;
    }

    /**
     * Set a name of encrypted table
     * @param tableName name of a table that contains encrypted columns
     */
    public void setTableName(String tableName) {
        this.tableName = tableName;
    }

    /**
     * Get the list of encrypted columns for the table
     */
    public Set<String> getEncColumns() {
        return encColumns;
    }

    /**
     * Add a column to the list of encrypted columns of the table
     *
     * @param column a column that needs to be encrypted
     */
    public void markColumnEncrypted(String column) {
        encColumns.add(column);
    }

    /**
     * Removes a column from the list of encrypted columns of the table. All columns are considered
     * unencrypted by default until they get marked as encrypted by calling
     * {@link #markColumnEncrypted(String)} method.
     *
     * @param column a column that doesn't need to be encrypted.
     */
    public void markColumnUnencrypted(String column) {
        encColumns.remove(column);
    }
}
