package com.furdei.furdroid.security.database;

import android.database.CharArrayBuffer;
import android.database.sqlite.SQLiteCursor;
import android.database.sqlite.SQLiteCursorDriver;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteQuery;
import android.os.Bundle;

import com.furdei.furdroid.security.encryption.EncryptedTableSettings;
import com.furdei.furdroid.security.encryption.EncryptionUtils;

import java.io.IOException;

import javax.crypto.Cipher;

/**
 * SQLite cursor with support for decryption of encrypted columns in database table. You should
 * work with this cursor implementation the same way you work with an ordinal SQLite cursor.
 * Your program event doesn't have to know that you are using this class. To make SQLite create
 * and return <code>DecryptingSQLiteCursor</code> instead of standard cursor provide an instance of
 * {@link com.furdei.furdroid.security.database.DecryptingSQLiteCursorFactory
 * DecryptingSQLiteCursorFactory} class. See
 * {@link com.furdei.furdroid.security.encryption.EncryptionUtils EncryptionUtils} for details.
 *
 * @see com.furdei.furdroid.security.database.DecryptingSQLiteCursorFactory
 * DecryptingSQLiteCursorFactory
 * @see com.furdei.furdroid.security.encryption.EncryptionUtils EncryptionUtils
 *
 * @author Stepan Furdey
 */
public class DecryptingSQLiteCursor extends SQLiteCursor {

    private Bundle  extras;
    private String  editTable;

    public DecryptingSQLiteCursor(SQLiteDatabase db, SQLiteCursorDriver driver,
                                  String editTable, SQLiteQuery query) {
        super(db, driver, editTable, query);
        this.editTable = editTable;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Bundle getExtras() {
        if (extras == null)
            extras = new Bundle();

        return extras;
    }

    private boolean[] encryptedColumns = null;

    private boolean isColumnEncrypted(int columnIndex) {
        if (encryptedColumns == null) {
            encryptedColumns = new boolean[getColumnCount()];
            EncryptedTableSettings encTable = EncryptionUtils.getEncSettings()
                    .getEncryptedTables().get(editTable);

            for (int i = 0; i < getColumnCount(); i++) {
                encryptedColumns[i] = encTable != null && encTable.getEncColumns().contains(getColumnName(i));
            }
        }

        return encryptedColumns[columnIndex];
    }

    private Cipher decryptingCipher = null;

    private Cipher getDecryptingCipher() {
        if (decryptingCipher == null) {
            try {
                decryptingCipher = EncryptionUtils.initForDecrypt();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return decryptingCipher;
    }

    private void checkColumnIndex(int columnIndex) {
        if (columnIndex < 0) {
            throw new IllegalArgumentException("columnIndex < 0. columnIndex: " + columnIndex);
        }

        if (columnIndex >= getColumnCount()) {
            throw new IllegalArgumentException("columnIndex >= getColumnCount(). columnIndex: "
                    + columnIndex + " getColumnCount(): " + getColumnCount());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getBlob(int columnIndex) {
        checkColumnIndex(columnIndex);

        if (isColumnEncrypted(columnIndex)) {
            throw new IllegalStateException("Blob encryption is not supported. " +
                    "Use getString(int columnIndex) instead.");
        }

        return super.getBlob(columnIndex);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getString(int columnIndex) {
        checkColumnIndex(columnIndex);

        try {
            return isColumnEncrypted(columnIndex) ?
                    EncryptionUtils.decrypt(getDecryptingCipher(), super.getString(columnIndex))
                    : super.getString(columnIndex);
        } catch (IOException e) {
            throw new RuntimeException("Error while decrypting cursor", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void copyStringToBuffer(int columnIndex, CharArrayBuffer buffer) {
        checkColumnIndex(columnIndex);

        if (isColumnEncrypted(columnIndex)) {
            throw new IllegalStateException("copyStringToBuffer is not supported for encrypted " +
                    "data. Use getString(int columnIndex) instead.");
        }

        super.copyStringToBuffer(columnIndex, buffer);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public short getShort(int columnIndex) {
        checkColumnIndex(columnIndex);

        if (isColumnEncrypted(columnIndex)) {
            String strVal = getString(columnIndex);
            return strVal != null ? Short.parseShort(strVal) : 0;
        }

        return super.getShort(columnIndex);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getInt(int columnIndex) {
        checkColumnIndex(columnIndex);

        if (isColumnEncrypted(columnIndex)) {
            String strVal = getString(columnIndex);
            return strVal != null ? Integer.parseInt(strVal) : 0;
        }

        return super.getInt(columnIndex);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getLong(int columnIndex) {
        checkColumnIndex(columnIndex);

        if (isColumnEncrypted(columnIndex)) {
            String strVal = getString(columnIndex);
            return strVal != null ? Long.parseLong(strVal) : 0;
        }

        return super.getLong(columnIndex);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public float getFloat(int columnIndex) {
        checkColumnIndex(columnIndex);

        if (isColumnEncrypted(columnIndex)) {
            String strVal = getString(columnIndex);
            return strVal != null ? Float.parseFloat(strVal) : 0;
        }

        return super.getFloat(columnIndex);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public double getDouble(int columnIndex) {
        checkColumnIndex(columnIndex);

        if (isColumnEncrypted(columnIndex)) {
            String strVal = getString(columnIndex);
            return strVal != null ? Double.parseDouble(strVal) : 0;
        }

        return super.getDouble(columnIndex);
    }

}
