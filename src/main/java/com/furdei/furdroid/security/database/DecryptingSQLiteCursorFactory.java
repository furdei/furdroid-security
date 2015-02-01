package com.furdei.furdroid.security.database;

import android.database.Cursor;
import android.database.sqlite.SQLiteCursorDriver;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteQuery;

/**
 * To make SQLite database create and return
 * {@link com.furdei.furdroid.security.database.DecryptingSQLiteCursor} cursors you need to set up
 * a cursor factory
 * {@link com.furdei.furdroid.security.database.DecryptingSQLiteCursorFactory} when you create an
 * {@link android.database.sqlite.SQLiteOpenHelper SQLiteOpenHelper} instance:
 * </p>
 * <pre>
 * {@code
 *
 *  SQLiteDatabase.CursorFactory cursorFactory = new DecryptingSQLiteCursorFactory();
 *  SQLiteOpenHelper helper = new SQLiteOpenHelper(
 *      getContext(), DATABASE_NAME, cursorFactory, DATABASE_VERSION) {
 *          // ...
 *      };
 * }
 * </pre>
 *
 * @see com.furdei.furdroid.security.encryption.EncryptionUtils EncryptionUtils
 * @see com.furdei.furdroid.security.database.DecryptingSQLiteCursor DecryptingSQLiteCursor
 * @see android.database.sqlite.SQLiteOpenHelper SQLiteOpenHelper
 *
 * @author Stepan Furdey
 */
public class DecryptingSQLiteCursorFactory implements SQLiteDatabase.CursorFactory {

    public Cursor newCursor(SQLiteDatabase db, SQLiteCursorDriver masterQuery, String editTable,
                            SQLiteQuery query) {
        return new DecryptingSQLiteCursor(db, masterQuery, editTable, query);
    }

}
