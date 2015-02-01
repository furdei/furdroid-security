package com.furdei.furdroid.security.encryption;

import android.content.ContentValues;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>
 * This class provides core utility methods to implement encryption and decryption for Android
 * applications' data. It provides support for symmetric encryption algorithm AES. That means
 * it uses for decryption the same key used for encryption. It is highly unsafe to store a key
 * on device or obtain it elsewhere if hacker can reproduce these steps to obtain a key. That's
 * why the key isn't stored anywhere but is generated on the fly. The problem is that key
 * derivation algorithm also has to be secure. It is solved by adding a variable to the algorithm:
 * a text password that you shouldn't keep on the device but make user enter every time he launches
 * an application. It decreases usability but keeps security high. If a hacker doesn't get a
 * password, he wouldn't be able to derive a key and decrypt your data. From the other side, key
 * derivation algorithm guarantees that the same key will always be generated from the same
 * password, so that you don't ever have to save a key on the device.
 * </p>
 * <h3>Initialize encryption</h3>
 * <p>
 * Basically to initialize <code>EncryptionUtils</code> you should call only two methods:
 * {@link #setPassword(String)} to specify a password for key derivation and
 * {@link #setEncryptionSettingsProvider(EncryptionSettingsProvider)} to specify what tables you
 * want to encrypt in your database. Note that you don't need to call
 * {@link #setEncryptionSettingsProvider(EncryptionSettingsProvider)} if you don't use SQLite
 * database in your application. If you want only to access a secure file storage than setting
 * a password is everything you need to initialize encryption.
 * </p>
 * <h3>Accessing secure file storage</h3>
 * <p>
 * This library provides a number of convenient APIs to access secure storage through
 * <code>EncryptedFileStorage.read*</code> and <code>EncryptedFileStorage.write*</code> methods.
 * See {@link EncryptedFileStorage} for details.
 * </p>
 * <h3>Accessing secure database</h3>
 * <p>
 * To work with encrypted SQLite database you should first setup database encryption settings.
 * You need to provide an instance of
 * {@link com.furdei.furdroid.security.encryption.EncryptionSettingsProvider} to a static method
 * {@link #setEncryptionSettingsProvider(EncryptionSettingsProvider)}. You can crate your own
 * provider or use an out-of-the-box implementation
 * {@link com.furdei.furdroid.security.encryption.EncryptionSettingsParser}. It reads encryption
 * settings out of XML file you specify. An example of XML encryption settings
 * (<code>encryption_settings.xml</code>):
 * </p>
 * <pre>
 * {@code
 *
 * <?xml version="1.0" encoding="utf-8"?>
 * <encryption>
 *      <table name="payments">
 *          <column name="account_from" />
 *          <column name="description" />
 *      </table>
 *      <table name="customers">
 *          <column name="address" />
 *          <column name="phone" />
 *      </table>
 * </encryption>
 * }
 * </pre>
 * <p>
 * Now you only need to call {@link #setEncryptionSettingsProvider(EncryptionSettingsProvider)}
 * to finish the setup:
 * <pre>
 * {@code
 *
 *  EncryptionUtils.setEncryptionSettingsProvider(
 *      new EncryptionSettingsParser(getApplicationContext(), R.xml.encryption_settings));
 * }
 * </pre>
 * In the above example we specify that we want to encrypt tables <code>payments</code> and
 * <code>customers</code>. But we don't usually need to encrypt the whole table, only some
 * sensible piece of data. In our case only an account number and description would be encrypted
 * for payments and some contact information of our customers also. You don't need to encrypt
 * all your data for several reasons.
 * </p><p>
 * First of all, you are running your application on a slow mobile device and you don't want to
 * increase time of waiting for data access operations to complete. Software encryption affects
 * performance dramatically.
 * </p><p>
 * The second reason is that encryption makes database search operations impossible. You have to
 * work around, possibly create new columns containing some functions over the original data to
 * keep sorting order etc. So you basically need to encrypt only top secret piece of data that
 * should be as small as possible.
 * </p>
 * <h3>Encrypting data to save into SQLite database</h3>
 * <p>
 * Assuming you have already got <code>contentValues</code> - an unencrypted instance of
 * {@link android.content.ContentValues} class and you want to insert a new payment into table
 * <code>payments</code>. Typical steps to encrypt data:
 * <ul>
 *     <li>Set a password and encryption settings as described above once per app launch.</li>
 *     <li>Initialize a {@link javax.crypto.Cipher} instance for encryption:
 *     <code>Cipher cipher = EncryptionUtils.initForEncrypt();</code></li>
 *     <li>Call {@link EncryptionUtils#encryptContentValues(javax.crypto.Cipher, android.content.ContentValues, String)}:
 *     <code>EncryptionUtils.encryptContentValues(cipher, contentValues, "payments");</code></li>
 * </ul>
 * That's it. Now you can insert or update records using encrypted data.
 * </p><p>
 * The important thing to point out is that <b>data types can change during encryption</b>. All
 * encrypted data are represented by Base64-encoded strings even if the original data was integer
 * or float or any other data type. Make sure that you have <code>TEXT</code> type of encrypted
 * columns in your database.
 * </p>
 * <h3>Decrypting data read from SQLite database</h3>
 * <p>
 * SQLite data reading is implemented through the cursors. This library provides a special cursor
 * type {@link com.furdei.furdroid.security.database.DecryptingSQLiteCursor} with support for
 * decryption on the fly. To make SQLite database create and return
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
 * @see EncryptedFileStorage EncryptedFileStorage
 * @see com.furdei.furdroid.security.database.DecryptingSQLiteCursor DecryptingSQLiteCursor
 * @see com.furdei.furdroid.security.database.DecryptingSQLiteCursorFactory
 * DecryptingSQLiteCursorFactory
 * @see android.database.sqlite.SQLiteOpenHelper SQLiteOpenHelper
 *
 * @author Stepan Furdey
 */
public class EncryptionUtils {

    private static final String KEY_ALGORITHM = "AES";
    private static final String ENC_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String DER_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int KEY_LENGTH = 128;
    private static final int ITERATION_COUNT = 1000;
    private static final String ENCODING = "UTF-8";

    private static volatile SecretKey secretKey = null;
    private static volatile EncryptionSettings encSettings;
    private static volatile EncryptionSettingsProvider encryptionSettingsProvider;

    /**
     * Specify a password for key derivation.
     *
     * @param password a text password. The same key is guaranteed to be derived for
     *                 the same password.
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public static void setPassword(String password)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        secretKey = deriveKeyFromPassword(password);
    }

    /**
     * Get a provider for encryption settings
     */
    public static EncryptionSettingsProvider getEncryptionSettingsProvider() {
        return encryptionSettingsProvider;
    }

    /**
     * Specify a provider for encryption settings. This method resets current encryption settings
     * to make program request for settings from new provider. Settings request occurs later
     * when they are actually needed.
     *
     * @param encryptionSettingsProvider a new settings provider
     */
    public static synchronized void setEncryptionSettingsProvider(
            EncryptionSettingsProvider encryptionSettingsProvider) {
        EncryptionUtils.encryptionSettingsProvider = encryptionSettingsProvider;
        encSettings = null;
    }

    /**
     * Create an encryption {@link javax.crypto.Cipher} instance using key provided
     *
     * @param aesKey a symmetric key
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static Cipher initForEncrypt(SecretKey aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher encryptCipher = Cipher.getInstance(ENC_ALGORITHM);
        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return encryptCipher;
    }

    /**
     * Create an encryption {@link javax.crypto.Cipher} instance using key derived from password
     *
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static Cipher initForEncrypt()
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return initForEncrypt(secretKey);
    }

    /**
     * Encrypt piece of data
     *
     * @param encryptCipher an instance of {@link javax.crypto.Cipher} initialized for encryption
     * @param rawBytes a data to encrypt
     * @return an encrypted data
     * @throws IOException
     */
    public static byte[] encrypt(Cipher encryptCipher, byte[] rawBytes) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, encryptCipher);
        cipherOutputStream.write(rawBytes);
        cipherOutputStream.flush();
        cipherOutputStream.close();
        return outputStream.toByteArray();
    }

    /**
     * Create a decryption {@link javax.crypto.Cipher} instance using key provided
     *
     * @param aesKey a symmetric key
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static Cipher initForDecrypt(SecretKey aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher decryptCipher = Cipher.getInstance(ENC_ALGORITHM);
        decryptCipher.init(Cipher.DECRYPT_MODE, aesKey, new SecureRandom());
        return decryptCipher;
    }

    /**
     * Create a decryption {@link javax.crypto.Cipher} instance using key derived from password
     *
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static Cipher initForDecrypt()
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return initForDecrypt(secretKey);
    }

    /**
     * Decrypt piece of data
     *
     * @param decryptCipher an instance of {@link javax.crypto.Cipher} initialized for decryption
     * @param encryptedBytes an encrypted piece of data to decrypt
     * @return a decrypted data
     * @throws IOException
     */
    public static byte[] decrypt(Cipher decryptCipher, byte[] encryptedBytes) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ByteArrayInputStream inStream = new ByteArrayInputStream(encryptedBytes);
        CipherInputStream cipherInputStream = new CipherInputStream(inStream, decryptCipher);
        byte[] buf = new byte[1024];
        int bytesRead;
        while ((bytesRead = cipherInputStream.read(buf)) >= 0) {
            outputStream.write(buf, 0, bytesRead);
        }
        return outputStream.toByteArray();
    }

    /**
     * Encrypt data in {@link android.content.ContentValues} instance before saving them to
     * the database. This method encrypts data in place without creating a copy of content
     * values. It uses {@link com.furdei.furdroid.security.encryption.EncryptionSettings}
     * to determine which data in a <code>contentValues</code> buffer to encrypt.
     *
     * @param encryptCipher an instance of {@link javax.crypto.Cipher} initialized for encryption
     * @param contentValues {@link android.content.ContentValues} that contains data need to
     *                      be encrypted
     * @param tableName a name of a table into which you are going to save data in this
     *                  {@link android.content.ContentValues}. Used to select an encryption schema
     *                  in {@link com.furdei.furdroid.security.encryption.EncryptionSettings}
     * @throws IOException
     */
    public static void encryptContentValues(Cipher encryptCipher, ContentValues contentValues,
                                            String tableName) throws IOException {
        String[] columnsToEncrypt = null;

        EncryptedTableSettings table = getEncSettings().getEncryptedTables().get(tableName);
        if (table != null) {
            columnsToEncrypt = table.getEncColumns().toArray(
                    new String[table.getEncColumns().size()]);
        }

        encryptContentValues(encryptCipher, contentValues, columnsToEncrypt);
    }

    /**
     * Encrypt data in {@link android.content.ContentValues} instance before saving them to
     * the database. This method encrypts data in place without creating a copy of content
     * values. It does not use {@link com.furdei.furdroid.security.encryption.EncryptionSettings}
     * to determine which data in a <code>contentValues</code> buffer to encrypt. You can
     * specify columns through the <code>columnsToEncrypt</code> parameter. You don't have
     * to provide {@link com.furdei.furdroid.security.encryption.EncryptionSettings} to use this
     * method.
     *
     * @param encryptCipher an instance of {@link javax.crypto.Cipher} initialized for encryption
     * @param contentValues {@link android.content.ContentValues} that contains data need to
     *                      be encrypted
     * @param columnsToEncrypt a list of columns in this {@link android.content.ContentValues}
     *                         instance to encrypt
     * @throws IOException
     */
    public static void encryptContentValues(Cipher encryptCipher, ContentValues contentValues,
                                            String[] columnsToEncrypt) throws IOException {
        if (encryptCipher == null || contentValues == null || columnsToEncrypt == null
                || columnsToEncrypt.length == 0 || contentValues.size() == 0)
            return;

        for (String column : columnsToEncrypt) {
            if (contentValues.containsKey(column)) {
                String value = contentValues.getAsString(column);

                if (value != null && value.length() > 0) {
                    byte[] dataToEncrypt = value.getBytes(ENCODING);
                    byte[] encryptedData = encrypt(encryptCipher, dataToEncrypt);
                    contentValues.put(column, Base64.encodeToString(encryptedData, Base64.DEFAULT));
                }
            }
        }
    }

    /**
     * Decrypt piece of text data. Encrypted data is represented with a Base64 encoded string here.
     *
     * @param decryptCipher an instance of {@link javax.crypto.Cipher} initialized for decryption
     * @param encryptedStringBase64 encrypted data represented with a Base64 encoded string
     * @return decrypted string. It is implied here that original unencrypted data is a text string
     * @throws IOException
     */
    public static String decrypt(Cipher decryptCipher, String encryptedStringBase64)
            throws IOException {
        if (encryptedStringBase64 == null || encryptedStringBase64.length() == 0) {
            return null;
        }

        byte[] encryptedData = Base64.decode(encryptedStringBase64, Base64.DEFAULT);
        return new String(decrypt(decryptCipher, encryptedData), ENCODING);
    }

    /**
     * Returns cached encryption settings
     */
    public static EncryptionSettings getEncSettings() {
        if (encSettings == null) {
            synchronized (EncryptionUtils.class) {
                if (encSettings == null) {
                    if (encryptionSettingsProvider == null) {
                        throw new IllegalStateException(
                                "Encryption settings provider has not been specified. Call " +
                                "EncryptionUtils.setEncryptionSettingsProvider(" +
                                "EncryptionSettingsProvider) to specify encryption settings.");
                    }

                    encSettings = encryptionSettingsProvider.getEncryptionSettings();
                }
            }
        }

        return encSettings;
    }

    private static SecretKey deriveKeyFromPassword(String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory f = SecretKeyFactory.getInstance(DER_ALGORITHM);
        KeySpec ks = new PBEKeySpec(password.toCharArray(), "salt0123456789yo".getBytes(),
                ITERATION_COUNT, KEY_LENGTH);
        byte[] keyBytes = f.generateSecret(ks).getEncoded();
        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }

}
