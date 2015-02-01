package com.furdei.furdroid.security.encryption;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.crypto.Cipher;

/**
 * Provides APIs to store/retrieve encrypted data into/from application file storage. See
 * {@link com.furdei.furdroid.security.encryption.EncryptionUtils EncryptionUtils} for details
 * about configuring and working with encrypted storage.
 *
 * @see com.furdei.furdroid.security.encryption.EncryptionUtils EncryptionUtils
 *
 * @author Stepan Furdey
 */
public class EncryptedFileStorage {

    /**
     * Encrypt data and write encrypted data into a file
     *
     * @param encryptCipher an instance of {@link javax.crypto.Cipher} initialized for encryption
     * @param file output file
     * @param rawBytes unencrypted data
     * @throws IOException
     */
    public static void write(Cipher encryptCipher, File file, byte[] rawBytes) throws IOException {
        byte[] encrypted = EncryptionUtils.encrypt(encryptCipher, rawBytes);
        FileOutputStream outputStream = new FileOutputStream(file);
        outputStream.write(encrypted);
    }

    /**
     * Read and decrypt data from file
     *
     * @param decryptCipher an instance of {@link javax.crypto.Cipher} initialized for decryption
     * @param file source file
     * @return decrypted data
     * @throws IOException
     */
    public static byte[] read(Cipher decryptCipher, File file) throws IOException {
        FileInputStream inputStream = new FileInputStream(file);
        DataInputStream dis = new DataInputStream(inputStream);
        byte[] encrypted = new byte[(int) file.length()];
        dis.readFully(encrypted);
        return EncryptionUtils.decrypt(decryptCipher, encrypted);
    }

    /**
     * Encrypt data and write encrypted data into a file
     *
     * @param encryptCipher an instance of {@link javax.crypto.Cipher} initialized for encryption
     * @param baseDir a directory for output file
     * @param fileName a name of the output file in the <code>baseDir</code> directory
     * @param rawBytes unencrypted data
     * @throws IOException
     */
    public static void write(Cipher encryptCipher, File baseDir, String fileName, byte[] rawBytes)
            throws IOException {
        write(encryptCipher, getFile(baseDir, fileName), rawBytes);
    }

    /**
     * Read and decrypt data from file
     *
     * @param decryptCipher an instance of {@link javax.crypto.Cipher} initialized for decryption
     * @param baseDir a directory for output file
     * @param fileName a name of the output file in the <code>baseDir</code> directory
     * @return decrypted data
     * @throws IOException
     */
    public static byte[] read(Cipher decryptCipher, File baseDir, String fileName)
            throws IOException {
        return read(decryptCipher, getFile(baseDir, fileName));
    }

    /**
     * Encrypt string data and write encrypted data into a file
     *
     * @param encryptCipher an instance of {@link javax.crypto.Cipher} initialized for encryption
     * @param baseDir a directory for output file
     * @param fileName a name of the output file in the <code>baseDir</code> directory
     * @param documentBody unencrypted data
     * @throws IOException
     */
    public static void writeString(Cipher encryptCipher, File baseDir, String fileName,
                                   String documentBody) throws IOException {
        write(encryptCipher, baseDir, fileName, documentBody.getBytes());
    }

    /**
     * Read and decrypt text data from file
     *
     * @param decryptCipher an instance of {@link javax.crypto.Cipher} initialized for decryption
     * @param baseDir a directory for output file
     * @param fileName a name of the output file in the <code>baseDir</code> directory
     * @return decrypted data
     * @throws IOException
     */
    public static String readString(Cipher decryptCipher, File baseDir, String fileName)
            throws IOException {
        return new String(read(decryptCipher, baseDir, fileName));
    }

    /**
     * Construct a File object from baseDir and fileName
     */
    private static File getFile(File baseDir, String fileName) {
        String baseDirPath = baseDir.getPath();

        if (!(baseDirPath.endsWith("/") || baseDirPath.endsWith("\\"))) {
            baseDirPath = baseDirPath.concat("/");
        }

        return new File(baseDirPath + fileName);
    }
}
