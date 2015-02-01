package com.furdei.furdroid.security.encryption.test;

import com.furdei.furdroid.security.encryption.EncryptionUtils;
import com.furdei.furdroid.security.encryption.EncryptedFileStorage;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by furdey on 28.06.14.
 */
public class EncryptedFileStorageTest extends Assert {

    private static final String keyPassword="keyPassword";
    private File baseDir;

    @Before
    public void setup() throws Exception {
        EncryptionUtils.setPassword(keyPassword);
        baseDir = new File(System.getProperty("java.io.tmpdir"));
    }

    @Test
    public void testWriteAndRead() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        System.out.println("com.furdei.furdroid.security.encryption.test.EncryptedFileStorageTest.testWriteAndRead");
        Cipher encryptCipher = EncryptionUtils.initForEncrypt();
        String fileName = "vegatest.xml";
        String fileBodySrc = "My test файл 123";
        EncryptedFileStorage.writeString(encryptCipher, baseDir, fileName, fileBodySrc);
        Cipher decryptCipher = EncryptionUtils.initForDecrypt();
        String fileBodyDst = EncryptedFileStorage.readString(decryptCipher, baseDir, fileName);

        Assert.assertEquals(fileBodySrc, fileBodyDst);
    }
}
