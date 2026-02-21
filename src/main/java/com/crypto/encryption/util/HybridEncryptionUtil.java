package com.crypto.encryption.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

@Component
@Slf4j
public class HybridEncryptionUtil {

    /**
     * Encrypt file using hybrid encryption (AES + RSA)
     */
    public HybridEncryptedData encryptFileHybrid(byte[] fileData, PublicKey publicKey) throws Exception {
        log.info("🔐 Starting hybrid encryption for {} bytes of data", fileData.length);

        // Generate random AES key (256-bit)
        SecretKey aesKey = generateAESKey(256);
        log.info("✓ Generated AES-256 key");

        // Encrypt file with AES
        byte[] encryptedFileData = encryptWithAES(fileData, aesKey);
        log.info("✓ Encrypted file with AES: {} → {} bytes", fileData.length, encryptedFileData.length);

        // Encrypt AES key with RSA
        byte[] encryptedAESKey = encryptWithRSA(aesKey.getEncoded(), publicKey);
        log.info("✓ Encrypted AES key with RSA: {} → {} bytes", aesKey.getEncoded().length, encryptedAESKey.length);

        return new HybridEncryptedData(encryptedFileData, encryptedAESKey);
    }

    /**
     * Decrypt file using hybrid encryption (AES + RSA)
     */
    public byte[] decryptFileHybrid(byte[] encryptedFileData, byte[] encryptedAESKey, PrivateKey privateKey) throws Exception {
        log.info("🔓 Starting hybrid decryption");

        // Decrypt AES key with RSA
        byte[] decryptedAESKeyBytes = decryptWithRSA(encryptedAESKey, privateKey);
        SecretKey aesKey = new SecretKeySpec(decryptedAESKeyBytes, 0, decryptedAESKeyBytes.length, "AES");
        log.info("✓ Decrypted AES key with RSA: {} bytes", decryptedAESKeyBytes.length);

        // Decrypt file with AES
        byte[] decryptedFileData = decryptWithAES(encryptedFileData, aesKey);
        log.info("✓ Decrypted file with AES: {} → {} bytes", encryptedFileData.length, decryptedFileData.length);

        return decryptedFileData;
    }

    /**
     * Generate AES key of specified size
     */
    private SecretKey generateAESKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize, new SecureRandom());
        return keyGen.generateKey();
    }

    /**
     * Encrypt data with AES
     */
    private byte[] encryptWithAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * Decrypt data with AES
     */
    private byte[] decryptWithAES(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Encrypt data with RSA
     */
    private byte[] encryptWithRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * Decrypt data with RSA
     */
    private byte[] decryptWithRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Inner class to hold hybrid encrypted data
     */
    public static class HybridEncryptedData {
        public final byte[] encryptedFile;
        public final byte[] encryptedKey;

        public HybridEncryptedData(byte[] encryptedFile, byte[] encryptedKey) {
            this.encryptedFile = encryptedFile;
            this.encryptedKey = encryptedKey;
        }
    }
}