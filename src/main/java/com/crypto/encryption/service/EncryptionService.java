package com.crypto.encryption.service;

import com.crypto.encryption.exception.CryptoException;
import com.crypto.encryption.util.CryptoUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;

@Service
@Slf4j
public class EncryptionService {

    /**
     * Encrypt data using public key (RSA)
     */
    public byte[] encrypt(byte[] data, PublicKey publicKey) {
        try {
            CryptoUtil.initializeBouncyCastle();

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", CryptoUtil.getProviderName());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedData = cipher.doFinal(data);
            log.info("✓ Data encrypted successfully - Size: {} bytes", encryptedData.length);

            return encryptedData;
        } catch (Exception e) {
            log.error("✗ Error during encryption", e);
            throw new CryptoException("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypt data using private key (RSA)
     */
    public byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) {
        try {
            CryptoUtil.initializeBouncyCastle();

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", CryptoUtil.getProviderName());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decryptedData = cipher.doFinal(encryptedData);
            log.info("✓ Data decrypted successfully - Size: {} bytes", decryptedData.length);

            return decryptedData;
        } catch (Exception e) {
            log.error("✗ Error during decryption", e);
            throw new CryptoException("Decryption failed: " + e.getMessage(), e);
        }
    }
}