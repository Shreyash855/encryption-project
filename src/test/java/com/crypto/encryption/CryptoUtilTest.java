package com.crypto.encryption;

import com.crypto.encryption.service.EncryptionService;
import com.crypto.encryption.service.KeyGenerationService;
import com.crypto.encryption.util.CryptoUtil;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Slf4j
class CryptoUtilTest {

    @Autowired
    private KeyGenerationService keyGenerationService;

    @Autowired
    private EncryptionService encryptionService;

    @BeforeAll
    static void setup() {
        CryptoUtil.initializeBouncyCastle();
    }

    @Test
    void testKeyGeneration() {
        log.info("═══════════════════════════════════════════════════════");
        log.info("TEST: Key Generation");
        log.info("═══════════════════════════════════════════════════════");

        KeyPair keyPair = keyGenerationService.generateKeyPair();

        assertNotNull(keyPair, "KeyPair should not be null");
        assertNotNull(keyPair.getPublic(), "Public key should not be null");
        assertNotNull(keyPair.getPrivate(), "Private key should not be null");

        log.info("✓ Public Key Algorithm: {}", keyPair.getPublic().getAlgorithm());
        log.info("✓ Private Key Algorithm: {}", keyPair.getPrivate().getAlgorithm());
        log.info("═══════════════════════════════════════════════════════\n");
    }

    @Test
    void testEncryptionDecryption() {
        log.info("═══════════════════════════════════════════════════════");
        log.info("TEST: Encryption & Decryption");
        log.info("═══════════════════════════════════════════════════════");

        // Generate key pair
        KeyPair keyPair = keyGenerationService.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Original message
        String originalMessage = "Hello, Encryption World!";
        byte[] plainText = originalMessage.getBytes();

        log.info("Original Message: {}", originalMessage);
        log.info("Plain Text Bytes: {}", plainText.length);

        // Encrypt
        byte[] encryptedData = encryptionService.encrypt(plainText, publicKey);
        log.info("Encrypted Data Bytes: {}", encryptedData.length);

        assertNotEquals(plainText.length, encryptedData.length);

        // Decrypt
        byte[] decryptedData = encryptionService.decrypt(encryptedData, privateKey);
        String decryptedMessage = new String(decryptedData);

        log.info("Decrypted Message: {}", decryptedMessage);
        log.info("Decrypted Data Bytes: {}", decryptedData.length);

        // Verify
        assertEquals(originalMessage, decryptedMessage, "Decrypted message should match original");

        log.info("✓ Encryption-Decryption cycle successful!");
        log.info("═══════════════════════════════════════════════════════\n");
    }
}