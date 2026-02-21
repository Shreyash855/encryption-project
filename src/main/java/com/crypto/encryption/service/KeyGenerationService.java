package com.crypto.encryption.service;

import com.crypto.encryption.exception.CryptoException;
import com.crypto.encryption.model.CryptoKey;
import com.crypto.encryption.repository.CryptoKeyRepository;
import com.crypto.encryption.util.CryptoUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

@Service
@Slf4j
public class KeyGenerationService {

    @Value("${crypto.key-size:2048}")
    private int defaultKeySize;

    @Value("${crypto.algorithm:RSA}")
    private String defaultAlgorithm;

    private final CryptoKeyRepository cryptoKeyRepository;

    public KeyGenerationService(CryptoKeyRepository cryptoKeyRepository) {
        this.cryptoKeyRepository = cryptoKeyRepository;
    }

    /**
     * Generate RSA Key Pair with default configuration
     */
    public KeyPair generateKeyPair() {
        return generateKeyPair(defaultKeySize);
    }

    /**
     * Generate RSA Key Pair with specified size
     */
    public KeyPair generateKeyPair(int keySize) {
        try {
            CryptoUtil.initializeBouncyCastle();

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(defaultAlgorithm, CryptoUtil.getProviderName());
            keyGen.initialize(keySize);

            KeyPair keyPair = keyGen.generateKeyPair();
            log.info("✓ KeyPair generated - Algorithm: {}, KeySize: {}", defaultAlgorithm, keySize);

            return keyPair;
        } catch (Exception e) {
            log.error("✗ Error generating KeyPair", e);
            throw new CryptoException("Failed to generate key pair: " + e.getMessage(), e);
        }
    }

    /**
     * Convert Public Key to PEM format
     */
    public String convertPublicKeyToPEM(PublicKey publicKey) {
        try {
            StringWriter writer = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(publicKey);
            pemWriter.close();

            String pem = writer.toString();
            log.debug("✓ Public key converted to PEM format");
            return pem;
        } catch (Exception e) {
            log.error("✗ Error converting public key to PEM", e);
            throw new CryptoException("Failed to convert public key to PEM: " + e.getMessage(), e);
        }
    }

    /**
     * Convert Private Key to PEM format
     */
    public String convertPrivateKeyToPEM(PrivateKey privateKey) {
        try {
            StringWriter writer = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(privateKey);
            pemWriter.close();

            String pem = writer.toString();
            log.debug("✓ Private key converted to PEM format");
            return pem;
        } catch (Exception e) {
            log.error("✗ Error converting private key to PEM", e);
            throw new CryptoException("Failed to convert private key to PEM: " + e.getMessage(), e);
        }
    }

    /**
     * Generate and save key pair in database
     */
    public CryptoKey generateAndSaveKeyPair(String keyName, Integer keySize, String description) {
        try {
            // Check if key name already exists
            if (cryptoKeyRepository.findByKeyName(keyName).isPresent()) {
                throw new CryptoException("Key with name '" + keyName + "' already exists");
            }

            // Use default if not provided
            int size = keySize != null ? keySize : defaultKeySize;

            // Generate key pair
            KeyPair keyPair = generateKeyPair(size);

            // Convert to PEM
            String publicKeyPEM = convertPublicKeyToPEM(keyPair.getPublic());
            String privateKeyPEM = convertPrivateKeyToPEM(keyPair.getPrivate());

            // Save to database
            CryptoKey cryptoKey = CryptoKey.builder()
                    .keyName(keyName)
                    .algorithm(defaultAlgorithm)
                    .keySize(size)
                    .publicKeyPEM(publicKeyPEM)
                    .privateKeyPEM(privateKeyPEM)
                    .description(description)
                    .keyStatus("ACTIVE")
                    .build();

            CryptoKey savedKey = cryptoKeyRepository.save(cryptoKey);
            log.info("✓ Key pair '{}' generated and saved with ID: {}", keyName, savedKey.getId());

            return savedKey;
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            log.error("✗ Error saving key pair", e);
            throw new CryptoException("Failed to save key pair: " + e.getMessage(), e);
        }
    }

    /**
     * Get public key from stored PEM
     */
    public PublicKey getPublicKeyFromPEM(String publicKeyPEM) {
        try {
            return CryptoUtil.convertPEMToPublicKey(publicKeyPEM);
        } catch (Exception e) {
            log.error("✗ Error reading public key from PEM", e);
            throw new CryptoException("Failed to read public key from PEM: " + e.getMessage(), e);
        }
    }

    /**
     * Get private key from stored PEM
     */
    public PrivateKey getPrivateKeyFromPEM(String privateKeyPEM) {
        try {
            return CryptoUtil.convertPEMToPrivateKey(privateKeyPEM);
        } catch (Exception e) {
            log.error("✗ Error reading private key from PEM", e);
            throw new CryptoException("Failed to read private key from PEM: " + e.getMessage(), e);
        }
    }
}