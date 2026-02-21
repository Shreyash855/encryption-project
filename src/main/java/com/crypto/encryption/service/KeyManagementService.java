package com.crypto.encryption.service;

import com.crypto.encryption.dto.KeyGenerationRequest;
import com.crypto.encryption.dto.KeyResponse;
import com.crypto.encryption.dto.PrivateKeyExportResponse;
import com.crypto.encryption.dto.PublicKeyExportResponse;
import com.crypto.encryption.exception.CryptoException;
import com.crypto.encryption.model.CryptoKey;
import com.crypto.encryption.repository.CryptoKeyRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
public class KeyManagementService {

    private final CryptoKeyRepository cryptoKeyRepository;
    private final KeyGenerationService keyGenerationService;

    public KeyManagementService(CryptoKeyRepository cryptoKeyRepository, KeyGenerationService keyGenerationService) {
        this.cryptoKeyRepository = cryptoKeyRepository;
        this.keyGenerationService = keyGenerationService;
    }

    /**
     * Create new key pair
     */
    public KeyResponse createKeyPair(KeyGenerationRequest request) {
        log.info("Creating new key pair: {}", request.getKeyName());

        CryptoKey cryptoKey = keyGenerationService.generateAndSaveKeyPair(
                request.getKeyName(),
                request.getKeySize(),
                request.getDescription()
        );

        return convertToResponse(cryptoKey);
    }

    /**
     * Get all active keys
     */
    public List<KeyResponse> getAllActiveKeys() {
        log.info("Fetching all active keys");

        return cryptoKeyRepository.findAllActiveKeys()
                .stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get key by ID
     */
    public KeyResponse getKeyById(Long keyId) {
        log.info("Fetching key by ID: {}", keyId);

        CryptoKey cryptoKey = cryptoKeyRepository.findById(keyId)
                .orElseThrow(() -> new CryptoException("Key not found with ID: " + keyId));

        return convertToResponse(cryptoKey);
    }

    /**
     * Export public key in PEM format
     */
    public PublicKeyExportResponse exportPublicKey(Long keyId) {
        log.info("Exporting public key for ID: {}", keyId);

        CryptoKey cryptoKey = cryptoKeyRepository.findById(keyId)
                .orElseThrow(() -> new CryptoException("Key not found with ID: " + keyId));

        return PublicKeyExportResponse.builder()
                .keyId(cryptoKey.getId())
                .keyName(cryptoKey.getKeyName())
                .algorithm(cryptoKey.getAlgorithm())
                .keySize(cryptoKey.getKeySize())
                .publicKeyPEM(cryptoKey.getPublicKeyPEM())
                .format("PEM")
                .build();
    }

    /**
     * Export public key in Base64 format
     */
    public PublicKeyExportResponse exportPublicKeyAsBase64(Long keyId) {
        log.info("Exporting public key as Base64 for ID: {}", keyId);

        CryptoKey cryptoKey = cryptoKeyRepository.findById(keyId)
                .orElseThrow(() -> new CryptoException("Key not found with ID: " + keyId));

        String base64 = Base64.encodeBase64String(cryptoKey.getPublicKeyPEM().getBytes());

        return PublicKeyExportResponse.builder()
                .keyId(cryptoKey.getId())
                .keyName(cryptoKey.getKeyName())
                .algorithm(cryptoKey.getAlgorithm())
                .keySize(cryptoKey.getKeySize())
                .publicKeyPEM(base64)
                .format("BASE64")
                .build();
    }

    /**
     * Export private key in PEM format (with security warning)
     */
    public PrivateKeyExportResponse exportPrivateKey(Long keyId) {
        log.warn("⚠️ Private key export requested for ID: {}", keyId);

        CryptoKey cryptoKey = cryptoKeyRepository.findById(keyId)
                .orElseThrow(() -> new CryptoException("Key not found with ID: " + keyId));

        return PrivateKeyExportResponse.builder()
                .keyId(cryptoKey.getId())
                .keyName(cryptoKey.getKeyName())
                .algorithm(cryptoKey.getAlgorithm())
                .keySize(cryptoKey.getKeySize())
                .privateKeyPEM(cryptoKey.getPrivateKeyPEM())
                .format("PEM")
                .warning("⚠️ SECURITY WARNING: Private key exported. Keep it confidential!")
                .build();
    }

    /**
     * Delete key (soft delete by marking as revoked)
     */
    public void revokeKey(Long keyId) {
        log.warn("Revoking key with ID: {}", keyId);

        CryptoKey cryptoKey = cryptoKeyRepository.findById(keyId)
                .orElseThrow(() -> new CryptoException("Key not found with ID: " + keyId));

        cryptoKey.setKeyStatus("REVOKED");
        cryptoKeyRepository.save(cryptoKey);

        log.info("✓ Key revoked: {}", keyId);
    }

    /**
     * Get key details by name
     */
    public KeyResponse getKeyByName(String keyName) {
        log.info("Fetching key by name: {}", keyName);

        CryptoKey cryptoKey = cryptoKeyRepository.findByKeyName(keyName)
                .orElseThrow(() -> new CryptoException("Key not found with name: " + keyName));

        return convertToResponse(cryptoKey);
    }

    /**
     * Convert entity to DTO
     */
    private KeyResponse convertToResponse(CryptoKey cryptoKey) {
        return KeyResponse.builder()
                .id(cryptoKey.getId())
                .keyName(cryptoKey.getKeyName())
                .algorithm(cryptoKey.getAlgorithm())
                .keySize(cryptoKey.getKeySize())
                .keyStatus(cryptoKey.getKeyStatus())
                .createdAt(cryptoKey.getCreatedAt())
                .updatedAt(cryptoKey.getUpdatedAt())
                .description(cryptoKey.getDescription())
                .build();
    }
}