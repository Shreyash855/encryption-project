package com.crypto.encryption.service;

import com.crypto.encryption.dto.EncryptedFileResponse;
import com.crypto.encryption.dto.FileDecryptionResponse;
import com.crypto.encryption.model.CryptoKey;
import com.crypto.encryption.model.EncryptedFile;
import com.crypto.encryption.repository.CryptoKeyRepository;
import com.crypto.encryption.repository.EncryptedFileRepository;
import com.crypto.encryption.util.HybridEncryptionUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
public class FileEncryptionService {

    private final EncryptedFileRepository encryptedFileRepository;
    private final CryptoKeyRepository cryptoKeyRepository;
    private final HybridEncryptionUtil hybridEncryptionUtil;

    public FileEncryptionService(
            EncryptedFileRepository encryptedFileRepository,
            CryptoKeyRepository cryptoKeyRepository,
            HybridEncryptionUtil hybridEncryptionUtil) {
        this.encryptedFileRepository = encryptedFileRepository;
        this.cryptoKeyRepository = cryptoKeyRepository;
        this.hybridEncryptionUtil = hybridEncryptionUtil;
    }

    /**
     * Encrypt and save file using hybrid encryption
     */
    public EncryptedFileResponse encryptAndSaveFile(MultipartFile file, Long keyId, String description) throws Exception {
        log.info("📁 Processing file upload: {}", file.getOriginalFilename());
        log.info("📁 File size: {} bytes", file.getSize());

        // Validate file
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }

        // Get the key
        CryptoKey cryptoKey = cryptoKeyRepository.findById(keyId)
                .orElseThrow(() -> new RuntimeException("Key not found: " + keyId));

        if ("REVOKED".equals(cryptoKey.getKeyStatus())) {
            throw new RuntimeException("Cannot use revoked key for encryption");
        }

        log.info("✓ Found key: {}", cryptoKey.getKeyName());

        // Get file bytes
        byte[] fileData = file.getBytes();

        // Reconstruct public key
        PublicKey publicKey = reconstructPublicKey(cryptoKey.getPublicKeyPEM());

        // Encrypt file using hybrid encryption
        HybridEncryptionUtil.HybridEncryptedData hybridData = hybridEncryptionUtil.encryptFileHybrid(fileData, publicKey);
        log.info("✓ Encrypted file: {} bytes → {} bytes", fileData.length, hybridData.encryptedFile.length);

        // Save to database
        EncryptedFile encryptedFile = new EncryptedFile();
        encryptedFile.setOriginalFilename(file.getOriginalFilename());
        encryptedFile.setEncryptedFilename("ENC_" + UUID.randomUUID() + ".dat");
        encryptedFile.setKeyId(keyId);
        encryptedFile.setFileSize((long) fileData.length);
        encryptedFile.setEncryptedSize((long) hybridData.encryptedFile.length);
        encryptedFile.setFileType(file.getContentType() != null ? file.getContentType() : "application/octet-stream");
        encryptedFile.setEncryptionStatus("ENCRYPTED");
        encryptedFile.setEncryptedData(hybridData.encryptedFile);
        encryptedFile.setEncryptedAESKey(hybridData.encryptedKey);
        encryptedFile.setDescription(description != null ? description : "");

        EncryptedFile saved = encryptedFileRepository.save(encryptedFile);
        log.info("✓ File saved with ID: {}", saved.getId());

        return mapToResponse(saved);
    }

    /**
     * Decrypt file
     */
    public FileDecryptionResponse decryptFile(Long fileId, Long keyId) throws Exception {
        log.info("📁 Decrypting file: {}", fileId);

        // Get encrypted file
        EncryptedFile encryptedFile = encryptedFileRepository.findById(fileId)
                .orElseThrow(() -> new RuntimeException("Encrypted file not found: " + fileId));

        // Get the key
        CryptoKey cryptoKey = cryptoKeyRepository.findById(keyId)
                .orElseThrow(() -> new RuntimeException("Key not found: " + keyId));

        if (!encryptedFile.getKeyId().equals(keyId)) {
            throw new RuntimeException("Key mismatch: File was encrypted with a different key");
        }

        // Reconstruct private key
        PrivateKey privateKey = reconstructPrivateKey(cryptoKey.getPrivateKeyPEM());

        // Decrypt file
        byte[] decryptedData = hybridEncryptionUtil.decryptFileHybrid(
                encryptedFile.getEncryptedData(),
                encryptedFile.getEncryptedAESKey(),
                privateKey
        );

        log.info("✓ File decrypted: {} bytes", decryptedData.length);

        return new FileDecryptionResponse(
                encryptedFile.getId(),
                encryptedFile.getOriginalFilename(),
                encryptedFile.getFileType(),
                encryptedFile.getFileSize(),
                decryptedData,
                "File decrypted successfully"
        );
    }

    /**
     * Get all encrypted files
     */
    public List<EncryptedFileResponse> getAllEncryptedFiles() {
        return encryptedFileRepository.findAll()
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get files by key ID
     */
    public List<EncryptedFileResponse> getFilesByKeyId(Long keyId) {
        return encryptedFileRepository.findByKeyId(keyId)
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get file by ID
     */
    public EncryptedFileResponse getEncryptedFileById(Long id) {
        return encryptedFileRepository.findById(id)
                .map(this::mapToResponse)
                .orElseThrow(() -> new RuntimeException("File not found: " + id));
    }

    /**
     * Delete file
     */
    public void deleteEncryptedFile(Long id) {
        if (!encryptedFileRepository.existsById(id)) {
            throw new RuntimeException("File not found: " + id);
        }
        encryptedFileRepository.deleteById(id);
        log.info("✓ File deleted: {}", id);
    }

    /**
     * Map entity to DTO
     */
    private EncryptedFileResponse mapToResponse(EncryptedFile file) {
        return EncryptedFileResponse.builder()
                .id(file.getId())
                .originalFilename(file.getOriginalFilename())
                .encryptedFilename(file.getEncryptedFilename())
                .keyId(file.getKeyId())
                .fileSize(file.getFileSize())
                .encryptedSize(file.getEncryptedSize())
                .fileType(file.getFileType())
                .encryptionStatus(file.getEncryptionStatus())
                .description(file.getDescription() != null ? file.getDescription() : "")
                .createdAt(file.getCreatedAt())
                .updatedAt(file.getUpdatedAt())
                .build();
    }

    /**
     * Reconstruct private key from PEM - FIXED VERSION
     */
    private PrivateKey reconstructPrivateKey(String privateKeyPEM) throws Exception {
        log.debug("Reconstructing private key from PEM...");

        // Remove PEM headers
        String privateKeyContent = privateKeyPEM
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .trim();  // ✅ Add trim()

        // Remove all whitespace (spaces, newlines, tabs, etc.)
        privateKeyContent = privateKeyContent.replaceAll("\\s+", "");

        log.debug("Private key content length: {}", privateKeyContent.length());

        try {
            // Decode from Base64
            byte[] decodedKey = Base64.getDecoder().decode(privateKeyContent);
            log.debug("Decoded key length: {} bytes", decodedKey.length);

            // Create KeySpec
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedKey);

            // Generate PrivateKey
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(spec);

            log.debug("✓ Private key reconstructed successfully");
            return privateKey;
        } catch (IllegalArgumentException e) {
            log.error("❌ Invalid Base64 format: {}", e.getMessage());
            log.error("❌ Key content (first 100 chars): {}", privateKeyContent.substring(0, Math.min(100, privateKeyContent.length())));
            throw new RuntimeException("Invalid private key format: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("❌ Error reconstructing private key: {}", e.getMessage());
            throw new RuntimeException("Failed to reconstruct private key: " + e.getMessage(), e);
        }
    }

    /**
     * Reconstruct public key from PEM - FIXED VERSION
     */
    private PublicKey reconstructPublicKey(String publicKeyPEM) throws Exception {
        log.debug("Reconstructing public key from PEM...");

        // Remove PEM headers
        String publicKeyContent = publicKeyPEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .trim();  //  Add trim()

        // Remove all whitespace
        publicKeyContent = publicKeyContent.replaceAll("\\s+", "");

        log.debug("Public key content length: {}", publicKeyContent.length());

        try {
            // Decode from Base64
            byte[] decodedKey = Base64.getDecoder().decode(publicKeyContent);
            log.debug("Decoded key length: {} bytes", decodedKey.length);

            // Create KeySpec
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);

            // Generate PublicKey
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(spec);

            log.debug("✓ Public key reconstructed successfully");
            return publicKey;
        } catch (IllegalArgumentException e) {
            log.error("Invalid Base64 format: {}", e.getMessage());
            log.error("Key content (first 100 chars): {}", publicKeyContent.substring(0, Math.min(100, publicKeyContent.length())));
            throw new RuntimeException("Invalid public key format: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Error reconstructing public key: {}", e.getMessage());
            throw new RuntimeException("Failed to reconstruct public key: " + e.getMessage(), e);
        }
    }
}