package com.crypto.encryption.controller;

import com.crypto.encryption.dto.KeyGenerationRequest;
import com.crypto.encryption.dto.KeyResponse;
import com.crypto.encryption.dto.PrivateKeyExportResponse;
import com.crypto.encryption.dto.PublicKeyExportResponse;
import com.crypto.encryption.service.KeyManagementService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/keys")
@Slf4j
public class KeyManagementController {

    private final KeyManagementService keyManagementService;

    public KeyManagementController(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    /**
     * Generate new key pair
     * POST /api/keys/generate
     */
    @PostMapping("/generate")
    public ResponseEntity<?> generateKeyPair(@Valid @RequestBody KeyGenerationRequest request) {
        log.info("📌 Generating new key pair: {}", request.getKeyName());

        try {
            KeyResponse response = keyManagementService.createKeyPair(request);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("message", "Key pair generated successfully");
            result.put("data", response);

            return ResponseEntity.status(HttpStatus.CREATED).body(result);
        } catch (Exception e) {
            log.error("✗ Error generating key pair", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    /**
     * Get all active keys
     * GET /api/keys
     */
    @GetMapping
    public ResponseEntity<?> getAllKeys() {
        log.info("📌 Fetching all active keys");

        try {
            List<KeyResponse> keys = keyManagementService.getAllActiveKeys();

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("count", keys.size());
            result.put("data", keys);

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("✗ Error fetching keys", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    /**
     * Get key by ID
     * GET /api/keys/{id}
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> getKeyById(@PathVariable Long id) {
        log.info("📌 Fetching key by ID: {}", id);

        try {
            KeyResponse response = keyManagementService.getKeyById(id);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("data", response);

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("✗ Error fetching key", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
    }

    /**
     * Export public key (PEM format)
     * GET /api/keys/{id}/public
     */
    @GetMapping("/{id}/public")
    public ResponseEntity<?> exportPublicKey(@PathVariable Long id) {
        log.info("📌 Exporting public key for ID: {}", id);

        try {
            PublicKeyExportResponse response = keyManagementService.exportPublicKey(id);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("message", "Public key exported successfully");
            result.put("data", response);

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("✗ Error exporting public key", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
    }

    /**
     * Export public key (Base64 format)
     * GET /api/keys/{id}/public/base64
     */
    @GetMapping("/{id}/public/base64")
    public ResponseEntity<?> exportPublicKeyBase64(@PathVariable Long id) {
        log.info("📌 Exporting public key as Base64 for ID: {}", id);

        try {
            PublicKeyExportResponse response = keyManagementService.exportPublicKeyAsBase64(id);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("message", "Public key exported as Base64 successfully");
            result.put("data", response);

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("✗ Error exporting public key", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
    }

    /**
     * Export private key (PEM format) - SENSITIVE!
     * GET /api/keys/{id}/private
     */
    @GetMapping("/{id}/private")
    public ResponseEntity<?> exportPrivateKey(@PathVariable Long id) {
        log.warn("⚠️ SECURITY ALERT: Private key export requested for ID: {}", id);

        try {
            PrivateKeyExportResponse response = keyManagementService.exportPrivateKey(id);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("message", response.getWarning());
            result.put("data", response);

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("✗ Error exporting private key", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
    }

    /**
     * Revoke key (soft delete)
     * DELETE /api/keys/{id}
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> revokeKey(@PathVariable Long id) {
        log.warn("Revoking key with ID: {}", id);

        try {
            keyManagementService.revokeKey(id);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("message", "Key revoked successfully");

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("✗ Error revoking key", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
    }
}