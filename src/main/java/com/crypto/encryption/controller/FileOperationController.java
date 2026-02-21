package com.crypto.encryption.controller;

import com.crypto.encryption.dto.EncryptedFileResponse;
import com.crypto.encryption.dto.FileDecryptionResponse;
import com.crypto.encryption.service.FileEncryptionService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/files")
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class FileOperationController {

    private final FileEncryptionService fileEncryptionService;

    public FileOperationController(FileEncryptionService fileEncryptionService) {
        this.fileEncryptionService = fileEncryptionService;
    }

    /**
     * Encrypt and upload file
     * POST /files/encrypt
     */
    @PostMapping("/encrypt")
    public ResponseEntity<?> encryptFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("keyId") Long keyId,
            @RequestParam(value = "description", required = false) String description) {

        log.info("📌 File encryption request: {}, KeyID: {}", file.getOriginalFilename(), keyId);

        try {
            EncryptedFileResponse response = fileEncryptionService.encryptAndSaveFile(file, keyId, description);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("message", "File encrypted and saved successfully");
            result.put("data", response);

            return ResponseEntity.status(HttpStatus.CREATED).body(result);
        } catch (Exception e) {
            log.error("✗ Error encrypting file", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    /**
     * Decrypt file and download
     * POST /files/{fileId}/decrypt
     */
    @PostMapping("/{fileId}/decrypt")
    public ResponseEntity<?> decryptFile(
            @PathVariable Long fileId,
            @RequestParam("keyId") Long keyId) {

        log.info("📌 File decryption request: FileID: {}, KeyID: {}", fileId, keyId);

        try {
            FileDecryptionResponse response = fileEncryptionService.decryptFile(fileId, keyId);

            // Return decrypted file for download
            String filename = response.getOriginalFilename();

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            ContentDisposition.attachment()
                                    .filename(filename)
                                    .build()
                                    .toString())
                    .header(HttpHeaders.CONTENT_TYPE, response.getFileType() != null ? response.getFileType() : "application/octet-stream")
                    .body(response.getDecryptedData());
        } catch (Exception e) {
            log.error("✗ Error decrypting file", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    /**
     * Get decryption details (without downloading)
     * GET /files/{fileId}/decrypt-info
     */
    @GetMapping("/{fileId}/decrypt-info")
    public ResponseEntity<?> getDecryptionInfo(
            @PathVariable Long fileId,
            @RequestParam("keyId") Long keyId) {

        log.info("📌 Getting decryption info for FileID: {}", fileId);

        try {
            FileDecryptionResponse response = fileEncryptionService.decryptFile(fileId, keyId);

            // Return info without actual data
            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("data", Map.of(
                    "fileId", response.getFileId(),
                    "originalFilename", response.getOriginalFilename(),
                    "fileType", response.getFileType(),
                    "originalFileSize", response.getOriginalFileSize(),
                    "message", response.getMessage()
            ));

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("✗ Error getting decryption info", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
    }

    /**
     * Get all encrypted files
     * GET /files
     */
    @GetMapping
    public ResponseEntity<?> getAllFiles() {
        log.info("📌 Fetching all encrypted files");

        try {
            List<EncryptedFileResponse> files = fileEncryptionService.getAllEncryptedFiles();

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("count", files.size());
            result.put("data", files);

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("✗ Error fetching files", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    /**
     * Get files by key ID
     * GET /files/by-key/{keyId}
     */
    @GetMapping("/by-key/{keyId}")
    public ResponseEntity<?> getFilesByKeyId(@PathVariable Long keyId) {
        log.info("📌 Fetching files by key ID: {}", keyId);

        try {
            List<EncryptedFileResponse> files = fileEncryptionService.getFilesByKeyId(keyId);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("count", files.size());
            result.put("data", files);

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("✗ Error fetching files", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    /**
     * Get encrypted file by ID (metadata only)
     * GET /files/{fileId}
     */
    @GetMapping("/{fileId}")
    public ResponseEntity<?> getFileById(@PathVariable Long fileId) {
        log.info("📌 Fetching encrypted file by ID: {}", fileId);

        try {
            EncryptedFileResponse response = fileEncryptionService.getEncryptedFileById(fileId);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("data", response);

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("✗ Error fetching file", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
    }

    /**
     * Delete encrypted file
     * DELETE /files/{fileId}
     */
    @DeleteMapping("/{fileId}")
    public ResponseEntity<?> deleteFile(@PathVariable Long fileId) {
        log.warn("Deleting encrypted file with ID: {}", fileId);

        try {
            fileEncryptionService.deleteEncryptedFile(fileId);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("message", "File deleted successfully");

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("✗ Error deleting file", e);

            Map<String, Object> error = new HashMap<>();
            error.put("status", "ERROR");
            error.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
    }
}