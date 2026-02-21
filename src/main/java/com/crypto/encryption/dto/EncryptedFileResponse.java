package com.crypto.encryption.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EncryptedFileResponse {

    private Long id;
    private String originalFilename;
    private String encryptedFilename;
    private Long keyId;
    private Long fileSize;
    private Long encryptedSize;
    private String fileType;
    private String encryptionStatus;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String description;
}