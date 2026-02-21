package com.crypto.encryption.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class FileDecryptionResponse {
    private Long fileId;
    private String originalFilename;
    private String fileType;
    private Long originalFileSize;
    private byte[] decryptedData;
    private String message;
}