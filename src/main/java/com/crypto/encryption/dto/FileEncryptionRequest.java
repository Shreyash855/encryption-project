package com.crypto.encryption.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FileEncryptionRequest {

    @NotNull(message = "File is required")
    private MultipartFile file;

    @Positive(message = "Key ID must be positive")
    private Long keyId;

    private String description;
}