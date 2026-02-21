package com.crypto.encryption.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class KeyGenerationRequest {

    @NotBlank(message = "Key name is required")
    private String keyName;

    @Positive(message = "Key size must be positive")
    private Integer keySize;

    private String description;

    private String algorithm;
}