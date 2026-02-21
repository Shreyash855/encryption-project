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
public class KeyResponse {

    private Long id;
    private String keyName;
    private String algorithm;
    private Integer keySize;
    private String keyStatus;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String description;
}