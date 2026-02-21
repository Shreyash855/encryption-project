package com.crypto.encryption.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PublicKeyExportResponse {

    private Long keyId;
    private String keyName;
    private String algorithm;
    private Integer keySize;
    private String publicKeyPEM;
    private String format; // PEM, BASE64
}