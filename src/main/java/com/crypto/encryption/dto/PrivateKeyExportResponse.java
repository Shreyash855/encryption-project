package com.crypto.encryption.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PrivateKeyExportResponse {

    private Long keyId;
    private String keyName;
    private String algorithm;
    private Integer keySize;
    private String privateKeyPEM;
    private String format; // PEM, BASE64
    private String warning; // Security warning
}