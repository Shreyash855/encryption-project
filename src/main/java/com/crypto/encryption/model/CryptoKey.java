package com.crypto.encryption.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "crypto_keys", indexes = {
        @Index(name = "idx_key_name", columnList = "key_name", unique = true),
        @Index(name = "idx_created_at", columnList = "created_at")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CryptoKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String keyName;

    @Column(nullable = false)
    private String algorithm;

    @Column(nullable = false)
    private Integer keySize;

    @Lob
    @Column(nullable = false, columnDefinition = "LONGTEXT")
    private String publicKeyPEM;

    @Lob
    @Column(nullable = false, columnDefinition = "LONGTEXT")
    private String privateKeyPEM;

    @Column(nullable = false)
    private String keyStatus; // ACTIVE, REVOKED, EXPIRED

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column
    private LocalDateTime updatedAt;

    @Column
    private String description;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
        this.keyStatus = "ACTIVE";
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}