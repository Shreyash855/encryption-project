package com.crypto.encryption.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "encrypted_files")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EncryptedFile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String originalFilename;

    @Column(nullable = false)
    private String encryptedFilename;

    @Column(nullable = false)
    private Long keyId;

    @Column(nullable = false)
    private Long fileSize;

    @Column(nullable = false)
    private Long encryptedSize;

    @Column(nullable = false)
    private String fileType;

    @Column(nullable = false)
    private String encryptionStatus = "ENCRYPTED";

    @Lob
    @Column(nullable = false, columnDefinition = "LONGBLOB")
    private byte[] encryptedData;

    @Lob
    @Column(nullable = false, columnDefinition = "LONGBLOB")
    private byte[] encryptedAESKey;

    @Column(length = 500)
    private String description;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private LocalDateTime updatedAt;
}