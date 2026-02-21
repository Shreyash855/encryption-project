package com.crypto.encryption.repository;

import com.crypto.encryption.model.EncryptedFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface EncryptedFileRepository extends JpaRepository<EncryptedFile, Long> {

    Optional<EncryptedFile> findByOriginalFilename(String originalFilename);

    @Query("SELECT f FROM EncryptedFile f WHERE f.keyId = :keyId ORDER BY f.createdAt DESC")
    List<EncryptedFile> findByKeyId(@Param("keyId") Long keyId);

    @Query("SELECT f FROM EncryptedFile f ORDER BY f.createdAt DESC")
    List<EncryptedFile> findAllOrderByCreatedAtDesc();
}