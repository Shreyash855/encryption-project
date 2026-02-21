package com.crypto.encryption.repository;

import com.crypto.encryption.model.CryptoKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CryptoKeyRepository extends JpaRepository<CryptoKey, Long> {

    Optional<CryptoKey> findByKeyName(String keyName);

    @Query("SELECT k FROM CryptoKey k WHERE k.keyStatus = 'ACTIVE' ORDER BY k.createdAt DESC")
    List<CryptoKey> findAllActiveKeys();

    @Query("SELECT k FROM CryptoKey k WHERE k.algorithm = :algorithm AND k.keyStatus = 'ACTIVE'")
    List<CryptoKey> findByAlgorithmAndActive(@Param("algorithm") String algorithm);
}