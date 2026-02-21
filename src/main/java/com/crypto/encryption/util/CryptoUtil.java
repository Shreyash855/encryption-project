package com.crypto.encryption.util;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.StringReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

@Slf4j
public class CryptoUtil {

    private static final String PROVIDER_NAME = "BC";
    private static boolean bcInitialized = false;

    /**
     * Initialize Bouncy Castle Provider
     */
    public static void initializeBouncyCastle() {
        if (!bcInitialized) {
            Security.addProvider(new BouncyCastleProvider());
            bcInitialized = true;
            log.info("✓ Bouncy Castle Provider initialized successfully");
        }
    }

    /**
     * Check if BC is initialized
     */
    public static boolean isBouncyCastleInitialized() {
        return bcInitialized;
    }

    /**
     * Get provider name
     */
    public static String getProviderName() {
        return PROVIDER_NAME;
    }

    /**
     * Convert PEM String to Public Key
     */
    public static PublicKey convertPEMToPublicKey(String publicKeyPEM) throws Exception {
        initializeBouncyCastle();

        try (PEMParser pemParser = new PEMParser(new StringReader(publicKeyPEM))) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(PROVIDER_NAME);

            if (object instanceof org.bouncycastle.cert.X509CertificateHolder) {
                return converter.getPublicKey(
                        ((org.bouncycastle.cert.X509CertificateHolder) object).getSubjectPublicKeyInfo()
                );
            } else if (object instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
                return converter.getPublicKey((org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) object);
            } else {
                throw new Exception("Invalid PEM format for public key");
            }
        }
    }

    /**
     * Convert PEM String to Private Key
     */
    public static PrivateKey convertPEMToPrivateKey(String privateKeyPEM) throws Exception {
        initializeBouncyCastle();

        try (PEMParser pemParser = new PEMParser(new StringReader(privateKeyPEM))) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(PROVIDER_NAME);

            PrivateKeyInfo privateKeyInfo = null;

            if (object instanceof PEMKeyPair) {
                privateKeyInfo = ((PEMKeyPair) object).getPrivateKeyInfo();
            } else if (object instanceof PrivateKeyInfo) {
                privateKeyInfo = (PrivateKeyInfo) object;
            } else {
                throw new Exception("Invalid PEM format for private key");
            }

            return converter.getPrivateKey(privateKeyInfo);
        }
    }
}