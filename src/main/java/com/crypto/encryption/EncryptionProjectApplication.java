package com.crypto.encryption;

import com.crypto.encryption.util.CryptoUtil;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class EncryptionProjectApplication {

	public static void main(String[] args) {
		// Initialize Bouncy Castle before Spring starts
		CryptoUtil.initializeBouncyCastle();
		SpringApplication.run(EncryptionProjectApplication.class, args);
	}

}
