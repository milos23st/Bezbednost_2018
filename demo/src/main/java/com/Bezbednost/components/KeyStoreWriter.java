package com.Bezbednost.components;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
@Component
public class KeyStoreWriter {
	//KeyStore je Java klasa za citanje specijalizovanih datoteka koje se koriste za cuvanje kljuceva
		//Tri tipa entiteta koji se obicno nalaze u ovakvim datotekama su:
		// - Sertifikati koji ukljucuju javni kljuc
		// - Privatni kljucevi
		// - Tajni kljucevi, koji se koriste u simetricnima siframa
		private KeyStore keyStore;
		@Value("${keyStore.file}")
		private String keyStoreFile;
		@Value("${keyStore.password}")
		private String keyStorePassword;
		
		public KeyStoreWriter() {
			try {
				keyStore = KeyStore.getInstance("JKS", "SUN");
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			}
		}
		@PostConstruct
		private void init()
		{
			if(new File(keyStoreFile).exists()){
				loadKeyStore(keyStoreFile, keyStorePassword.toCharArray());
			}
			else
				loadKeyStore(null, keyStorePassword.toCharArray());
		}
		
		public void loadKeyStore(String fileName, char[] password) {
			try {
				if(fileName != null) {
					keyStore.load(new FileInputStream(fileName), password);
					System.out.print("Kreiran file " + fileName);
				} else {
					//Ako je cilj kreirati novi KeyStore poziva se i dalje load, pri cemu je prvi parametar null
					keyStore.load(null, password);
					System.out.print("Kreiran file ");
				}
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		public void saveKeyStore(String fileName, char[] password) {
			try {
				keyStore.store(new FileOutputStream(fileName), password);
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		public void write(String alias, PrivateKey privateKey, char[] password, Certificate certificate) {
			try {
				keyStore.setKeyEntry(alias, privateKey, password, new Certificate[] {certificate});
				saveKeyStore(keyStoreFile, keyStorePassword.toCharArray());
				System.out.println("Upisao");
			} catch (KeyStoreException e) {
				e.printStackTrace();
			}
		}

}
