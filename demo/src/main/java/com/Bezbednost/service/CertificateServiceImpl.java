package com.Bezbednost.service;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.Bezbednost.components.CertificateGenerator;
import com.Bezbednost.components.Issuer;
import com.Bezbednost.components.KeyStoreReader;
import com.Bezbednost.components.KeyStoreWriter;
import com.Bezbednost.components.Subject;





@Service
public class CertificateServiceImpl implements CertificateService {
	@Autowired
	private CertificateGenerator cg;
	@Autowired
	private KeyStoreWriter keyStoreWriter;
	@Autowired
	private KeyStoreReader keyStoreReader;
	private X509CRL crl;
	
	@Value("${keyStore.file}")
	private String file;
	@Value("${keyStore.password}")
	private String pass;
	
	@Override
	public Certificate addSelfSigned(Subject subject, String alias, String password) {
		KeyPair keyPairSubject = generateKeyPair();
		subject.setPublicKey(keyPairSubject.getPublic());
		
		Issuer issuer = new Issuer(keyPairSubject.getPrivate(), subject.getX500name());
		
		X509Certificate cert = cg.generateCertificate(subject, issuer, true);
		keyStoreWriter.write(alias, keyPairSubject.getPrivate(), password.toCharArray(), cert);
		return cert;
		
	}

	@Override
	public Certificate addSigned(Subject subject, String alias, String password, String issuerAlias,
			String issuerPassword, boolean endUser) {
		KeyPair keyPairSubject = generateKeyPair();
		subject.setPublicKey(keyPairSubject.getPublic());
		
		Issuer issuer = keyStoreReader.readIssuerFromStore(file, 
				issuerAlias, 
				pass.toCharArray(), 
				issuerPassword.toCharArray());
		X509Certificate check = (X509Certificate)keyStoreReader.readCertificate(file, pass, issuerAlias);
		System.out.println(check.getBasicConstraints());
		if(check.getBasicConstraints()!=-1){
		System.out.println("CA");
		X509Certificate cert = cg.generateCertificate(subject, issuer, endUser);
		keyStoreWriter.write(alias, keyPairSubject.getPrivate(), password.toCharArray(), cert);
		return cert;
		}
		else return null;
	}

	
	@Override
	public Certificate get(String serial) {
		Certificate cert = keyStoreReader.readCertificate(file, pass, serial);
		return cert;
	}

	@Override
	public boolean checkStatus(String serialNumber) {
		if(crl.getRevokedCertificate(((X509Certificate)keyStoreReader.readCertificate(file,pass, serialNumber)).getSerialNumber()) != null)
			{
			System.out.println("Povucen je");
			return true;
			}
		else{
			System.out.println("Nije povucen");
			return false;
		}
	}

	@SuppressWarnings("deprecation")
	@Override
	public Certificate revoke(String serialNumber, String issuerAlias, String issuerPassword)
			throws CRLException, IOException, OperatorCreationException {
		X509Certificate cert = (X509Certificate) keyStoreReader.readCertificate(file,pass, serialNumber);
		X509Certificate issuerCert = (X509Certificate) keyStoreReader.readCertificate(file,pass, issuerAlias);
		PrivateKey pk = keyStoreReader.readPrivateKey(file, pass, issuerAlias, issuerPassword);
		
		X509V2CRLGenerator   crlGen = new X509V2CRLGenerator();
		Date now = new Date();
		Date nextUpdate = new Date(now.getTime()+20000);
		crlGen.setIssuerDN(issuerCert.getIssuerX500Principal());
		crlGen.setThisUpdate(now);
		crlGen.setNextUpdate(nextUpdate);
		crlGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
			if(crl!=null){
			crlGen.addCRL(crl);
			}
			crlGen.addCRLEntry(cert.getSerialNumber(), now, CRLReason.privilegeWithdrawn);
			try {
				crlGen.addExtension(X509Extensions.AuthorityKeyIdentifier,
				          false, new AuthorityKeyIdentifierStructure(issuerCert));
			} catch (CertificateParsingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			crlGen.addExtension(X509Extensions.CRLNumber,
	                  false, new CRLNumber(new BigInteger("1")));
			try {
				Security.addProvider(new BouncyCastleProvider());
				X509CRL    crl1 = crlGen.generateX509CRL(pk, "BC");
				crl = crl1;
				System.out.println(crl.getRevokedCertificate(cert.getSerialNumber()));
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return null;	
	}
	private KeyPair generateKeyPair() {
        try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); 
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(2048, random);
			return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
        return null;
	}

}
