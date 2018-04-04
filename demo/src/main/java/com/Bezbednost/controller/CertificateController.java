package com.Bezbednost.controller;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.Bezbednost.components.CertificateGenerator;
import com.Bezbednost.components.Issuer;
import com.Bezbednost.components.KeyStoreWriter;
import com.Bezbednost.components.MyCertificate;
import com.Bezbednost.components.Subject;
import com.Bezbednost.repositories.CertificateRepository;
import com.Bezbednost.service.CertificateService;





@Controller
public class CertificateController {
	
	@Autowired
	private CertificateRepository cr;
	private String pass = "123";
	@Autowired
	CertificateService service;
	
	@RequestMapping(value="/root",method = RequestMethod.POST)
	public ModelAndView addSelfSigned(@RequestParam("date2") String validTo,@RequestParam("date1") String validFrom,@RequestParam("serialNumber") String serialNumber, @RequestParam("pwd") String password,@RequestParam("cn") String cn, @RequestParam("ou") String ou, @RequestParam("on") String o, @RequestParam("ln") String l, @RequestParam("sn") String st, @RequestParam("c") String c, @RequestParam("e") String e){
		KeyPair keyPairIssuer = generateKeyPair();
		Subject subject = generateSubjectData(validFrom,validTo,serialNumber,cn,ou,o,l,st,c,e);
		service.addSelfSigned(subject,serialNumber,password); 
		System.out.println("OK");
		return new ModelAndView("redirect:" + "index.html");
		
		
	}
	@RequestMapping(value = "/CA", method = RequestMethod.POST)
	public ResponseEntity<?> addCA(@RequestParam("date2") String validTo,@RequestParam("date1") String validFrom,@RequestParam(value="endUser",required=false) String endUser,@RequestParam("pwd1") String issuerPassword,@RequestParam("issuerSerialNumber") String issuerSerialNumber,@RequestParam("serialNumber") String serialNumber, @RequestParam("pwd") String password,@RequestParam("cn") String cn, @RequestParam("ou") String ou, @RequestParam("on") String o, @RequestParam("ln") String l, @RequestParam("sn") String st, @RequestParam("c") String c, @RequestParam("e") String e) {
		Subject subject = generateSubjectData(validFrom,validTo,serialNumber,cn,ou,o,l,st,c,e);
		boolean isCa = true;
		if(endUser != null) isCa = false;
		if(service.addSigned(subject, serialNumber, password, issuerSerialNumber, issuerPassword,isCa) != null)
		return new ResponseEntity<>(HttpStatus.OK);
		else return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
	}
	@RequestMapping(value = "/getCert", method = RequestMethod.GET)
	public ResponseEntity<?> getCertificate(@RequestParam("serialNumber") String id){
		X509Certificate cert = (X509Certificate)service.get(id);
		HashMap<String, String> map = new HashMap<>();
		map.put("Issuer", cert.getIssuerX500Principal().getName());
		map.put("Subject", cert.getSubjectX500Principal().getName());
		map.put("Od", cert.getNotBefore().toString());
		map.put("Do", cert.getNotAfter().toString());
		return new ResponseEntity<>(map, HttpStatus.OK);
	}
	@RequestMapping(value = "/revokeCert", method = RequestMethod.POST)
	public ResponseEntity<?> revokeCertificate(@RequestParam("serialNumber") String serialNumber,@RequestParam("issuerAlias") String issuerAlias,@RequestParam("issuerPassword") String issuerPassword){
		try {
			service.revoke(serialNumber, issuerAlias, issuerPassword);
		} catch (CRLException | OperatorCreationException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new ResponseEntity<>(HttpStatus.OK);
	}
	@RequestMapping(value = "/checkCert", method = RequestMethod.GET)
	public ResponseEntity<?> checkCertificate(@RequestParam("serialNumber") String serialNumber){
		if(service.checkStatus(serialNumber))
		return new ResponseEntity<>(HttpStatus.OK);
		else return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
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
	private Subject generateSubjectData(String validFrom, String validTo,String serial, String cn, String ou, String o, String l, String st, String c, String e) {
		try {
			KeyPair keyPairSubject = generateKeyPair();
			
			//Datumi od kad do kad vazi sertifikat
			SimpleDateFormat iso8601Formater = new SimpleDateFormat("yyyy-MM-dd");
			Date startDate = iso8601Formater.parse(validFrom);
			Date endDate = iso8601Formater.parse(validTo);
			
			//Serijski broj sertifikata
			String sn=serial;
			//klasa X500NameBuilder pravi X500Name objekat koji predstavlja podatke o vlasniku
			X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
			builder.addRDN(BCStyle.CN, cn);
		    builder.addRDN(BCStyle.O, o);
		    builder.addRDN(BCStyle.OU, ou);
		    builder.addRDN(BCStyle.C, c);
		    builder.addRDN(BCStyle.E, e);
		    builder.addRDN(BCStyle.L, l);
		    builder.addRDN(BCStyle.ST, st);
		    //UID (USER ID) je ID korisnika
		    builder.addRDN(BCStyle.UID, "654321");
		    
		    //Kreiraju se podaci za sertifikat, sto ukljucuje:
		    // - javni kljuc koji se vezuje za sertifikat
		    // - podatke o vlasniku
		    // - serijski broj sertifikata
		    // - od kada do kada vazi sertifikat
		    return new Subject(keyPairSubject.getPublic(), builder.build(), sn, startDate, endDate);
		} catch (ParseException ex) {
			ex.printStackTrace();
		}
		return null;
	}
	private Issuer generateIssuerData(PrivateKey issuerKey,String cn, String ou, String o, String l, String st, String c, String e) {
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
	    builder.addRDN(BCStyle.CN, cn);
	    builder.addRDN(BCStyle.O, o);
	    builder.addRDN(BCStyle.OU, ou);
	    builder.addRDN(BCStyle.C, c);
	    builder.addRDN(BCStyle.E, e);
	    builder.addRDN(BCStyle.L, l);
	    builder.addRDN(BCStyle.ST, st);
	    //UID (USER ID) je ID korisnika
	    builder.addRDN(BCStyle.UID, "654321");

		//Kreiraju se podaci za issuer-a, sto u ovom slucaju ukljucuje:
	    // - privatni kljuc koji ce se koristiti da potpise sertifikat koji se izdaje
	    // - podatke o vlasniku sertifikata koji izdaje nov sertifikat
		return new Issuer(issuerKey, builder.build());
	}

}
