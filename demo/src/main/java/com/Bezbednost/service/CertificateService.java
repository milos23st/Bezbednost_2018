package com.Bezbednost.service;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;

import org.bouncycastle.operator.OperatorCreationException;

import com.Bezbednost.components.Subject;



public interface CertificateService {
	Certificate addSelfSigned(Subject subject,
			String alias,
			String password);
	Certificate addSigned(Subject subject,
			String alias,
			String password,
			String issuerAlias,
			String issuerPassword,
			boolean endUser
			);
	
	Certificate get(String serialNumber);
	boolean checkStatus(String serialNumber);
	Certificate revoke(String serialNumber, 
			String issuerAlias, 
			String issuerPassword) throws CRLException, IOException, OperatorCreationException;

}
