package com.Bezbednost.components;

import java.security.PrivateKey;

import javax.persistence.Entity;

import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.stereotype.Component;

public class Issuer {
	private X500Name x500name;
	private PrivateKey privateKey;

	public Issuer() {
	}

	public Issuer(PrivateKey privateKey, X500Name x500name) {
		this.privateKey = privateKey;
		this.x500name = x500name;
	}

	public X500Name getX500name() {
		return x500name;
	}

	public void setX500name(X500Name x500name) {
		this.x500name = x500name;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

}
