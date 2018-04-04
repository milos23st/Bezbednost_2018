package com.Bezbednost.components;

import java.security.cert.X509Certificate;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;



@Entity
@Table(name = "Sertifikat")
public class MyCertificate {
	
	private X509Certificate certificate;
	private boolean CA;
	private int uid;
	
	public MyCertificate(){}
	
	public MyCertificate(X509Certificate cert, boolean ca){
		certificate = cert;
		CA = ca;
		
	}
	@Column(name = "sertifikat", length = 1100 )
	public X509Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}
	@Column(name = "ca")
	public boolean isCA() {
		return CA;
	}

	public void setCA(boolean cA) {
		CA = cA;
	}
	@Id
	@GeneratedValue
	@NotNull
	@Column
	public int getUid() {
		return uid;
	}

	public void setUid(int uid) {
		this.uid = uid;
	}

}
