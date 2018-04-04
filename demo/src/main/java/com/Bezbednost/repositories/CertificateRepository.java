package com.Bezbednost.repositories;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.Bezbednost.components.MyCertificate;

@Repository
public interface CertificateRepository extends CrudRepository<MyCertificate, Integer> {

}
