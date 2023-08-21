package ru.vershinin.repository;

import ru.vershinin.model.CertificateEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateRepository extends JpaRepository<CertificateEntity, Long> {

    CertificateEntity findByCertificate(byte[] certificate);
    CertificateEntity findByName(String name);

    CertificateEntity findFirstByNameEquals(String name);

}
