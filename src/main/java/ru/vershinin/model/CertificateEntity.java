package ru.vershinin.model;

import lombok.Data;

import javax.persistence.*;

@Entity
@Table(name = "certificate")
@Data
public class CertificateEntity {
    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name")
    private String name;

    @Column(name = "private_key", length = 2048)
    private byte[] privateKey;

    @Column(name = "certificate", length = 2048)
    private byte[] certificate;

    @Column(nullable = false)
    private boolean revoked;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }


}
