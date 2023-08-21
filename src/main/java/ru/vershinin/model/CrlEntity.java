package ru.vershinin.model;

import lombok.Data;

import javax.persistence.*;

@Entity
@Data
public class CrlEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;


    @Column(nullable = false, unique = true)
    private String name;

    @Column(nullable = false)
    private byte[] crl;


}






