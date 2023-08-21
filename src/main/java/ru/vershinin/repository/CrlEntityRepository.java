package ru.vershinin.repository;

import ru.vershinin.model.CrlEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CrlEntityRepository extends JpaRepository<CrlEntity, Long> {
    CrlEntity findByName(String name);

}