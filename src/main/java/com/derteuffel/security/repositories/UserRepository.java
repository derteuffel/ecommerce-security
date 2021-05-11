package com.derteuffel.security.repositories;

import com.derteuffel.security.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsernameOrEmail(String username, String email);

    User findByCode(String code);

    Boolean existsByEmail(String email);
    Boolean existsByUsername(String username);
}
