package com.neotech.auth.repository;

import com.neotech.auth.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

/**
 * Repository interface for managing {@link User} entities in MongoDB.
 * Extends Spring Data MongoDB's {@link MongoRepository} to provide basic CRUD operations
 * and additional query methods specific to the {@link User} entity.
 */
public interface UserRepository extends MongoRepository<User, String> {
    /**
     * Retrieves a user from the database based on their email address.
     *
     * @param email The email address of the user to find.
     * @return An {@link Optional} containing the {@link User} if found, or empty if no user exists
     *         with the given email.  Using {@link Optional} handles the case where a user with
     *         the specified email does not exist.
     */
    Optional<User> findByEmail(String email);
    /**
     * Checks if a user exists in the database with the given email address.
     *
     * @param email The email address to check for existence.
     * @return {@code true} if a user with the given email exists, {@code false} otherwise.
     */
    boolean existsByEmail(String email);
}
