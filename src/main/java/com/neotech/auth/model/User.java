package com.neotech.auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Set;


/**
 * Represents a user in the system.  This entity is stored in MongoDB
 * in the "users" collection.  It encapsulates user credentials,
 * identifying information, and authorization roles.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "users")
public class User {
    /**
     * The unique identifier for the user.  This is automatically
     * generated by MongoDB.
     */
    @Id
    private String id;
    private String username;
    private String email;
    /**
     * The user's password.  **Important:** This should *never* be
     * stored in plain text.  Always use a strong hashing algorithm
     * (like bcrypt or Argon2) with a salt.
     */
    private String password;
    /**
     * The set of roles assigned to the user.  Roles determine the
     * user's authorization level within the application.  Examples:
     * "USER", "ADMIN".  Using a `Set` ensures that a user cannot
     * have duplicate roles.
     */
    private Set<String> role; // Roles: USER, ADMIN
}
