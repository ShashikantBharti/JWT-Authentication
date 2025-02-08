package com.neotech.auth.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * Utility class for handling JSON Web Tokens (JWT). This component provides methods
 * for generating, validating, and extracting information (specifically, the email) from JWTs.
 * It uses a secret key to sign and verify the tokens.
 *
 * **Security Warning:** The `SECRET_KEY` should be stored securely (e.g., using environment variables
 * or a dedicated secrets management system) and should be a long, randomly generated string.  Never
 * hardcode a secret key directly in the source code in a production environment.
 */
@Component
public class JwtUtil {
    /**
     * The secret key used to sign and verify JWTs.  **Important:  This is a highly sensitive value
     * and should never be hardcoded in a production environment.  Store it securely (e.g., environment
     * variable, secrets management system).**  A strong, randomly generated key is essential for the
     * security of your JWT implementation.
     */
    private static final String SECRET_KEY = "asjdhskjhfskdjhfdskfuwerioweuroieuhsjdkbdskvbjkhfoiewfhsfhsdhfiowefofds";
    /**
     * The expiration time for JWTs, in milliseconds.  Currently set to 1 day.
     */
    private static final long EXPIRATION_TIME = 24 * 60 * 60 * 1000; // 1 Day

    /**
     * Generates a JWT token for the given email address.  The token includes the email as the
     * subject, the issue date, and the expiration date.
     *
     * @param email The email address to include as the subject of the JWT.
     * @return The generated JWT token.
     */
    public String generateToken(String email) {
        return JWT.create()
                .withSubject(email)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(Algorithm.HMAC256(SECRET_KEY));
    }

    /**
     * Validates the given JWT token.  It verifies the token's signature against the secret key
     * and checks if the token has expired.
     *
     * @param token The JWT token to validate.
     * @return {@code true} if the token is valid, {@code false} otherwise.
     */
    public boolean validateToken(String token) {
        try {
            JWT.require(Algorithm.HMAC256(SECRET_KEY)).build().verify(token);
            return true;
        } catch (JWTVerificationException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Extracts the email address from the given JWT token.  This method assumes that the email
     * address is stored in the "subject" claim of the token.
     *
     * @param token The JWT token to extract the email from.
     * @return The email address extracted from the token's subject claim.
     */
    public String extractEmail(String token) {
        return JWT.require(Algorithm.HMAC256(SECRET_KEY)).build().verify(token).getSubject();
    }
}
