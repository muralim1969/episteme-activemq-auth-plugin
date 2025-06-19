package org.episteme.activemq.auth.core;

public interface AuthValidator {
    /**
     * Validates the incoming request context.
     * @param context context with connection and identity information
     * @return an AuthenticatedUser if validation succeeds
     * @throws AuthException if authentication fails
     */
    AuthenticatedUser validate(AuthRequestContext context) throws AuthException;
}
