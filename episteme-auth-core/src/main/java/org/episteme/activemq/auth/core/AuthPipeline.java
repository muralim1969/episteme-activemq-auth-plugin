package org.episteme.activemq.auth.core;


import java.util.List;

public class AuthPipeline {
    private final List<AuthValidator> validators;    

	public AuthPipeline(List<AuthValidator> validators) {
        this.validators = validators;
    }

    public AuthenticatedUser validate(AuthRequestContext context) throws AuthException {
    	AuthenticatedUser user=null;
        for (AuthValidator validator : validators) {
            user = validator.validate(context);         
        }
        if (user != null) {
            return user;
        }
        throw new AuthException("Authentication failed in all validators");
    }
    
    public List<AuthValidator> getValidators() {
		return validators;
	}
}