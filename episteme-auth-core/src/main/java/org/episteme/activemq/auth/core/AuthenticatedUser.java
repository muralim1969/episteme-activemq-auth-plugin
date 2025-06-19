package org.episteme.activemq.auth.core;

import java.util.Map;
import java.util.Set;

public class AuthenticatedUser {
    private final String subject;
    private Set<String> roles;
    private Map<String, String> attributes;
    
    public AuthenticatedUser(String subject)
    {
    	this.subject = subject;
    }

    public AuthenticatedUser(String subject, Set<String> roles, Map<String, String> attributes) {
        this.subject = subject;
        this.roles = roles;
        this.attributes = attributes;
    }

    public String getSubject() { return subject; }
    public Set<String> getRoles() { return roles; }
    public Map<String, String> getAttributes() { return attributes; }

	
}