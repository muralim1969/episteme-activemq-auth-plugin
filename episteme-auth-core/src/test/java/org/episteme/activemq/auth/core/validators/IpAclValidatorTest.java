package org.episteme.activemq.auth.core.validators;

import org.episteme.activemq.auth.core.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class IpAclValidatorTest {
	
	 private AuthRequestContext context(String ip) {
	        return new AuthRequestContext() {
	            @Override public String getRemoteAddress() { return ip; }
	            @Override public Optional<String> getJwtToken() { return Optional.empty(); }
	            @Override public String getUsername() { return ""; }
	            @Override public Optional<String> getPassword() { return Optional.empty(); }
	            @Override public Optional<String> getHeader(String key) { return Optional.empty(); }
	            @Override public Optional<java.security.cert.X509Certificate[]> getClientCertificates() { return Optional.empty(); }
				@Override
				public void setClientCertificates(X509Certificate[] clientCertificates) {		}
	        };
	    }
   
    AuthConfigLoader configLoader;
    @BeforeEach
    void setup() throws IOException
    {    	
    	configLoader= new AuthConfigLoader("src/test/resources/ip-acl.json");
    }

    @Test
    public void testIpAllowed() throws Exception {
        IpAclValidator validator = new IpAclValidator(configLoader);
        AuthenticatedUser user = validator.validate(context("192.168.1.10"));
        assertEquals("192.168.1.10", user.getSubject());
    }

    @Test
    public void testIpDenied() throws Exception {
        IpAclValidator validator = new IpAclValidator(configLoader);       
        AuthException ex = assertThrows(AuthException.class, () -> validator.validate(context("192.168.1.5")));
        assertTrue(ex.getMessage().contains("not in allow list"));
    }

    @Test
    public void testMissingIp() throws Exception {
        IpAclValidator validator = new IpAclValidator(configLoader);
        AuthException ex = assertThrows(AuthException.class, () -> validator.validate(context(null)));
        assertTrue(ex.getMessage().contains("Missing remote IP"));
    }
}