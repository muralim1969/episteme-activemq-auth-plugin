package org.episteme.activemq.auth.core.validators;

import org.episteme.activemq.auth.core.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class ClientCertValidatorTest {
  
	 private AuthRequestContext getContext(String user,String ip,X509Certificate[] certs) {
	        return new AuthRequestContext() {
	            @Override public String getRemoteAddress() { return ip; }
	            @Override public Optional<String> getJwtToken() { return Optional.empty(); }
	            @Override public String getUsername() { return user; }
	            @Override public Optional<String> getPassword() { return Optional.empty(); }
	            @Override public Optional<String> getHeader(String key) { return Optional.empty(); }
	            @Override public Optional<java.security.cert.X509Certificate[]> getClientCertificates() { return Optional.of(certs); }
				@Override
				public void setClientCertificates(X509Certificate[] clientCertificates) {		}
	        };
	    }
	
    AuthConfigLoader configLoader;
    @BeforeEach
    void setup() throws IOException
    {
    	
    	configLoader= new AuthConfigLoader("src/test/resources/ip-certs.json");
    }

    private X509Certificate loadTestCertificate(String filePath) throws Exception {
        try (FileInputStream in = new FileInputStream(filePath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);
        }
    }


    @Test
    public void testThumbprintAllowed() throws Exception {
        X509Certificate cert = loadTestCertificate("src/test/resources/testcert1.pem");
        AuthValidator  clientCertValidator = new ClientCertValidator(configLoader);
        AuthRequestContext requestContext=getContext("serviceuser","12.23.34.45",new X509Certificate[] {cert});
        
        AuthenticatedUser user=clientCertValidator.validate(requestContext);
        assertNotNull(user);
        assertTrue(user.getSubject().contains("serviceuser"));
    }


@Test
    public void testThumbprintDenied() throws Exception {
	   X509Certificate cert = loadTestCertificate("src/test/resources/testcert3.pem");
       AuthValidator  clientCertValidator = new ClientCertValidator(configLoader);
       AuthRequestContext requestContext=getContext("serviceuser","12.23.34.45",new X509Certificate[] {cert});
        
       AuthException ex = assertThrows(AuthException.class,() -> clientCertValidator.validate(requestContext));
        assertTrue(ex.getMessage().contains("not allowed"));
    }

   /* @Test
    public void testMissingCertificate() {
        ClientCertValidator validator = new ClientCertValidator(new TestConfigLoader("ABCDEF123456"));

        AuthException ex = assertThrows(AuthException.class,
            () -> validator.validate(() -> Optional.empty()));
        assertTrue(ex.getMessage().contains("required but missing"));
    }*/
}