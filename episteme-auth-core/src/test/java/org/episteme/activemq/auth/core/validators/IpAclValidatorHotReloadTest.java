package org.episteme.activemq.auth.core.validators;

import org.episteme.activemq.auth.core.AuthConfigLoader;
import org.episteme.activemq.auth.core.AuthException;
import org.episteme.activemq.auth.core.AuthRequestContext;
import org.episteme.activemq.auth.core.AuthenticatedUser;
import org.junit.jupiter.api.*;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IpAclValidatorHotReloadTest {

    private IpAclValidator validator;
    private final Path configPath = Path.of("src/test/resources/ip-acl-hot.json");

    @BeforeEach
    public void setup() throws Exception {
        String initialConfig = "{\"ipAcl\":{\"allow\":[\"11.0.0.0/8\"]}}";
        try (FileWriter writer = new FileWriter(configPath.toFile())) {
            writer.write(initialConfig);
        }
        AuthConfigLoader configLoader = new AuthConfigLoader("src/test/resources/ip-acl-hot.json");
        validator=new IpAclValidator(configLoader);
    }

    private void writeConfig(String json) throws IOException {
        try (FileWriter writer = new FileWriter(configPath.toFile())) {
            writer.write(json);
            writer.flush();
        }
    }

    private AuthRequestContext context(String ip) {
        return new AuthRequestContext() {
            @Override public String getRemoteAddress() { return ip; }
            @Override public Optional<String> getJwtToken() { return Optional.empty(); }
            @Override public String getUsername() { return ""; }
            @Override public Optional<String> getPassword() { return Optional.empty(); }
            @Override public Optional<String> getHeader(String key) { return Optional.empty(); }
            @Override public Optional<java.security.cert.X509Certificate[]> getClientCertificates() { return Optional.empty(); }
			@Override
			public void setClientCertificates(X509Certificate[] clientCertificates) {					
			}	
        };
    }

    
    void testHotReloadAddsNewIp() throws Exception {
    	
        // Initially denied
        assertThrows(AuthException.class, () -> validator.validate(context("10.10.10.11")));
  
        // Modify config to add the new IP
        writeConfig("{\"ipAcl\":{\"allow\":[\"10.10.10.10/32\", \"10.10.10.11/32\"]}}");
        Thread.sleep(5000); // Give time for reload

        // New IP should now be allowed
        AuthenticatedUser user = validator.validate(context("10.10.10.11"));
        assertEquals("10.10.10.11", user.getSubject());
    }

   
    void testHotReloadRemovesOldIp() throws Exception {
        // Remove the previously allowed IP
        writeConfig("{\"ipAcl\":{\"allow\":[\"10.10.10.11/32\"]}}");
        Thread.sleep(2000); // Wait for reload

        // Old IP should now be denied
        assertThrows(AuthException.class, () -> validator.validate(context("10.10.10.10")));
    }  
}
