package org.episteme.activemq.auth.core.validators;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import org.episteme.activemq.auth.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClientCertValidator implements AuthValidator {
	
	private static final Logger log = LoggerFactory.getLogger(ClientCertValidator.class);	
    private final AuthConfigLoader configLoader;

    public ClientCertValidator(AuthConfigLoader configLoader) {
        this.configLoader = configLoader;
    }

    @Override
    public AuthenticatedUser validate(AuthRequestContext context) throws AuthException {
        log.info("Validating connection from the remoteaddress:"+context.getRemoteAddress());
        Optional<X509Certificate[]> certsOpt = context.getClientCertificates();
        if (certsOpt.isEmpty() || certsOpt.get().length == 0) {
            throw new AuthException("Client certificate is required but missing");
        }
        X509Certificate clientCert = certsOpt.get()[0]; // Assuming leaf cert is first
        String thumbprint = computeThumbprint(clientCert);
        List<String> allowedThumbprints = configLoader.getAllowedThumbprints();
        if (allowedThumbprints == null || allowedThumbprints.isEmpty()) {
            throw new AuthException("No allowed certificate thumbprints configured");
        }
        boolean match = allowedThumbprints.stream()
            .anyMatch(allowed -> allowed.equalsIgnoreCase(thumbprint));

        if (!match) {
            throw new AuthException("Client certificate is not allowed");
        }
        return new AuthenticatedUser(context.getUsername());
    }

    private String computeThumbprint(X509Certificate cert) throws AuthException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] encoded = cert.getEncoded();
            byte[] hash = digest.digest(encoded);
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new AuthException("Failed to compute certificate thumbprint", e);
        }
    }
}