package org.episteme.activemq.auth.core.validators;

import java.util.List;

import org.episteme.activemq.auth.core.*;
import org.episteme.activemq.auth.core.utils.IpAclEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IpAclValidator implements AuthValidator {

	private static final Logger log = LoggerFactory.getLogger(IpAclValidator.class);
    private final AuthConfigLoader configLoader;

    public IpAclValidator(AuthConfigLoader configLoader) {
        this.configLoader = configLoader;
    }

    @Override
    public AuthenticatedUser validate(AuthRequestContext context) throws AuthException {
        log.info("Validating connection from the remoteaddress:"+context.getRemoteAddress());
    	List<IpAclEntry> allowList = configLoader.getIpAclAllowList();
        if (allowList == null || allowList.isEmpty()) {
            throw new AuthException("IP ACL config is missing or empty");
        }
        String ip = context.getRemoteAddress();
        if (ip == null || ip.isEmpty()) {
            throw new AuthException("Missing remote IP address");
        }
        boolean allowed = allowList.stream().anyMatch(entry -> entry.contains(ip));
        if (!allowed) {
            throw new AuthException("IP address not in allow list: " + ip);
        }
        return new AuthenticatedUser(ip);
    }
}