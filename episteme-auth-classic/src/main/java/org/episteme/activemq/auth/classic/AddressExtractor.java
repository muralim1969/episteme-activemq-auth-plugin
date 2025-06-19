package org.episteme.activemq.auth.classic;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AddressExtractor {
	
	private static final String IPV6_REGEX = "(.*//)((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})(:(\\d{1,5}))?$";
	private static final Pattern pattern = Pattern.compile(IPV6_REGEX);
	
	public static String getHost(URI uri) {
        if (uri == null) {
            return null;
        }
        
        // Try the standard way first
        String host = uri.getHost();
        if (host != null) {
            return host;
        }
        
        // Fallback: extract from URI string
        return extractHostFromString(uri.toString());
    }

	public static String extractHostFromString(String input) {
		Matcher matcher = pattern.matcher(input);
		if (matcher.matches() && matcher.groupCount() >=2) {
			String ipv6Address = matcher.group(2);
			return "[" + ipv6Address + "]";
		} else {
			return null;
		}
	}
}
