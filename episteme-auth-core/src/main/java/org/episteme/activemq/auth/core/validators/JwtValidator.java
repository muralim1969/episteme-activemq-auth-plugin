package org.episteme.activemq.auth.core.validators;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.episteme.activemq.auth.core.AuthConfigLoader;
import org.episteme.activemq.auth.core.AuthException;
import org.episteme.activemq.auth.core.AuthRequestContext;
import org.episteme.activemq.auth.core.AuthValidator;
import org.episteme.activemq.auth.core.AuthenticatedUser;
import org.episteme.activemq.auth.core.AuthConfigLoader.JwtConfig;
import org.episteme.activemq.auth.core.AuthConfigLoader.JwtIdpConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;


public class JwtValidator implements AuthValidator 
{
	private static final Logger log = LoggerFactory.getLogger(JwtValidator.class);


	private final Map<String, JWTVerifier> verifiers = new ConcurrentHashMap<>();
	private final AuthConfigLoader configLoader;

	public JwtValidator(AuthConfigLoader configLoader) {
		this.configLoader = configLoader;
	}
	@Override
	public AuthenticatedUser validate(AuthRequestContext authRequest) throws AuthException {		
		log.info("Validating connection from the remoteaddress:"+authRequest.getRemoteAddress());
		Optional<String> tokenOpt = authRequest.getJwtToken();
		if(tokenOpt.isEmpty()) {
			throw new AuthException("No token provided to validate");
		}
		try {
			Optional<JwtConfig> idpConfigs=configLoader.getJwtConfig();
			DecodedJWT jwt = JWT.decode(tokenOpt.get());
			String issuer = jwt.getIssuer();
			String kid = jwt.getKeyId();

			log.info("Validating JWT for issuer: {}, kid: {}", issuer, kid);

			JwtIdpConfig idpConfig = Optional.ofNullable(idpConfigs.get().idps.get(issuer))
					.orElseThrow(() -> new AuthException("No IdP config found for issuer: " + issuer));
			String verifierKey = issuer + ":" + (kid != null ? kid : "default");
			JWTVerifier verifier = verifiers.computeIfAbsent(verifierKey, k -> {
				try {
					return createVerifier(idpConfig, kid);
				} catch (AuthException e) {
					log.error("Failed to create JWT verifier for issuer: {}, kid: {}", issuer, kid, e);
					throw new RuntimeException(e);
				}
			});
			String userName=authRequest.getUsername().toLowerCase();
			boolean usernameMatches = checkUsernameClaim(jwt, userName, "preferred_username") ||
                    checkUsernameClaim(jwt, userName, "email") ||
                    checkUsernameClaim(jwt, userName, "upn") ||           // Azure AD
                    checkUsernameClaim(jwt, userName, "unique_name") ||   // Azure AD
                    checkUsernameClaim(jwt, userName, "sub");
			if(!usernameMatches)
			{
				throw new AuthException("UserId mismatch with token");
			}			
			verifier.verify(tokenOpt.get());
			log.info("JWT validation successful for user: {}", userName);			
			return new AuthenticatedUser(jwt.getSubject());
		}catch (JWTVerificationException ex) {
			log.info("JWT verification failed: {}", ex.getMessage());
			throw new AuthException("Invalid JWT: " + ex.getMessage(), ex);
		} catch (Exception ex) {
			log.error("JWT validation error: {}", ex.getMessage(), ex);
			throw new AuthException("JWT validation failure: " + ex.getMessage(), ex);
		}
	}
	
	private boolean checkUsernameClaim(DecodedJWT jwt, String providedUsername, String claimName) {
	    try {
	        String claimValue = jwt.getClaim(claimName).asString();
	        if (claimValue != null && !claimValue.trim().isEmpty()) {
	            boolean matches =claimValue.trim().toLowerCase().contains(providedUsername);
	            log.info("Checking claim '{}': '{}' vs '{}' = {}", claimName, providedUsername, claimValue, matches);
	            return matches;
	        }
	    } catch (Exception e) {
	        log.debug("Error reading claim '{}': {}", claimName, e.getMessage());
	    }
	    return false;
	}
	private JWTVerifier createVerifier(JwtIdpConfig idpConfig, String kid) throws AuthException {
		RSAPublicKey publicKey = fetchKeyFromJwks(idpConfig, kid);

		return JWT.require(Algorithm.RSA256(publicKey, null))
				.withIssuer(idpConfig.issuer)
				.withAnyOfAudience(idpConfig.audience)
				.acceptLeeway(30) // Allow 30 seconds clock skew
				.build();
	}

	private RSAPublicKey fetchKeyFromJwks(JwtIdpConfig idpConfig, String requestedKid) throws AuthException {
		try {
			log.debug("Fetching public key for issuer: {}, kid: {}", idpConfig.issuer, requestedKid);
			String openidUrl = idpConfig.issuer.endsWith("/") ? idpConfig.issuer : idpConfig.issuer + "/";
			URI openIdUri = URI.create(openidUrl + ".well-known/openid-configuration");
			String response=invokeRestCall(openIdUri);
			ObjectMapper objectMapper = new ObjectMapper();
			JsonNode rootNode = objectMapper.readTree(response);

			String jwksUri = rootNode.get("jwks_uri").asText();
			String jwksResponse=invokeRestCall(URI.create(jwksUri));

			JsonNode jwks = objectMapper.readTree(jwksResponse);
			ArrayNode keys = (ArrayNode) jwks.get("keys");

			for (JsonNode key : keys) {
				if (!"RSA".equals(key.get("kty").asText())) continue;

				String kid = key.get("kid").asText();
				if (!kid.equals(requestedKid)) continue;

				String n = key.get("n").asText();
				String e = key.get("e").asText();

				byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
				byte[] exponentBytes = Base64.getUrlDecoder().decode(e);

				BigInteger modulus = new BigInteger(1, modulusBytes);
				BigInteger exponent = new BigInteger(1, exponentBytes);
				log.debug("Successfully extracted RSA public key: kid={}", kid);
				return (RSAPublicKey) KeyFactory.getInstance("RSA")
						.generatePublic(new RSAPublicKeySpec(modulus, exponent));
			}
			throw new AuthException("Matching key not found in JWKS");

		} catch (IOException ex) {
			throw new AuthException("Failed to fetch JWKS: " + ex.getMessage(), ex);
		} catch (Exception ex) {
			throw new AuthException("Failed to parse JWKS: " + ex.getMessage(), ex);
		}
	}

	private String invokeRestCall(URI uri) throws IOException, InterruptedException {
		HttpClient httpClient = HttpClient.newHttpClient();
		HttpRequest request = HttpRequest.newBuilder()
				.uri(uri)
				.timeout(Duration.ofSeconds(5))
				.header("Accept", "application/json")
				.GET()
				.build();

		HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

		if (response.statusCode() != 200) {
			throw new IOException("HTTP " + response.statusCode() + " from " + uri);
		}

		return response.body();
	}

}