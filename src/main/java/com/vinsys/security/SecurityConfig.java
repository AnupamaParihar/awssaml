package com.vinsys.security;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

//	public RSAPrivateKey readPrivateKey(File file) throws Exception {
//		String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());
//
//		String privateKeyPEM = key.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "")
//				.replace("-----END PRIVATE KEY-----", "");
//
//		byte[] encoded = Base64.getDecoder().decode(privateKeyPEM.getBytes());
//
//		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
//		return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
//	}
	private String metadataURL = "http://localhost:8080/saml2/service-provider-metadata/nilesh";

//	@Bean
//	RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
//		X509Certificate certificate = X509Support.decodeCertificate(this.verificationKey);
//		X509Certificate publicCred = X509Support.decodeCertificate(this.publicKey);
//		PrivateKey key = readPrivateKey(privateKey);
//		Saml2X509Credential credential = Saml2X509Credential.verification(certificate);
//
//		RelyingPartyRegistration registration = RelyingPartyRegistration.withRegistrationId("nilesh")
//				.assertingPartyDetails(party -> party.entityId(
//						"https://portal.sso.us-east-1.amazonaws.com/saml/assertion/NDU3MzYyOTMwNzQ3X2lucy1iZWJmOTExM2M5NjE3Y2I1")
//						.singleSignOnServiceLocation(
//								"https://portal.sso.us-east-1.amazonaws.com/saml/assertion/NDU3MzYyOTMwNzQ3X2lucy1iZWJmOTExM2M5NjE3Y2I1")
//						.wantAuthnRequestsSigned(false).verificationX509Credentials(c -> c.add(credential)))
//				.build();
//		return new InMemoryRelyingPartyRegistrationRepository(registration);
//	}

	@Autowired
	private PostLoginFilter postFilter;

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		Saml2MetadataFilter filter = new Saml2MetadataFilter(new DefaultRelyingPartyRegistrationResolver(registration),
				new OpenSamlMetadataResolver());
		http.authorizeHttpRequests(r -> r.requestMatchers("/saml2/**").permitAll());
		http.authorizeHttpRequests().anyRequest().authenticated();
		http.saml2Login(withDefaults());
		http.saml2Logout(withDefaults());
		http.csrf().disable();
		http.addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);
		http.addFilterAfter(postFilter, Saml2WebSsoAuthenticationFilter.class);
		return http.build();
	}

	@Autowired
	RelyingPartyRegistrationRepository registration;
}
