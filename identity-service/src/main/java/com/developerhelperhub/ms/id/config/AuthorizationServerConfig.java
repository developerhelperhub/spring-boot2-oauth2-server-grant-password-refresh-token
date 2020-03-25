package com.developerhelperhub.ms.id.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Value("${user.oauth.clientId}")
	private String clientID;
	@Value("${user.oauth.clientSecret}")
	private String clientSecret;
	@Value("${user.oauth.redirectUris}")
	private String redirectURLs;

	private final PasswordEncoder passwordEncoder;

	private AuthenticationManager authenticationManager;

	private UserDetailsService userDetailsService;

	@Autowired
	public AuthorizationServerConfig(PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager,
			UserDetailsService userDetailsService) {
		this.passwordEncoder = passwordEncoder;
		this.authenticationManager = authenticationManager;
		this.userDetailsService = userDetailsService;
	}

	/**
	 * Spring Security OAuth exposes two endpoints for checking tokens
	 * (/oauth/check_token and /oauth/token_key). Those endpoints are not exposed by
	 * default (have access "denyAll()").
	 */
	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		endpoints.authenticationManager(authenticationManager).userDetailsService(userDetailsService);
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory().withClient(clientID).secret(passwordEncoder.encode(clientSecret))
				.authorizedGrantTypes("authorization_code", "password", "refresh_token").scopes("user_info")
				.autoApprove(true).redirectUris(redirectURLs).refreshTokenValiditySeconds(83199)
				.accessTokenValiditySeconds(43199);
		
	}
}
