# Spring Boot 2.2.5 Oauth2 Authentication Server and Client Application

This repository contains the Oauth2 authentication server implementation which supports grant types are ```authorization_code```, ```password``` and ```refresh_token```. This example is continuation of the [Oauth2 Autherization Server and Client Application](https://github.com/developerhelperhub/spring-boot2-oauth2-server-and-client) example. I would suggest, please look previous implementation before looking this source code. In the previous example, ```authorization_code``` grant type is only supported.

This repository contains three maven project. 
* my-cloud-service: Its main module, it contains the dependecy management of our application.
* identity-service: This authentication server service. 
* client-application-service: This client application for authentication server.

### Updation and additions in the identity-service
I changed the oauth2 version 2.4.0 to 2.2.6 in ```pom.xml``` file because of the latest spring boot oauth2 implementation all classes are depricated.  

```xml
<dependency>
      <groupId>org.springframework.security.oauth</groupId>
      <artifactId>spring-security-oauth2</artifactId>
      <version>2.2.6.RELEASE</version>
</dependency>
```

We need to add additional codes in the ```WebSecurity``` class. Which are given below
* Required expose the ```/oauth/token``` url to generate the access and refresh token
* Override method ```authenticationManagerBean``` to create the AuthenticationManager bean. This bean is required to configured in the authorization server to support the grant type "password".
* Override method ```userDetailsServiceBean``` to create the UserDetailsService bean. This bean is required to configured in the authorization server to support the grant type "refresh_token".

```java
package com.developerhelperhub.ms.id.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Order(1)
@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	@Value("${user.oauth.user.username}")
	private String username;
	@Value("${user.oauth.user.password}")
	private String password;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.requestMatchers().antMatchers("/login", "/oauth/token", "/oauth/authorize").and().authorizeRequests()
				.anyRequest().authenticated().and().formLogin().permitAll();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser(username).password(passwordEncoder().encode(password)).roles("USER");
	}

	/**
	 * AuthenticationManager bean is creating. This bean is required to configured
	 * in the authorization server to support the grant type "password".
	 */
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	/**
	 * UserDetailsService bean is creating. This bean is required to configured in
	 * the authorization server to support the grant type "refresh_token".
	 */
	@Bean
	@Override
	public UserDetailsService userDetailsServiceBean() throws Exception {
		return super.userDetailsServiceBean();
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}

```

We need to add the additional code in the ```AuthorizationServerConfig``` to configure and manage the grant types. The below code are implemented.

* Autowired the AuthenticationManager
* Autowired the UserDetailsService
* Override the configure method of ```AuthorizationServerEndpointsConfigurer``` to configure the endpoints. This method is using to configure the authentication manager and user detail service.
* Added the ```password``` and ```refresh_token```
* Added the validity seconds for access and refresh tokens

```java
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

```

Above all changes added in the respective classes, we can run the spring boot application, this application run on 8081 and the context path will ```/auth```. We can use this url ```http://localhost:8081/auth/login``` to check, whether it is working or not.

*Note:* I got an issue, when I implemented this code, ```authorization_code``` is not working. I am getting error "Unauthorized" when execute the ```/login```. This issue is fixed when I added ```@Order(1)``` annotation in the ```WebSecurity``` class level.

### To generate the tokens with grant type "password"

Here, I am using Postman to test the grant types. Please open the Postman and open a new tab. We have to add below configuration and data in the tab.
* Method: POST
* URL: http://localhost:8081/auth/oauth/token
* Select the "Autherization" tab and change the type to "Basic Auth". Enter the username and password of client id and client secrete. Click the "Update Request" button
* Select the "Body" tab and select "x-www-form-urlencoded" option
* Add the keys and values in the form
  - grant_type is password
  - username is mycloud
  - password is mycloud@1234
* Click the "Send" button.

The API give the response contains
```json
{
    "access_token": "590adfd7-3503-446a-ac0c-3c65341aaf12",
    "token_type": "bearer",
    "refresh_token": "a0cae88d-eac7-4688-b09d-8c05b61ffe96",
    "expires_in": 43198,
    "scope": "user_info"
}
```

### To generate the tokens with grant type "refresh_token"

Open a new tab. We have to add below configuration and data in the tab.
* Method: POST
* URL: http://localhost:8081/auth/oauth/token
* Select the "Autherization" tab and change the type to "Basic Auth". Enter the username and password of client id and client secrete. Click the "Update Request" button
* Select the "Body" tab and select "x-www-form-urlencoded" option
* Add the keys and values in the form
  - grant_type is refresh_token
  - refresh_token is ```a0cae88d-eac7-4688-b09d-8c05b61ffe96```
* Click the "Send" button.
 
The API give the response contains
```json
{
    "access_token": "162544f0-5dd5-4500-abe7-58c4be74bfab",
    "token_type": "bearer",
    "refresh_token": "c6c647d1-4985-4474-8374-e0f0b1bccf90",
    "expires_in": 43198,
    "scope": "user_info"
}
```

### Reference
* [developer.okta.com](https://developer.okta.com/blog/2019/03/12/oauth2-spring-security-guide)
* [Oauth2 Autherization Server and Client Application](https://github.com/developerhelperhub/spring-boot2-oauth2-server-and-client)
* [Fix for "unsupported grant type"](https://stackoverflow.com/questions/52194081/spring-boot-oauth-unsupported-grant-type)
