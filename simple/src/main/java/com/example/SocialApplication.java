/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;
import java.security.Principal;
import java.util.*;

@SpringBootApplication
@EnableOAuth2Sso
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter{

	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
	}

	//impacts global security
	@Override
	public void configure(WebSecurity webSecurity) throws Exception{
		webSecurity
				.ignoring().antMatchers("/management/**")
				.and().debug(true);
	}


	//authorization (roles) for http resources (similar to method security annotations)
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				.and().authorizeRequests()
				.antMatchers("/insecured").permitAll()
				.anyRequest().fullyAuthenticated();
	}



	@GetMapping("/insecured")
	public String insecuredEndpoint(){
		return "insecured";
	}

	@GetMapping("/secured")
	public Principal securedEndpoint(@AuthenticationPrincipal Principal principal){
		return principal;
	}


	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(myAccessTokenConverter());
	}

	@Value("${security.oauth2.resource.jwt.key-value}")
	private  String signingkey;

//	@Primary
	@Bean
	public JwtAccessTokenConverter myAccessTokenConverter() {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter(){
			private static final String USERNAME = "preferred_username";

			@Override
			protected Map<String, Object> decode(String token) {
				return super.decode(token);
			}

			@Override
			public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
				Map<String, String> parameters = new HashMap<String, String>();
				Set<String> scope = extractScope(map);
//				Authentication user = userTokenConverter.extractAuthentication(map);
				Authentication user = extractUser(map);
				String clientId = (String) map.get(CLIENT_ID);
				parameters.put(CLIENT_ID, clientId);
//				if (includeGrantType && map.containsKey(GRANT_TYPE)) {
//					parameters.put(GRANT_TYPE, (String) map.get(GRANT_TYPE));
//				}
				Set<String> resourceIds = new LinkedHashSet<String>(map.containsKey(AUD) ? getAudience(map)
						: Collections.<String>emptySet());

				Collection<? extends GrantedAuthority> authorities = null;
//				if (user==null && map.containsKey(AUTHORITIES)) {
//					@SuppressWarnings("unchecked")
//					String[] roles = ((Collection<String>)map.get(AUTHORITIES)).toArray(new String[0]);
//					authorities = AuthorityUtils.createAuthorityList(roles);
//				}
				OAuth2Request request = new OAuth2Request(parameters, clientId, user.getAuthorities(), true, scope, resourceIds, null, null,
						null);
				return new OAuth2Authentication(request, user);
			}

			private Collection<String> getAudience(Map<String, ?> map) {
				Object auds = map.get(AUD);
				if (auds instanceof Collection) {
					@SuppressWarnings("unchecked")
					Collection<String> result = (Collection<String>) auds;
					return result;
				}
				return Collections.singleton((String)auds);
			}

			private Authentication extractUser(Map<String, ?> map) {
				if (map.containsKey(USERNAME)) {
					Object principal = map.get(USERNAME);
					Collection<? extends GrantedAuthority> authorities = getAuthorities(map);
					return new UsernamePasswordAuthenticationToken(principal, "N/A", authorities);
				}
				return null;
			}


			private Collection<? extends GrantedAuthority> getAuthorities(Map<String, ?> map) {
				String REALM_ACCESS = "realm_access";
				String ROLES = "roles";

				if (!map.containsKey(REALM_ACCESS)) {
					return null;
				}
				Collection<String> authorities = ((Map<String,List<String>>)map.get(REALM_ACCESS)).get(ROLES);
//				if (authorities instanceof String) {
//					return AuthorityUtils.commaSeparatedStringToAuthorityList((String) authorities);
//				}
				if (authorities instanceof Collection) {
					return AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils
							.collectionToCommaDelimitedString((Collection<?>) authorities));
				}
				throw new IllegalArgumentException("Authorities must be either a String or a Collection");
			}

			private Set<String> extractScope(Map<String, ?> map) {
				Set<String> scope = Collections.emptySet();
				if (map.containsKey(SCOPE)) {
					Object scopeObj = map.get(SCOPE);
					if (String.class.isInstance(scopeObj)) {
						scope = new LinkedHashSet<String>(Arrays.asList(String.class.cast(scopeObj).split(" ")));
					} else if (Collection.class.isAssignableFrom(scopeObj.getClass())) {
						@SuppressWarnings("unchecked")
						Collection<String> scopeColl = (Collection<String>) scopeObj;
						scope = new LinkedHashSet<String>(scopeColl);	// Preserve ordering
					}
				}
				return scope;
			}
		};
		converter.setVerifierKey(this.signingkey);
		return converter;
	}

	@Bean
	@Primary
	public DefaultTokenServices tokenServices() {
		DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
		defaultTokenServices.setTokenStore(tokenStore());
		return defaultTokenServices;
	}

}
