package org.opendatanode.midpoint.security;

import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.cas.userdetails.AbstractCasAssertionUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class ODNAuthenticationUserDetailsService extends
		AbstractCasAssertionUserDetailsService {

	private UserDetailsService userDetailsService;

	private String userAttributeName;

	@Override
	protected UserDetails loadUserDetails(Assertion assertion) {
		String username = (String) assertion.getPrincipal().getAttributes()
				.get(userAttributeName);
		if (username == null) {
			throw new UsernameNotFoundException("User " + username
					+ " not found!");
		}

		return userDetailsService.loadUserByUsername(username);
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public void setUserAttributeName(String userAttributeName) {
		this.userAttributeName = userAttributeName;
	}
}
