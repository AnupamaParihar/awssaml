package com.vinsys.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class PostLoginFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			// TODO Auto-generated method stub
			Authentication authn = SecurityContextHolder.getContext().getAuthentication();
			Set authorities = new HashSet();
			SimpleGrantedAuthority auth1 = new SimpleGrantedAuthority("ROLE_USER");
			SimpleGrantedAuthority auth2 = new SimpleGrantedAuthority("ROLE_ADMIN");
			SimpleGrantedAuthority auth3 = new SimpleGrantedAuthority("ROLE_SUPERADMIN");
			SimpleGrantedAuthority auth4 = new SimpleGrantedAuthority("ROLE_MANAGER");
			authorities.add(auth1);
			authorities.add(auth2);
			authorities.add(auth3);
			authorities.add(auth4);
			Saml2Authentication auth = new Saml2Authentication((AuthenticatedPrincipal) authn.getPrincipal(),
					ALREADY_FILTERED_SUFFIX, authorities);
			SecurityContextHolder.getContext().setAuthentication(auth);
			System.out.println(SecurityContextHolder.getContext().getAuthentication());
			System.out.println(SecurityContextHolder.getContext().getAuthentication().getName());
		} catch (Exception e) {
			e.printStackTrace();
		}
		filterChain.doFilter(request, response);
	}

}
