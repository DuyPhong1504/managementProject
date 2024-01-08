package manage.project.config;

import java.io.IOException;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import manage.project.service.JWTService;
import manage.project.service.UserService;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {
	@Autowired
	private JWTService jwtService;

	@Autowired
	private UserService userService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		final String authHeader = request.getHeader("Authorization");
		final String jwt;
		final String userEmail;

		if (StringUtils.isEmpty(authHeader) || StringUtils.startsWith(authHeader, "Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}
		jwt = authHeader.substring(7);
		userEmail = jwtService.extractUserName(jwt);

		if (StringUtils.isNotEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetail = userService.loadByUserName(userEmail);
			if (jwtService.isTokenValid(jwt, userDetail)) {
				SecurityContext securityContextHolder = SecurityContextHolder.createEmptyContext();

				UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetail, null,
						userDetail.getAuthorities());

				token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				securityContextHolder.setAuthentication(token);
				SecurityContextHolder.setContext(securityContextHolder);

			}
		}
		filterChain.doFilter(request, response);
	}

}
