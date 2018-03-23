package us.hebi.oauth2.server.jsf;

import javax.inject.Inject;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 21 Mar 2018
 */
public class AuthenticationFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (authenticationService.requireUserAuthentication((HttpServletRequest) request, (HttpServletResponse) response)) {
            // User is logged in, so continue
            chain.doFilter(request, response);
        }

    }

    @Override
    public void destroy() {

    }

    @Inject
    AuthenticationService authenticationService;

}
