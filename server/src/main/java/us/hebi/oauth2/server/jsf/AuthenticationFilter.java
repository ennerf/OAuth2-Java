package us.hebi.oauth2.server.jsf;

import us.hebi.oauth2.server.OAuthAuthorizationService;

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
        // Check if user is authenticated
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String userInfo = (String) req.getSession().getAttribute("userInfo");

        // Require authentication
        if (userInfo == null) {
            String state = CallbackServlet.encodeState(req.getRequestURI());
            res.sendRedirect(service.getAuthorizationUrl(state));
            return;
        }

        // Pass on data
        req.getSession().setAttribute("user", "User Name");

        // Continue
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }

    @Inject
    OAuthAuthorizationService service;

}
