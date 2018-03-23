package us.hebi.oauth2.server.jsf;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static us.hebi.oauth2.server.jsf.AuthenticationService.*;

/**
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 21 Mar 2018
 */
@WebServlet(urlPatterns = CALLBACK_SERVLET_PATH, asyncSupported = true)
public class AuthenticationCallback extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        service.handleAuthenticationCallback(req, resp);
    }

    @Inject
    AuthenticationService service;

}
