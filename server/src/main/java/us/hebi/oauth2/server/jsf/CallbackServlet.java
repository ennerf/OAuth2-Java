package us.hebi.oauth2.server.jsf;

import com.github.scribejava.core.model.OAuth2AccessToken;
import us.hebi.oauth2.server.OAuthAuthorizationService;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Optional;

/**
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 21 Mar 2018
 */
@WebServlet(urlPatterns = {"/oauth2callback"}, asyncSupported = true)
public class CallbackServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {

        // TODO: make async to avoid blocking the request handler thread
        Optional<String> userInfo = service.requestAccessToken(req)
                .map(OAuth2AccessToken::getAccessToken)
                .flatMap(service::getUserInfo);

        // Unauthenticated
        if (!userInfo.isPresent()) {
            HttpSession sess = req.getSession();
            sess.invalidate();
            resp.sendRedirect(req.getContextPath());
            return;
        }

        // Authenticated
        req.getSession().setAttribute("userInfo", userInfo.get());
        resp.sendRedirect("faces/index.xhtml"); // TODO: proper redirect to previous url using optional state

    }

    @Inject
    OAuthAuthorizationService service;

}
