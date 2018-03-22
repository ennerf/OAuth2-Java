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
import java.util.Base64;
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

        // Forward to initial request uri
        String state = req.getParameter("state");
        if (state != null) {
            resp.sendRedirect(decodeUrl(state));
        }

    }

    static String encodeUrl(String url) {
        return Base64.getUrlEncoder().encodeToString(url.getBytes());
    }

    private static String decodeUrl(String url) {
        return new String(Base64.getUrlDecoder().decode(url));
    }

    @Inject
    OAuthAuthorizationService service;

}
