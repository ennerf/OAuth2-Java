package us.hebi.oauth2.server.jsf;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.ejb.Singleton;
import javax.servlet.AsyncContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import static com.github.scribejava.core.model.OAuthConstants.*;

/**
 * Handles user logins using Google's OAuth2 API
 *
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 21 Mar 2018
 */
@Singleton
class AuthenticationService {

    /**
     * Redirects non-authenticated users to an appropriate login page
     *
     * @param req
     * @param res
     * @return true if user is authenticated
     * @throws IOException
     * @throws ServletException
     */
    boolean requireUserAuthentication(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        boolean isAuthenticated = req.getSession().getAttribute("userInfo") != null;
        if (!isAuthenticated) {

            // Dynamically build callback URI so the server can run on any port. This is used to
            // support local test environments. In production this can be a fixed url.
            // e.g. "http://localhost:28080/server/oauth2callback";
            // See https://stackoverflow.com/a/42706412/3574093 for URL parts
            StringBuffer callbackUrl = req.getRequestURL();
            callbackUrl.setLength(callbackUrl.length() - req.getRequestURI().length());
            callbackUrl.append(req.getContextPath()).append(CALLBACK_SERVLET_PATH);

            // Store source URI as state, so we can redirect back after login
            String state = encodeUrl(req.getRequestURI());

            // Forward non-authenticated users to OAuth login
            final OAuth20Service service = new ServiceBuilder(CLIENT_ID)
                    .apiKey(CLIENT_ID)
                    .apiSecret(CLIENT_SECRET)
                    .callback(callbackUrl.toString())
                    .state(state)
                    .scope("openid profile email")
                    .responseType(CODE)
                    .build(GoogleApi20.instance());

            // Store auth service in session for the returning call
            req.getSession().setAttribute("oauth2Service", service);
            res.sendRedirect(service.getAuthorizationUrl(ADDITIONAL_PARAMS));

        }
        return isAuthenticated;
    }

    /**
     * Handles calls returning from OAuth provider and redirects users to the
     * original target page
     *
     * @param req
     * @param resp
     * @throws IOException
     * @throws ServletException
     */
    void handleAuthenticationCallback(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {

        // Check if the user has rejected
        HttpSession session = req.getSession();
        if (hasUserRejected(req)) {
            session.invalidate();
            resp.sendRedirect(req.getContextPath());
            return;
        }

        // User has consented
        AsyncContext asyncCtx = req.startAsync();
        asyncCtx.start(() -> {

            try {

                // Trade one time token with access token
                String code = req.getParameter(CODE);
                OAuth20Service service = (OAuth20Service) session.getAttribute("oauth2Service");
                if (service == null || code == null) return;
                OAuth2AccessToken token = service.getAccessToken(code);

                // Get user info
                OAuthRequest oReq = new OAuthRequest(Verb.GET, GOOGLE_PLUS_INFO_ENDPOINT);
                service.signRequest(token, oReq);
                String json = service.execute(oReq).getBody();

                // Store user data (could also do proxy login via req.login("user", "pw"))
                session.setAttribute("userInfo", json);

                // Forward to initial request uri
                String state = req.getParameter("state");
                if (state != null) {
                    resp.sendRedirect(decodeUrl(state));
                }

            } catch (IOException | ExecutionException | InterruptedException e) {
                // Failed to get token. TODO: does this case need to be handled in an actual response?
            } finally {
                asyncCtx.complete();
            }

        });

    }

    private static String encodeUrl(String url) {
        return Base64.getUrlEncoder().encodeToString(url.getBytes());
    }

    private static String decodeUrl(String url) {
        return new String(Base64.getUrlDecoder().decode(url));
    }

    private boolean hasUserRejected(HttpServletRequest req) {
        String error = req.getParameter("error");
        return (null != error) && ("access_denied".equals(error.trim()));
    }

    static final String CALLBACK_SERVLET_PATH = "/oauth2callback";
    private static final String CLIENT_ID = "739350014484-qijtb6bcaagjk9rq4kh6tt8o7g804n56.apps.googleusercontent.com";
    private static final String CLIENT_SECRET = "JSX6Wai753bDz_DwucnqV7Iz";
    private static final String GOOGLE_PLUS_INFO_ENDPOINT = "https://www.googleapis.com/plus/v1/people/me";
    private static final Map<String, String> ADDITIONAL_PARAMS = new HashMap<>();

    static {
        ADDITIONAL_PARAMS.put("access_type", "offline"); // here we are asking to access to user's data while they are not signed in (get refresh tokens)
        ADDITIONAL_PARAMS.put("approval_prompt", "force"); // this requires them to verify which account
    }

}
