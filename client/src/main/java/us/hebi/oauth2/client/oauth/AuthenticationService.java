package us.hebi.oauth2.client.oauth;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.github.scribejava.core.pkce.AuthorizationUrlWithPKCE;
import com.sun.javafx.application.HostServicesDelegate;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Prompts the user to login via the system browser and receives the oauth response on
 * a local callback.
 */
public class AuthenticationService {

    // TODO: use random port and check port on startup
    // ((ServerConnector) server.getConnectors()[0]).getLocalPort();
    private Server server = new Server(8089);

    private static final String clientId = "739350014484-j652uuj1mrq8p3r5m5kt0kjs9b1fmaag.apps.googleusercontent.com";
    private static final String clientSecret = "V2q2tbZ4Zv7cPFy7fHtUFnd9";
    private static final String callbackUri = "http://localhost:8089/callback";
    private final OAuth20Service service = new ServiceBuilder(clientId)
            .apiKey(clientId) // the client id from the api console registration
            .apiSecret(clientSecret)
            .callback(callbackUri) // the servlet that google redirects to after authorization
            .scope("openid profile email") // scope is the api permissions we are requesting
            .responseType("code")
            .build(GoogleApi20.instance());

    private volatile AuthorizationUrlWithPKCE authUrl = null;
    private volatile OAuth2AccessToken accessToken = null;

    @Inject
    HostServicesDelegate hostServices;

    public void requestAccessToken() {
        Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("access_type", "offline"); // here we are asking to access to user's data while they are not signed in (get refresh tokens)
        additionalParams.put("approval_prompt", "force"); // this requires them to verify which account to use, if they are already signed in

        // Add PKCE (Proof Key for Code Exchange) to prevent authorization interception attacks. This is recommended for
        // installed apps that can't secure the client secret. Note that this requires the PKCE to be stored in order to
        // verify the callback. Get more info at the following links:
        //
        // * https://tools.ietf.org/html/rfc7636
        // * https://developers.google.com/identity/protocols/OAuth2InstalledApp
        // * https://github.com/scribejava/scribejava/blob/master/scribejava-apis/src/test/java/com/github/scribejava/apis/examples/Google20WithPKCEExample.java
        authUrl = service.getAuthorizationUrlWithPKCE(additionalParams);
        hostServices.showDocument(authUrl.getAuthorizationUrl());
    }

    public void refreshAccessToken() {
        try {
            accessToken = service.refreshAccessToken(accessToken.getRefreshToken());
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    public void deleteAccessToken() {
        accessToken = null;
    }

    public Optional<String> requestSigned(OAuthRequest oReq) {
        // get some info about the user with the access token
        service.signRequest(accessToken, oReq);
        try {
            Response oResp = service.execute(oReq);
            return Optional.of(oResp.getBody());
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return Optional.empty();
        }

    }

    @PostConstruct
    public void startJetty() throws Exception {
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        server.setHandler(context);
        context.addServlet(new ServletHolder(new CallbackServlet()), "/callback");
        server.start();
    }

    @PreDestroy
    public void stopJetty() {
        server.setStopTimeout(100);
        try {
            server.stop();
        } catch (Exception e) {
            System.err.println("Failed to stop Jetty: " + e.getMessage());
        }
    }

    class CallbackServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

            // if the user denied access, we get back an error, ex
            // error=access_denied&state=session%3Dpotatoes
            if (req.getParameter("error") != null) {
                resp.getWriter().println(req.getParameter("error"));
                return;
            }

            // Trade the request token and verifier for the access token
            try {
                accessToken = service.getAccessToken(req.getParameter("code"), authUrl.getPkce().getCodeVerifier());
                resp.getWriter().println("Successfully logged in. You can close this window.");
            } catch (Exception e) {
                resp.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
                return;
            }

        }
    }

}
