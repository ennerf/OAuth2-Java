package us.hebi.oauth2.client.oauth;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
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
import java.util.concurrent.ExecutionException;

/**
 * Prompts the user to login via the system browser and receives the oauth response on
 * a local callback.
 */
public class AuthenticationService {

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

    private volatile OAuth2AccessToken accessToken = null;

    @Inject
    HostServicesDelegate hostServices;

    public void requestToken() {
        Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("access_type", "offline"); // here we are asking to access to user's data while they are not signed in (get refresh tokens)
        additionalParams.put("approval_prompt", "force"); // this requires them to verify which account to use, if they are already signed in
        String authUrl = service.getAuthorizationUrl(additionalParams);
        hostServices.showDocument(authUrl);
    }

    public void refreshToken() throws InterruptedException, ExecutionException, IOException {
        accessToken = service.refreshAccessToken(accessToken.getRefreshToken());
    }

    public Optional<String> requestUserInfo() {
        // get some info about the user with the access token
        OAuthRequest oReq = new OAuthRequest(Verb.GET, "https://www.googleapis.com/oauth2/v2/userinfo");
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
                accessToken = service.getAccessToken(req.getParameter("code"));
                resp.getWriter().println("Successfully logged in. You can close this window.");
            } catch (Exception e) {
                resp.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
                return;
            }

        }
    }

}
