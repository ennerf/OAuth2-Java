package us.hebi.oauth2.client.oauth;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.github.scribejava.core.pkce.AuthorizationUrlWithPKCE;
import com.github.scribejava.httpclient.okhttp.OkHttpHttpClient;
import com.sun.javafx.application.HostServicesDelegate;
import fi.iki.elonen.NanoHTTPD;
import okhttp3.JavaNetCookieJar;
import okhttp3.OkHttpClient;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.inject.Inject;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Prompts the user to login via the system browser and receives the oauth response on
 * a local callback.
 */
public class AuthenticationService {

    // Enable cookies in http handler to work with sessions
    private final CookieHandler cookieHandler = new CookieManager();
    private final OkHttpHttpClient httpClient = new OkHttpHttpClient(new OkHttpClient.Builder()
            .cookieJar(new JavaNetCookieJar(cookieHandler))
            .connectTimeout(5, TimeUnit.SECONDS)
            .writeTimeout(3, TimeUnit.SECONDS)
            .readTimeout(3, TimeUnit.SECONDS)
            .build());

    // TODO: use random port and check port on startup. Note that this requires the Desktop-OAuth2 version
    // port = 0 with httpServer.getListeningPort()
    private final int port = 8089;

    private static final String clientId = "739350014484-j652uuj1mrq8p3r5m5kt0kjs9b1fmaag.apps.googleusercontent.com";
    private static final String clientSecret = "V2q2tbZ4Zv7cPFy7fHtUFnd9";
    private static final String callbackUri = "http://localhost:8089/callback";
    private final OAuth20Service service = new ServiceBuilder(clientId)
            .apiKey(clientId) // the client id from the api console registration
            .apiSecret(clientSecret)
            .callback(callbackUri) // the servlet that google redirects to after authorization
            .scope("openid profile email") // scope is the api permissions we are requesting
            .responseType("code")
            .httpClient(httpClient)
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
    public void startServer() throws Exception {
        httpServer.start();
    }

    @PreDestroy
    public void stopServer() {
        httpServer.stop();
    }

    // Embedded http server that handles the OAuth2 callback
    private final NanoHTTPD httpServer = new NanoHTTPD(port) {
        @Override
        public Response serve(IHTTPSession session) {

            // Handle callback uri
            if (session.getMethod() == Method.GET && "/callback".equalsIgnoreCase(session.getUri())) {

                // if the user denied access, we get back an error, ex
                // error=access_denied&state=session%3Dpotatoes
                if (session.getParameters().get("error") != null) {
                    return newFixedLengthResponse("error");
                }

                // Trade the request token and verifier for the access token
                try {
                    accessToken = service.getAccessToken(
                            session.getParameters().get("code").get(0),
                            authUrl.getPkce().getCodeVerifier());
                    return newFixedLengthResponse("Successfully logged in. You can close this window.");
                } catch (Exception e) {
                    return newFixedLengthResponse(Response.Status.UNAUTHORIZED, MIME_HTML, e.getMessage());
                }

            }

            // Ignore all other request uris
            return newFixedLengthResponse(Response.Status.NOT_FOUND, null, null);
        }
    };

}
