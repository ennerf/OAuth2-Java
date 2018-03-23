package us.hebi.oauth2.client.oauth;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.github.scribejava.core.pkce.AuthorizationUrlWithPKCE;
import com.github.scribejava.core.revoke.TokenTypeHint;
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

    private OAuth20Service service;
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

    public void revokeAccessToken() {
        try {
            service.revokeToken(accessToken.getRefreshToken(), TokenTypeHint.refresh_token);
            service.revokeToken(accessToken.getAccessToken(), TokenTypeHint.access_token);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        } finally {
            accessToken = null;
        }
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
        final String clientId = "739350014484-qijtb6bcaagjk9rq4kh6tt8o7g804n56.apps.googleusercontent.com";
        final String clientSecret = "JSX6Wai753bDz_DwucnqV7Iz";
        final String callbackUri = "http://localhost:" + httpServer.getListeningPort() + "/callback";
        service = new ServiceBuilder(clientId)
                .apiKey(clientId) // the client id from the api console registration
                .apiSecret(clientSecret)
                .callback(callbackUri) // the servlet that google redirects to after authorization
                .scope("openid profile email") // scope is the api permissions we are requesting
                .responseType("code")
                .httpClient(httpClient)
                .build(GoogleApi20.instance());
    }

    @PreDestroy
    public void stopServer() {
        httpServer.stop();
    }

    // Embedded http server that handles the OAuth2 callback
    private final NanoHTTPD httpServer = new NanoHTTPD(0) {
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
