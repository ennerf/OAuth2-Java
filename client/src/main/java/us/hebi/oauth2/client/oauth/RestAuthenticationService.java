package us.hebi.oauth2.client.oauth;

import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.google.gson.Gson;

/**
 * Version that sends the one time code to the rest API where it gets exchanged
 * for an access token. This way the Desktop app would not need to store the
 * client secret, and the server could manage login state via sessions.
 * <p>
 * This is for testing a scenario where the Desktop application does not need to
 * access Google resources directly, and only needs to use OAuth to login to a
 * server.
 * <p>
 */
public class RestAuthenticationService extends AuthenticationService {

    @Override
    protected OAuth2AccessToken exchangeAccessToken(String code, String verifier) throws Exception {
        // Build Request
        OAuthRequest loginRequest = new OAuthRequest(Verb.POST, loginUrl);
        loginRequest.addBodyParameter("code", code);
        loginRequest.addBodyParameter("verifier", verifier);
        loginRequest.addBodyParameter("callback", service.getConfig().getCallback());

        // Exchange for token via an intermediate server
        Response response = service.execute(loginRequest);
        if (response.isSuccessful()) {
            return gson.fromJson(response.getBody(), OAuth2AccessToken.class);
        }
        throw new IllegalStateException(response.getBody());
    }

    private final Gson gson = new Gson();
    private static String loginUrl = "http://localhost:8080/server/resource/auth/login"; // change as needed

}
