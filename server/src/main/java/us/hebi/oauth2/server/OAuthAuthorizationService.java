package us.hebi.oauth2.server;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MultivaluedMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 21 Mar 2018
 */
public class OAuthAuthorizationService {

    public String getAuthorizationUrl() {
        Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("access_type", "offline"); // here we are asking to access to user's data while they are not signed in (get refresh tokens)
        additionalParams.put("approval_prompt", "force"); // this requires them to verify which account
        return service.getAuthorizationUrl(additionalParams);
    }

    public Optional<OAuth2AccessToken> requestAccessToken(HttpServletRequest req) {

        //Check if the user have rejected
        String error = req.getParameter("error");
        if ((null != error) && ("access_denied".equals(error.trim()))) {
            return Optional.empty();
        }

        // User has accepted, so we can trade the returned code for the access token
        try {
            return Optional.of(service.getAccessToken(req.getParameter("code")));
        } catch (Exception e) {
            return Optional.empty();
        }

    }

    public Optional<String> extractAuthenticationToken(MultivaluedMap<String, String> requestHeaders) {
        return Optional.ofNullable(requestHeaders.getFirst("Authorization"))
                .map(str -> str.substring("Bearer ".length()));
    }

    public Optional<String> getUserInfo(String token) {
        OAuthRequest oReq = new OAuthRequest(Verb.GET, "https://www.googleapis.com/plus/v1/people/me");
        service.signRequest(token, oReq);
        try {
            return Optional.of(service.execute(oReq).getBody());
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static final String clientId = "739350014484-j652uuj1mrq8p3r5m5kt0kjs9b1fmaag.apps.googleusercontent.com";
    private static final String clientSecret = "V2q2tbZ4Zv7cPFy7fHtUFnd9";
//    private static final String callbackUri = "http://localhost:8089/callback";
    private static final String callbackUri = "http://localhost:8080/server/oauth2callback";
    private final OAuth20Service service = new ServiceBuilder(clientId)
            .apiKey(clientId)
            .apiSecret(clientSecret)
            .callback(callbackUri)
            .scope("openid profile email")
            .responseType("code")
            .build(GoogleApi20.instance());

}
