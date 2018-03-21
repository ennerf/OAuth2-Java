package us.hebi.oauth2.server.rest;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.enterprise.inject.Produces;

/**
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 21 Mar 2018
 */
public class OAuth2Config {

    @Produces
    public OAuth20Service createGoogleOAuth2Service() {
        return new ServiceBuilder(clientId)
                .apiKey(clientId)
                .apiSecret(clientSecret)
                .callback(callbackUri)
                .scope("openid profile email")
                .responseType("code")
                .build(GoogleApi20.instance());
    }

    private static final String clientId = "739350014484-j652uuj1mrq8p3r5m5kt0kjs9b1fmaag.apps.googleusercontent.com";
    private static final String clientSecret = "V2q2tbZ4Zv7cPFy7fHtUFnd9";
    private static final String callbackUri = "http://localhost:8089/callback";

}
