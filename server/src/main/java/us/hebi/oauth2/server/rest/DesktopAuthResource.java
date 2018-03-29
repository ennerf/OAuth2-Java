package us.hebi.oauth2.server.rest;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.ejb.Stateless;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Resource that allows Desktop users to login/logout using the one
 * time code. This can remove the need for the Desktop app to do the exchange
 * itself and store the client secret.
 * <p>
 * This is for testing a scenario where Desktop apps don't need to access Google
 * resources directly, and the credentials are only used for login.
 *
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 29 Mar 2018
 */
@Stateless
@Path("auth")
@Produces(MediaType.APPLICATION_JSON)
public class DesktopAuthResource {

    @POST
    @Path("login")
    public Response login(@FormParam("code") String code,
                          @FormParam("verifier") String verifier,
                          @FormParam("callback") String callback) throws Exception {
        // Exchange for token and e.g. store user data in session
        OAuth20Service service = createService(callback);
        OAuth2AccessToken token = service.getAccessToken(code, verifier);
        String json = gson.toJson(token);
        return Response.ok(json).build();
    }

    private final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    // Needs to match Desktop ids
    final String clientId = "739350014484-qijtb6bcaagjk9rq4kh6tt8o7g804n56.apps.googleusercontent.com";
    final String clientSecret = "JSX6Wai753bDz_DwucnqV7Iz";

    private OAuth20Service createService(String callback) {
        return new ServiceBuilder(clientId) // the client id from the api console registration
                .apiSecret(clientSecret) // the client secret from the api console registration
                .scope("openid profile email") // scope is the api permissions we are requesting
                .responseType("code")
                .callback(callback)
                .build(GoogleApi20.instance());
    }

}
