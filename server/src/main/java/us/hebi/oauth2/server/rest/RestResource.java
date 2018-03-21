package us.hebi.oauth2.server.rest;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.ejb.Stateless;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * REST endpoint that accepts authorization token and confirms its validity
 */
@Stateless
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class RestResource {

    @GET
    @Path("public/{id}")
    public Response getPublicItem(@PathParam("id") int id) throws Exception {
        return Response.ok("success " + id).build();
    }

    @GET
    @Path("private/{id}")
    public Response getPrivateItem(@PathParam("id") int id, @Context HttpHeaders headers) throws Exception {

        // Check if user added token
        String token = headers.getRequestHeaders().getFirst("Authorization");
        if (token == null)
            return Response.status(Response.Status.FORBIDDEN).build();

        // Check if token is valid
        OAuthRequest oReq = new OAuthRequest(Verb.GET, "https://www.googleapis.com/plus/v1/people/me");
        oReq.addHeader("Authorization", token);
        String json = service.execute(oReq).getBody();

        // TODO: filter users based on e.g. domain

        // Respond
        return Response.ok(json).build();

    }

    private static final String clientId = "739350014484-j652uuj1mrq8p3r5m5kt0kjs9b1fmaag.apps.googleusercontent.com";
    private static final String clientSecret = "V2q2tbZ4Zv7cPFy7fHtUFnd9";
    private static final String callbackUri = "http://localhost:8089/callback";
    private final OAuth20Service service = new ServiceBuilder(clientId)
            .apiKey(clientId)
            .apiSecret(clientSecret)
            .callback(callbackUri)
            .scope("openid profile email")
            .responseType("code")
            .build(GoogleApi20.instance());

}
