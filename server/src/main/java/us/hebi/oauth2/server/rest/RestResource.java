package us.hebi.oauth2.server.rest;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import us.hebi.oauth2.server.jsf.UserInfo;

import javax.ejb.Stateless;
import javax.json.Json;
import javax.json.JsonObject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
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
    public Response getPublicItem(@PathParam("id") int id, @Context HttpServletRequest request) throws Exception {
        // Add some state to check that sessions are working
        HttpSession session = request.getSession();
        try {
            JsonObject json = Json.createObjectBuilder()
                    .add("id", id)
                    .add("previousId", String.valueOf(session.getAttribute("id")))
                    .build();
            return Response.ok(json).build();
        } finally {
            session.setAttribute("id", id);
        }
    }

    @GET
    @Path("private/{id}")
    public Response getPrivateItem(@PathParam("id") int id, @Context HttpHeaders headers) throws Exception {

        // Copy authorization header to outgoing request. Note that the value is "Bearer " followed by the token
        OAuthRequest oReq = new OAuthRequest(Verb.GET, UserInfo.API_ENDPOINT);
        oReq.addHeader("Authorization", headers.getRequestHeaders().getFirst("Authorization"));

        // Call external service
        String json = client.execute(oReq).getBody();
        return Response.ok(json).build();

    }

    // Dummy client for sending the web requests
    private final OAuth20Service client = new ServiceBuilder("N/A")
            .apiSecret("N/A")
            .build(GoogleApi20.instance());

}
