package us.hebi.oauth2.server.rest;

import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.ejb.Stateless;
import javax.inject.Inject;
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

        // Check if user is authenticated
        String token = headers.getRequestHeaders().getFirst("Authorization");
        if (token == null)
            return Response.status(Response.Status.FORBIDDEN).build();
        token = token.substring("Bearer ".length());

        // Check if user is authorized
        OAuthRequest oReq = new OAuthRequest(Verb.GET, "https://www.googleapis.com/plus/v1/people/me");
        service.signRequest(token, oReq);
        String json = service.execute(oReq).getBody();

        // TODO: filter users based on e.g. domain

        // Respond
        return Response.ok(json).build();

    }

    @Inject
    OAuth20Service service;

}
