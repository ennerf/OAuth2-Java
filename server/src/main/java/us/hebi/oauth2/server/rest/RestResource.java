package us.hebi.oauth2.server.rest;

import us.hebi.oauth2.server.OAuthAuthorizationService;

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

import static javax.ws.rs.core.Response.Status.*;

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
        // TODO: filter users based on e.g. domain
        return service.extractAccessToken(headers.getRequestHeaders())
                .flatMap(service::getUserInfo)
                .map(Response::ok)
                .orElseGet(() -> Response.status(FORBIDDEN))
                .build();

    }

    @Inject
    OAuthAuthorizationService service;

}
