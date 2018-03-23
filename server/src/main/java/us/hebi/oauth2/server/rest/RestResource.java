package us.hebi.oauth2.server.rest;

import javax.ejb.Stateless;
import javax.json.Json;
import javax.json.JsonObject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.*;
import java.util.Optional;

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

        // Check if user is authenticated
        // TODO: filter users based on e.g. domain
        return extractAccessToken(headers.getRequestHeaders())
                .map(Response::ok)
                .orElseGet(() -> Response.status(FORBIDDEN))
                .build();

    }

    private Optional<String> extractAccessToken(MultivaluedMap<String, String> requestHeaders) {
        return Optional.ofNullable(requestHeaders.getFirst("Authorization"))
                .map(str -> str.substring("Bearer ".length()));
    }

}
