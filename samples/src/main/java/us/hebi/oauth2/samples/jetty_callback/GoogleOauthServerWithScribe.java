package us.hebi.oauth2.samples.jetty_callback;

/**
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 21 Mar 2018
 */

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.*;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.github.scribejava.core.oauth.OAuthService;
import com.google.common.collect.ImmutableMap;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

/**
 * Same as original GoogleOauthServer, but using the Scribe library rather than text urls
 * See https://github.com/scribejava/scribejava
 * <p>
 * Sort of following https://oneminutedistraction.wordpress.com/2014/04/29/using-oauth-for-your-javaee-login/
 */
public class GoogleOauthServerWithScribe {

    private Server server = new Server(8089);

    private final String clientId = "739350014484-j652uuj1mrq8p3r5m5kt0kjs9b1fmaag.apps.googleusercontent.com";
    private final String clientSecret = "V2q2tbZ4Zv7cPFy7fHtUFnd9";
    private final String callbackUri = "http://localhost:8089/callback";

    public static void main(String[] args) throws Exception {
        new GoogleOauthServerWithScribe().startJetty();
    }

    public void startJetty() throws Exception {

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        server.setHandler(context);

        // map servlets to endpoints
        context.addServlet(new ServletHolder(new SigninServlet()), "/signin");
        context.addServlet(new ServletHolder(new CallbackServlet()), "/callback");

        server.start();
        server.join();
    }

    class SigninServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

            GoogleApi20 api = GoogleApi20.instance();
            OAuth20Service service = new ServiceBuilder(clientId)
                    .apiKey(clientId) // the client id from the api console registration
                    .apiSecret(clientSecret)
                    .callback(callbackUri) // the servlet that google redirects to after authorization
                    .scope("openid profile email") // scope is the api permissions we are requesting
                    .state("state to correlate the response such as session id")
                    .responseType("code")
                    .debug()
                    .build(api);

            // Add to session
            req.getSession().setAttribute("oauth2service", service);

            Map<String, String> additionalParams = new HashMap<>();
            additionalParams.put("access_type", "offline"); // here we are asking to access to user's data while they are not signed in
            additionalParams.put("approval_prompt", "force"); // this requires them to verify which account to use, if they are already signed in

            String authUrl = api.getAuthorizationUrl(service.getConfig(), additionalParams);
            resp.sendRedirect(authUrl);

        }
    }

    class CallbackServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            // google redirects with
            /*
                http://localhost:8089/callback?
                    state=this_can_be_anything_to_help_correlate_the_response%3Dlike_session_id
                    &code=4/ygE-kCdJ_pgwb1mKZq3uaTEWLUBd.slJWq1jM9mcUEnp6UAPFm0F2NQjrgwI
                    &authuser=0
                    &prompt=consent
                    &session_state=a3d1eb134189705e9acf2f573325e6f30dd30ee4..d62c
            */

            // if the user denied access, we get back an error, ex
            // error=access_denied&state=session%3Dpotatoes
            if (req.getParameter("error") != null) {
                resp.getWriter().println(req.getParameter("error"));
                return;
            }

            // Construct the access token from the returned authorization code
            OAuth20Service service = (OAuth20Service) req.getSession().getAttribute("oauth2service");
            final OAuth2AccessToken token;
            try {
                token = service.getAccessToken(req.getParameter("code"));
                req.getSession().setAttribute("token", token);
            } catch (Exception e) {
                resp.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
                return;
            }

            // ex. returns
            /*
            {
			    "access_token": "ya29.AHES6ZQS-BsKiPxdU_iKChTsaGCYZGcuqhm_A5bef8ksNoU",
			    "token_type": "Bearer",
			    "expires_in": 3600,
			    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA5ZmE5NmFjZWNkOGQyZWRjZmFiMjk0NDRhOTgyN2UwZmFiODlhYTYifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIiwiZW1haWwiOiJhbmRyZXcucmFwcEBnbWFpbC5jb20iLCJhdWQiOiI1MDgxNzA4MjE1MDIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdF9oYXNoIjoieUpVTFp3UjVDX2ZmWmozWkNublJvZyIsInN1YiI6IjExODM4NTYyMDEzNDczMjQzMTYzOSIsImF6cCI6IjUwODE3MDgyMTUwMi5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImlhdCI6MTM4Mjc0MjAzNSwiZXhwIjoxMzgyNzQ1OTM1fQ.Va3kePMh1FlhT1QBdLGgjuaiI3pM9xv9zWGMA9cbbzdr6Tkdy9E-8kHqrFg7cRiQkKt4OKp3M9H60Acw_H15sV6MiOah4vhJcxt0l4-08-A84inI4rsnFn5hp8b-dJKVyxw1Dj1tocgwnYI03czUV3cVqt9wptG34vTEcV3dsU8",
			    "refresh_token": "1/Hc1oTSLuw7NMc3qSQMTNqN6MlmgVafc78IZaGhwYS-o"
			}
			*/

            // get some info about the user with the access token
            OAuthRequest oReq = new OAuthRequest(Verb.GET, "https://www.googleapis.com/oauth2/v2/userinfo");
            service.signRequest(token, oReq);
            final Response oResp;
            try {
                oResp = service.execute(oReq);
            } catch (Exception e) {
                resp.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
                return;
            }

            // return the json of the user's basic info
            resp.getWriter().println(oResp.getBody());

        }
    }

    // makes a GET request to url and returns body as a string
    public String get(String url) throws ClientProtocolException, IOException {
        return execute(new HttpGet(url));
    }

    // makes a POST request to url with form parameters and returns body as a string
    public String post(String url, Map<String, String> formParameters) throws ClientProtocolException, IOException {
        HttpPost request = new HttpPost(url);

        List<NameValuePair> nvps = new ArrayList<NameValuePair>();

        for (String key : formParameters.keySet()) {
            nvps.add(new BasicNameValuePair(key, formParameters.get(key)));
        }

        request.setEntity(new UrlEncodedFormEntity(nvps));

        return execute(request);
    }

    // makes request and checks response code for 200
    private String execute(HttpRequestBase request) throws ClientProtocolException, IOException {
        HttpClient httpClient = new DefaultHttpClient();
        HttpResponse response = httpClient.execute(request);

        HttpEntity entity = response.getEntity();
        String body = EntityUtils.toString(entity);

        if (response.getStatusLine().getStatusCode() != 200) {
            throw new RuntimeException("Expected 200 but got " + response.getStatusLine().getStatusCode() + ", with body " + body);
        }

        return body;
    }

}
