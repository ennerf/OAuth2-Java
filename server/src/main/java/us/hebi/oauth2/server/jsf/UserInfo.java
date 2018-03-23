package us.hebi.oauth2.server.jsf;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import lombok.Getter;

import javax.faces.context.FacesContext;
import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * Entity for mapping Google+ user info
 *
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 23 Mar 2018
 */
@Getter
public class UserInfo implements Serializable {

    String kind;
    String etag;
    String gender;
    List<Email> emails;
    String objectType;
    String id;
    String displayName;
    Name name;
    String url;
    Image image;
    boolean isPlusUser;
    String language;
    int circledByCount;
    boolean verified;
    String domain;

    @Getter
    public static class Email implements Serializable {
        String value;
        String type;
    }

    @Getter
    public static class Image implements Serializable {
        String url;
        boolean isDefault;
    }

    @Getter
    public static class Name implements Serializable {
        String familyName;
        String givenName;
    }

    @Override
    public String toString() {
        return gson.toJson(this);
    }

    public static UserInfo fromJson(String json) {
        return gson.fromJson(json, UserInfo.class);
    }

    public static Optional<UserInfo> fromFacesContext() {
        Map<String, Object> sessionMap = FacesContext.getCurrentInstance().getExternalContext().getSessionMap();
        return fromMap(sessionMap::get);
    }

    public static Optional<UserInfo> fromSession(HttpSession session) {
        return fromMap(session::getAttribute);
    }

    public void storeInSession(HttpSession session) {
        session.setAttribute(SESSION_VAR, this);
    }

    private static Optional<UserInfo> fromMap(Function<String, Object> getter) {
        Object obj = getter.apply(SESSION_VAR);
        if (obj != null && obj instanceof UserInfo)
            return Optional.of((UserInfo) obj);
        return Optional.empty();
    }

    public static String API_ENDPOINT = "https://www.googleapis.com/plus/v1/people/me";
    private static String SESSION_VAR = "userInfo";
    private static Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .serializeNulls()
            .create();

}
