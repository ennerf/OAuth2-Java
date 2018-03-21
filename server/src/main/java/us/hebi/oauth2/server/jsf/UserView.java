package us.hebi.oauth2.server.jsf;

import javax.enterprise.context.RequestScoped;
import javax.faces.context.FacesContext;
import javax.inject.Named;
import java.util.Map;

/**
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 21 Mar 2018
 */
@Named
@RequestScoped
public class UserView {

    public String getName() {
        Map<String, Object> sessionMap = FacesContext.getCurrentInstance().getExternalContext().getSessionMap();
        return String.valueOf(sessionMap.get("user"));
    }

    public String getDetails() {
        Map<String, Object> sessionMap = FacesContext.getCurrentInstance().getExternalContext().getSessionMap();
        return String.valueOf(sessionMap.get("userInfo"));
    }

}
