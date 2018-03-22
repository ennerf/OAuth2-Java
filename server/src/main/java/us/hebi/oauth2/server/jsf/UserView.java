package us.hebi.oauth2.server.jsf;

import javax.faces.context.FacesContext;
import javax.faces.view.ViewScoped;
import javax.inject.Named;
import java.io.Serializable;
import java.util.Map;

/**
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 21 Mar 2018
 */
@Named
@ViewScoped
public class UserView implements Serializable {

    public String getName() {
        Map<String, Object> sessionMap = FacesContext.getCurrentInstance().getExternalContext().getSessionMap();
        return String.valueOf(sessionMap.get("user"));
    }

    public String getDetails() {
        Map<String, Object> sessionMap = FacesContext.getCurrentInstance().getExternalContext().getSessionMap();
        return String.valueOf(sessionMap.get("userInfo"));
    }

}
