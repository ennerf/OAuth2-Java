package us.hebi.oauth2.server.jsf;

import javax.faces.view.ViewScoped;
import javax.inject.Named;
import java.io.Serializable;

/**
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 21 Mar 2018
 */
@Named
@ViewScoped
public class UserView implements Serializable {

    public String getName() {
        return UserInfo.fromFacesContext()
                .map(UserInfo::getDisplayName)
                .orElse("N/A");
    }

    public String getDetails() {
        return UserInfo.fromFacesContext()
                .map(Object::toString)
                .orElse("N/A");
    }

}
