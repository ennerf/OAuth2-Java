package us.hebi.oauth2.client.dashboard;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.TextArea;
import us.hebi.oauth2.client.oauth.AuthenticationService;

import javax.inject.Inject;
import java.net.URL;
import java.util.ResourceBundle;

/**
 * @author ennerf
 */
public class DashboardPresenter implements Initializable {

    @FXML
    private TextArea textArea;

    @Inject
    private String browserUrl;

    @Inject
    private AuthenticationService authenticationService;

    @Override
    public void initialize(URL url, ResourceBundle rb) {

    }

    @FXML
    void loginViaBrowser(ActionEvent event) {
        authenticationService.requestToken();
    }

    @FXML
    void callPublicEndpoint(ActionEvent event) {

    }

    @FXML
    void callRestrictedEndpoint(ActionEvent event) {
        textArea.setText(authenticationService.requestUserInfo().orElse("N/A"));
    }

}
