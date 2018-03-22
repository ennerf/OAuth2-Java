package us.hebi.oauth2.client.dashboard;

import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import us.hebi.oauth2.client.oauth.AuthenticationService;

import javax.inject.Inject;
import java.net.URL;
import java.util.ResourceBundle;

/**
 * @author ennerf
 */
public class DashboardPresenter implements Initializable {

    @FXML
    private TextField urlField;

    @FXML
    private TextArea textArea;

    @Inject
    private String browserUrl;

    @Inject
    private AuthenticationService authenticationService;

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        // deprecated user info: https://www.googleapis.com/oauth2/v2/userinfo
        // field selection: https://www.googleapis.com/plus/v1/people/me?fields=id,displayName,domain
        urlField.setText("https://www.googleapis.com/plus/v1/people/me");
    }

    @FXML
    void requestAccessToken(ActionEvent event) {
        authenticationService.requestAccessToken();
    }

    @FXML
    void refreshAccessToken(ActionEvent event) {
        authenticationService.refreshAccessToken();
    }

    @FXML
    void deleteAccessToken(ActionEvent event) {
        authenticationService.revokeAccessToken();
    }

    @FXML
    void createSignedGetRequest(ActionEvent event) {
        OAuthRequest oReq = new OAuthRequest(Verb.GET, urlField.getText());
        textArea.setText(authenticationService.requestSigned(oReq).orElse("N/A"));
    }

}
