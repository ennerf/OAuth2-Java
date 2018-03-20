package us.hebi.oauth2.client.dashboard;

import com.sun.javafx.application.HostServicesDelegate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;

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
    private HostServicesDelegate hostServices;

    @Override
    public void initialize(URL url, ResourceBundle rb) {

    }

    @FXML
    void loginViaBrowser(ActionEvent event) {
        // TODO: Replace with OAuth call
        hostServices.showDocument(browserUrl);
    }

    @FXML
    void callPublicEndpoint(ActionEvent event) {

    }

    @FXML
    void callRestrictedEndpoint(ActionEvent event) {

    }

}
