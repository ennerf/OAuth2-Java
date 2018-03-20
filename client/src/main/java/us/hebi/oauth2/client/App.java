package us.hebi.oauth2.client;

import com.airhacks.afterburner.injection.Injector;
import com.sun.deploy.uitoolkit.impl.fx.HostServicesFactory;
import com.sun.javafx.application.HostServicesDelegate;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;
import us.hebi.oauth2.client.dashboard.DashboardView;

import java.util.Locale;

/**
 * @author ennerf
 */
public class App extends Application {

    @Override
    public void start(Stage stage) throws Exception {

        // Add host services for opening browser windows
        HostServicesDelegate hostServices = HostServicesFactory.getInstance(this);
        Injector.setModelOrService(HostServicesDelegate.class, hostServices);

        // Default language
        Locale.setDefault(Locale.ENGLISH);

        // Start application
        DashboardView appView = new DashboardView();
        Scene scene = new Scene(appView.getView());
        stage.setTitle("JavaFX Application");
        final String uri = getClass().getResource("app.css").toExternalForm();
        scene.getStylesheets().add(uri);
        stage.setScene(scene);
        stage.show();

    }

    @Override
    public void stop() throws Exception {
        Injector.forgetAll();
    }

    public static void main(String[] args) {
        launch(args);
    }

}
