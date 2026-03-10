module kz.team.aesmy.shantae {
        requires javafx.controls;
        requires javafx.fxml;

        opens kz.team.aesmy.shantae to javafx.graphics, javafx.fxml;
        opens kz.team.aesmy.shantae.Controller to javafx.fxml, javafx.base;

        exports kz.team.aesmy.shantae;
}