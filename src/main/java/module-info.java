module kz.team.aesmy.shantae {
    requires javafx.controls;
    requires javafx.fxml;


    opens kz.team.aesmy.shantae to javafx.fxml;
    exports kz.team.aesmy.shantae;
}