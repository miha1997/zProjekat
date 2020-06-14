package gui.controllers;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import main.CryptoLogic;
import main.UserState;

public class EnterPassword {
    @FXML
    public PasswordField inputPassword;
    @FXML
    public PasswordField inputRepeat;

    @FXML
    public Label errorMessage;

    public void submitPassword(ActionEvent event){
        String password = inputPassword.getText();
        String repeat = inputRepeat.getText();

        if(password.equals("") || repeat.equals("")){
            errorMessage.setText("Enter all fields!");
            errorMessage.setVisible(true);
            return;
        }

        if(! password.equals(repeat)){
            errorMessage.setText("Passwords are not same!");
            errorMessage.setVisible(true);
            return;
        }

        UserState.instance.password = password;
        CryptoLogic.instance.generateKeyPair();

        Home.instance.loadKeyList();

        //close current window
        Stage stage = (Stage) errorMessage.getScene().getWindow();
        stage.close();
    }

}
