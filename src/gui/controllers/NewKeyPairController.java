package gui.controllers;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import main.CryptoLogic;
import main.UserState;

import java.io.IOException;
import java.util.Objects;


public class NewKeyPairController {
    @FXML
    public TextField inputName;
    @FXML
    public TextField inputEmail;

    @FXML
    public RadioButton radioButton2048;
    @FXML
    public RadioButton radioButton4096;

    @FXML
    public Label errorMessageLabel;

    public void submitFormNewKeyPair(ActionEvent event){
        String name = inputName.getText();
        String email = inputEmail.getText();

        if(name.equals("")){
            errorMessageLabel.setText("Enter name!");
            errorMessageLabel.setVisible(true);
            return;
        }

        if(email.equals("")){
            errorMessageLabel.setText("Enter email!");
            errorMessageLabel.setVisible(true);
            return;
        }

        int keySize = 1024;
        if(radioButton2048.isSelected())
            keySize = 2048;

        if(radioButton4096.isSelected())
            keySize = 4096;

        //preserve data
        UserState.instance.name = name;
        UserState.instance.email = email;
        UserState.instance.keySize = keySize;

        //close current window
        Stage stage = (Stage) errorMessageLabel.getScene().getWindow();
        stage.close();

        //open new one
        Parent root;
        try {
            root = FXMLLoader.load(Objects.requireNonNull(getClass().getClassLoader().getResource("gui/layouts/enterPassword.fxml")));
            stage = new Stage();
            stage.setTitle("Enter Password");
            stage.setScene(new Scene(root, 500, 400));
            stage.show();
        }
        catch (IOException e) {
            e.printStackTrace();
        }

    }

}
