package gui.controllers;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import main.CryptoLogic;
import main.Keys;
import main.UserState;
import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.File;
import java.math.BigInteger;
import java.net.URL;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.ResourceBundle;

public class SendMessage implements Initializable {
    @FXML
    private CheckBox signCheckBox;
    @FXML
    private CheckBox encryptCheckBox;
    @FXML
    private CheckBox radixCheckBox;
    @FXML
    private CheckBox compressCheckBox;

    @FXML
    private ChoiceBox signChoiceBox;
    @FXML
    private ChoiceBox encryptChoiceBox;

    @FXML
    private PasswordField passwordTextField;

    @FXML
    private Label errorLabel;

    @FXML
    private Label labelEncryption;

    @FXML
    private RadioButton radio3DES;

    @FXML
    private RadioButton radioCAST5;

    @FXML
    private ListView<Home.PublicKey> keyListView;

    private ArrayList<Home.PublicKey> addedPublicKeys;


    @Override
    public void initialize(URL location, ResourceBundle resources) {
        loadData();
    }

    private void loadData(){
        addedPublicKeys = new ArrayList<>();

        ArrayList<Home.PublicKey> publicKeys = Keys.instance.getPublicKeys();
        ArrayList<Home.PrivateKey> privateKeys = Keys.instance.getPrivateKeys();

        ObservableList<Home.PrivateKey> observableListPrivateKeys = FXCollections.observableList(privateKeys);
        signChoiceBox.setItems(observableListPrivateKeys);
        if(privateKeys.size() > 0)
            signChoiceBox.setValue(observableListPrivateKeys.get(0));

        ObservableList<Home.PublicKey> observableListPublicKeys = FXCollections.observableList(publicKeys);
        encryptChoiceBox.setItems(observableListPublicKeys);

        if(publicKeys.size() > 0)
            encryptChoiceBox.setValue(observableListPublicKeys.get(0));
    }

    public void addPublicKey(ActionEvent event){
        Home.PublicKey selectedKey = (Home.PublicKey) encryptChoiceBox.getSelectionModel().getSelectedItem();
        if(addedPublicKeys.contains(selectedKey))
            return;

        addedPublicKeys.add(selectedKey);

        ObservableList<Home.PublicKey> observableListPublicKeys = FXCollections.observableList(addedPublicKeys);
        keyListView.setItems(observableListPublicKeys);

    }

    public void signMessageClicked(ActionEvent event){
        if(signCheckBox.isSelected()){
            passwordTextField.setVisible(true);

        }else{
            passwordTextField.setVisible(false);
        }

    }

    public void encryptionClicked(ActionEvent event){
        if(encryptCheckBox.isSelected()){
            labelEncryption.setVisible(true);
            radio3DES.setVisible(true);
            radioCAST5.setVisible(true);

        }else{
            labelEncryption.setVisible(false);
            radio3DES.setVisible(false);
            radioCAST5.setVisible(false);
        }

    }

    public void sendMessage(ActionEvent event){
        if(signCheckBox.isSelected() && passwordTextField.getText().equals("")){
            errorLabel.setVisible(true);
            return;
        }

        if(encryptCheckBox.isSelected() && addedPublicKeys.size() == 0){
            errorLabel.setText("Add at least one public key!");
            errorLabel.setVisible(true);
            return;
        }

        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showSaveDialog(null);

        if (selectedFile != null) {
            UserState.instance.outputFileName = selectedFile.getAbsolutePath();

        }

        UserState.instance.sign = signCheckBox.isSelected();
        UserState.instance.encrypt = encryptCheckBox.isSelected();
        UserState.instance.radix64 = radixCheckBox.isSelected();
        UserState.instance.compress = compressCheckBox.isSelected();
        UserState.instance.pass = "";

        if(encryptCheckBox.isSelected()){
            boolean cast5 = false;
            if(radioCAST5.isSelected())
                cast5 = true;

            UserState.instance.cast5 = cast5;

            ArrayList<PGPPublicKey> publicKeys = new ArrayList<>();
            for (Home.PublicKey key : addedPublicKeys) {
                publicKeys.add(Keys.instance.findPublicKey(new BigInteger(key.keyIdProperty.getValue(), 16).longValue()));
            }
            UserState.instance.publicKeys = publicKeys;
        }


        if(signCheckBox.isSelected()){
            try{
                UserState.instance.secretKey = Keys.instance.pgpSecretKeyRingCollection.getSecretKey(new BigInteger(((Home.PrivateKey)signChoiceBox.getSelectionModel().getSelectedItem()).keyIdProperty.getValue(), 16).longValue());
                UserState.instance.pass = passwordTextField.getText();
            }catch (Exception e){
                e.printStackTrace();
            }
        }

        try{
            CryptoLogic.sendMessage();

            //close current window
            Stage stage = (Stage) errorLabel.getScene().getWindow();
            stage.close();
        }catch (Exception e){
            e.printStackTrace();
        }

    }
}
