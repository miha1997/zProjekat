package gui.controllers;

import javafx.beans.property.SimpleStringProperty;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeTableCell;
import javafx.scene.control.TreeTableColumn;
import javafx.scene.control.TreeTableView;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Callback;
import main.CryptoLogic;
import main.Keys;
import main.PGPKeyTools;
import org.bouncycastle.openpgp.*;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.Objects;
import java.util.ResourceBundle;

public class Home implements Initializable {
    @FXML
    private TreeTableView<PrivateKey> privateTableView;
    @FXML
    private TreeTableColumn<PrivateKey, String> keyIDColumnPrivate;
    @FXML
    private TreeTableColumn<PrivateKey, String> nameColumnPrivate;
    @FXML
    private TreeTableColumn<PrivateKey, String> emailColumnPrivate;

    @FXML
    private TreeTableView<PublicKey> publicTableView;
    @FXML
    private TreeTableColumn<PublicKey, String> keyIDColumnPublic;
    @FXML
    private TreeTableColumn<PublicKey, String> nameColumnPublic;
    @FXML
    private TreeTableColumn<PublicKey, String> emailColumnPublic;

    public static Home instance;

    public void newKeyPair(ActionEvent event){
        Parent root;
        try {
            root = FXMLLoader.load(Objects.requireNonNull(getClass().getClassLoader().getResource("gui/layouts/newKeyPair.fxml")));
            Stage stage = new Stage();
            stage.setTitle("New Key Pair");
            stage.setScene(new Scene(root, 600, 400));
            stage.show();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void importKey(ActionEvent event){
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(null);

        if(selectedFile != null) {
            try{
                CryptoLogic.instance.readKey(selectedFile.getAbsolutePath());
                loadKeyList();
            }
            catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public void exportKey(ActionEvent event){
        TreeItem<PrivateKey> item = privateTableView.getSelectionModel().getSelectedItem();
        if (item == null) return;

        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showSaveDialog(null);

        if(file != null) {
            try{
                long id = new BigInteger(item.getValue().getKeyIdProperty().getValue(), 16).longValue();
                PGPPublicKeyRing key = Keys.instance.pgpPublicKeyRingCollection.getPublicKeyRing(id);

                PGPSecretKeyRing secKey = Keys.instance.pgpSecretKeyRingCollection.getSecretKeyRing(id);
                if (secKey != null) {
                    CryptoLogic.exportSecretKey(secKey, file.getAbsolutePath());
                    return;
                }

                if (key != null){
                    CryptoLogic.exportPublicKey(key, file.getAbsolutePath());
                }

            }
            catch (Exception e){
                e.printStackTrace();
            }
        }
    }


    @Override
    public void initialize(URL location, ResourceBundle resources) {
        instance = this;
        loadKeyList();
    }

    public void loadKeyList(){
        TreeItem<PrivateKey> privateKeyRoot = new TreeItem<>(new PrivateKey("identity", "keyId", "email"));

        for(PrivateKey privateKey: Keys.instance.getPrivateKeys()){
            TreeItem<PrivateKey> privateKeyTreeItem = new TreeItem<>(privateKey);
            privateKeyRoot.getChildren().addAll(privateKeyTreeItem);
        }

        nameColumnPrivate.setCellValueFactory(param -> param.getValue().getValue().getNameProperty());
        keyIDColumnPrivate.setCellValueFactory(param -> param.getValue().getValue().getKeyIdProperty());
        emailColumnPrivate.setCellValueFactory(param -> param.getValue().getValue().getEmailProperty());

        privateTableView.setRoot(privateKeyRoot);
        privateTableView.setShowRoot(false);

        TreeItem<PublicKey> publicKeyRoot = new TreeItem<>(new PublicKey("identity", "keyID", "email"));

        for(PublicKey publicKey: Keys.instance.getPublicKeys()){
            TreeItem<PublicKey> publicKeyTreeItem = new TreeItem<PublicKey>(publicKey);
            publicKeyRoot.getChildren().addAll(publicKeyTreeItem);
        }

        nameColumnPublic.setCellValueFactory(param -> param.getValue().getValue().getNameProperty());
        keyIDColumnPublic.setCellValueFactory(param -> param.getValue().getValue().getKeyIdProperty());
        emailColumnPublic.setCellValueFactory(param -> param.getValue().getValue().getEmailProperty());

        publicTableView.setRoot(publicKeyRoot);
        publicTableView.setShowRoot(false);
    }

    public static class PrivateKey{
        SimpleStringProperty nameProperty;
        SimpleStringProperty emailProperty;
        SimpleStringProperty keyIdProperty;

        public PrivateKey(String name, String keyId, String email) {
            this.nameProperty = new SimpleStringProperty(name);
            this.keyIdProperty = new SimpleStringProperty(keyId);
            this.emailProperty = new SimpleStringProperty(email);
        }

        public SimpleStringProperty getNameProperty() {
            return nameProperty;
        }
        public SimpleStringProperty getKeyIdProperty() {
            return keyIdProperty;
        }
        public SimpleStringProperty getEmailProperty() {
            return emailProperty;
        }
    }

    public static class PublicKey {
        SimpleStringProperty nameProperty;
        SimpleStringProperty keyIdProperty;
        SimpleStringProperty emailProperty;

        public PublicKey(String name, String keyId, String email) {
            this.nameProperty = new SimpleStringProperty(name);
            this.keyIdProperty = new SimpleStringProperty(keyId);
            this.emailProperty = new SimpleStringProperty(email);
        }

        public SimpleStringProperty getNameProperty() {
            return nameProperty;
        }
        public SimpleStringProperty getKeyIdProperty() {
            return keyIdProperty;
        }
        public SimpleStringProperty getEmailProperty() {
            return emailProperty;
        }
    }
}
