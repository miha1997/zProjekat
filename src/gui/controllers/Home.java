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
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

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
    private TreeTableColumn<PrivateKey, String> masterKeyColumnPrivate;

    @FXML
    private TreeTableView<PublicKey> publicTableView;
    @FXML
    private TreeTableColumn<PublicKey, String> keyIDColumnPublic;
    @FXML
    private TreeTableColumn<PublicKey, String> nameColumnPublic;
    @FXML
    private TreeTableColumn<PublicKey, String> masterKeyColumnPublic;

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
                PGPKeyRing key = Keys.instance.pgpPublicKeyRingCollection.getPublicKeyRing(id);
                if (key == null)
                    key = Keys.instance.pgpSecretKeyRingCollection.getSecretKeyRing(id);

                CryptoLogic.exportKey(key, file.getAbsolutePath());
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
        TreeItem<PrivateKey> privateKeyRoot = new TreeItem<>(new PrivateKey("identity", "keyId", false));

        for(PrivateKey privateKey: Keys.instance.getPrivateKeys()){
            TreeItem<PrivateKey> privateKeyTreeItem = new TreeItem<>(privateKey);
            privateKeyRoot.getChildren().addAll(privateKeyTreeItem);
        }

        nameColumnPrivate.setCellValueFactory(param -> param.getValue().getValue().getNameProperty());
        keyIDColumnPrivate.setCellValueFactory(param -> param.getValue().getValue().getKeyIdProperty());
        masterKeyColumnPrivate.setCellValueFactory(param -> param.getValue().getValue().getMasterKeyProperty());

        privateTableView.setRoot(privateKeyRoot);
        privateTableView.setShowRoot(false);

        TreeItem<PublicKey> publicKeyRoot = new TreeItem<>(new PublicKey("identity", "keyId", false));

        for(PublicKey publicKey: Keys.instance.getPublicKeys()){
            TreeItem<PublicKey> publicKeyTreeItem = new TreeItem<PublicKey>(publicKey);
            publicKeyRoot.getChildren().addAll(publicKeyTreeItem);
        }

        nameColumnPublic.setCellValueFactory(param -> param.getValue().getValue().getNameProperty());
        keyIDColumnPublic.setCellValueFactory(param -> param.getValue().getValue().getKeyIdProperty());
        masterKeyColumnPublic.setCellValueFactory(param -> param.getValue().getValue().getMasterKeyProperty());

        publicTableView.setRoot(publicKeyRoot);
        publicTableView.setShowRoot(false);
    }

    public static class PrivateKey{
        SimpleStringProperty nameProperty;
        SimpleStringProperty keyIdProperty;
        SimpleStringProperty masterKeyProperty;

        public PrivateKey(String name, String keyId, boolean masterKey) {
            this.nameProperty = new SimpleStringProperty(name);
            this.keyIdProperty = new SimpleStringProperty(keyId);

            if(masterKey)
                this.masterKeyProperty = new SimpleStringProperty("true");
            else
                this.masterKeyProperty = new SimpleStringProperty("false");
        }

        public SimpleStringProperty getNameProperty() {
            return nameProperty;
        }
        public SimpleStringProperty getKeyIdProperty() {
            return keyIdProperty;
        }
        public SimpleStringProperty getMasterKeyProperty() {
            return masterKeyProperty;
        }
    }

    public static class PublicKey {
        SimpleStringProperty nameProperty;
        SimpleStringProperty keyIdProperty;
        SimpleStringProperty masterKeyProperty;

        public PublicKey(String name, String keyId, boolean masterKey) {
            this.nameProperty = new SimpleStringProperty(name);
            this.keyIdProperty = new SimpleStringProperty(keyId);

            if(masterKey)
                this.masterKeyProperty = new SimpleStringProperty("true");
            else
                this.masterKeyProperty = new SimpleStringProperty("false");
        }

        public SimpleStringProperty getNameProperty() {
            return nameProperty;
        }
        public SimpleStringProperty getKeyIdProperty() {
            return keyIdProperty;
        }
        public SimpleStringProperty getMasterKeyProperty() {
            return masterKeyProperty;
        }
    }
}
