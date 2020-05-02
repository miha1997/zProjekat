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
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Iterator;
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

    public static Home instance;

    public void newKeyPair(ActionEvent event){
        Parent root;
        try {
            root = FXMLLoader.load(getClass().getClassLoader().getResource("gui/layouts/newKeyPair.fxml"));
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
                CryptoLogic.getCryptoLogic().readKey(selectedFile.getAbsolutePath());
                loadKeyList();
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
        TreeItem<PrivateKey> privateKeyRoot = new TreeItem<>(new PrivateKey("name", "keyId", false));

        for(PrivateKey privateKey: Keys.getInstance().getPrivateKeys()){
            TreeItem<PrivateKey> privateKeyTreeItem = new TreeItem<>(privateKey);
            privateKeyRoot.getChildren().addAll(privateKeyTreeItem);
        }

        nameColumnPrivate.setCellValueFactory(new Callback<TreeTableColumn.CellDataFeatures<PrivateKey, String>, ObservableValue<String>>() {
            @Override
            public ObservableValue<String> call(TreeTableColumn.CellDataFeatures<PrivateKey, String> param) {
                return param.getValue().getValue().getNameProperty();
            }
        });

        keyIDColumnPrivate.setCellValueFactory(new Callback<TreeTableColumn.CellDataFeatures<PrivateKey, String>, ObservableValue<String>>() {
            @Override
            public ObservableValue<String> call(TreeTableColumn.CellDataFeatures<PrivateKey, String> param) {
                return param.getValue().getValue().getKeyIdProperty();
            }
        });

        masterKeyColumnPrivate.setCellValueFactory(new Callback<TreeTableColumn.CellDataFeatures<PrivateKey, String>, ObservableValue<String>>() {
            @Override
            public ObservableValue<String> call(TreeTableColumn.CellDataFeatures<PrivateKey, String> param) {
                return param.getValue().getValue().getMasterKeyProperty();
            }
        });

        privateTableView.setRoot(privateKeyRoot);
        privateTableView.setShowRoot(false);

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
}
