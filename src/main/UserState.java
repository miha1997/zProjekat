package main;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class UserState {
    //for generating keyPair
    private String name;
    private String email;
    private String password;
    private int keySize;

    private boolean sign;
    private PGPSecretKey secretKey;
    private PGPPublicKey publicKey;
    private String pass;

    private static UserState userState;

    private UserState(){

    }

    public static UserState getUserState(){
        if(userState == null)
            userState = new UserState();

        return userState;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public boolean isSign() {
        return sign;
    }

    public void setSign(boolean sign) {
        this.sign = sign;
    }

    public PGPSecretKey getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(PGPSecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public String getPass() {
        return pass;
    }

    public void setPass(String pass) {
        this.pass = pass;
    }

    public PGPPublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PGPPublicKey publicKey) {
        this.publicKey = publicKey;
    }
}
