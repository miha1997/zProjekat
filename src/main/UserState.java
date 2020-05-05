package main;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class UserState {
    //for generating keyPair
    public String name;
    public String email;
    public String password;
    public int keySize;

    public boolean sign;
    public PGPSecretKey secretKey;
    public PGPPublicKey publicKey;
    public String pass;
    public boolean radix64;
    public boolean encrypt;
    public boolean compress;
    public String inputFileName;
    public String outputFileName;
    public String signatureFileName;

    public static final UserState instance = new UserState();

    private UserState(){
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

    public boolean isRadix64() {
        return radix64;
    }

    public void setRadix64(boolean radix64) {
        this.radix64 = radix64;
    }

    public boolean isEncrypt() {
        return encrypt;
    }

    public void setEncrypt(boolean encrypt) {
        this.encrypt = encrypt;
    }

    public boolean isCompress() {
        return compress;
    }

    public void setCompress(boolean compress) {
        this.compress = compress;
    }

    public String getInputFileName() {
        return inputFileName;
    }

    public void setInputFileName(String inputFileName) {
        this.inputFileName = inputFileName;
    }

    public String getOutputFileName() {
        return outputFileName;
    }

    public void setOutputFileName(String outputFileName) {
        this.outputFileName = outputFileName;
    }
}
