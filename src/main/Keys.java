package main;

import gui.controllers.Home;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.util.ArrayList;
import java.util.Iterator;

import static main.PGPKeyTools.longToBytes;

public class Keys {
    public static final Keys instance = new Keys();

    private static final String secretKeysFileName = "secret.asc";
    private static final String publicKeysFileName = "public.asc";

    private BCPGInputStream publicIn;
    private BCPGInputStream secretIn;

    private ArmoredOutputStream secretOut;
    private ArmoredOutputStream publicOut;

    public PGPPublicKeyRingCollection pgpPublicKeyRingCollection;
    public PGPSecretKeyRingCollection pgpSecretKeyRingCollection;

    private Keys() {

        try {
            publicIn = new BCPGInputStream(PGPUtil.getDecoderStream(new BufferedInputStream(new FileInputStream(publicKeysFileName))));
            secretIn = new BCPGInputStream(PGPUtil.getDecoderStream(new BufferedInputStream(new FileInputStream(secretKeysFileName))));

            if (publicIn.available() > 0)
                pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(publicIn, new JcaKeyFingerprintCalculator());
            if (secretIn.available() > 0)
                pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(secretIn, new JcaKeyFingerprintCalculator());

        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }
    }

    public void printPublicKeys() {
        Iterator<PGPPublicKeyRing> keyRingIter = pgpPublicKeyRingCollection.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = keyRingIter.next();

            Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = keyIter.next();

                if (key.isEncryptionKey()) {
                    PGPKeyTools.printPublicKey(key);
                }
            }
        }
    }

    public PGPPrivateKey findSecretKey(long keyID, char[] pass) {
        if(pgpSecretKeyRingCollection == null)
            return null;

        try{
            PGPSecretKey pgpSecKey = pgpSecretKeyRingCollection.getSecretKey(keyID);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        }catch (Exception e){
            e.printStackTrace();
        }

        return null;
    }

    public PGPPublicKey findPublicKey(long keyID) {
        if(pgpPublicKeyRingCollection == null)
            return null;

        try{
            PGPPublicKey pgpPubKey = pgpPublicKeyRingCollection.getPublicKey(keyID);
            return pgpPubKey;

        }catch (Exception e){
            e.printStackTrace();
        }

        return null;
    }

    public void deletePublicKey(long id) throws PGPException, IOException {
        PGPPublicKeyRing ring = pgpPublicKeyRingCollection.getPublicKeyRing(id);
        pgpPublicKeyRingCollection = PGPPublicKeyRingCollection.removePublicKeyRing(pgpPublicKeyRingCollection, ring);

        ArmoredOutputStream publicOut = new ArmoredOutputStream (new FileOutputStream("public.asc"));
        pgpPublicKeyRingCollection.encode(publicOut);
        publicOut.close();
    }

    public boolean deleteSecretKey(long id, String password) throws PGPException, IOException {
        PGPSecretKeyRing ring = pgpSecretKeyRingCollection.getSecretKeyRing(id);
        PGPPrivateKey pgpPrivKey;
        try {
            pgpPrivKey = ring.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password.toCharArray()));
        }catch(Exception e){
            return false;
        }

        pgpSecretKeyRingCollection = PGPSecretKeyRingCollection.removeSecretKeyRing(pgpSecretKeyRingCollection, ring);

        ArmoredOutputStream secretOut = new ArmoredOutputStream (new FileOutputStream("secret.asc"));
        pgpSecretKeyRingCollection.encode(secretOut);
        secretOut.close();
        return true;
    }

    public ArrayList<Home.PublicKey> getPublicKeys() {
        ArrayList publicKeys = new ArrayList();

        if (pgpPublicKeyRingCollection == null) return publicKeys;

        Iterator<PGPPublicKeyRing> keyRingIter = pgpPublicKeyRingCollection.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = keyRingIter.next();

            Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = keyIter.next();

                String userId = key.getUserIDs().next();
                userId = userId.substring(0, userId.length() - 1);
                String name = userId.split("<")[0];
                String email = userId.split("<")[1];
                String keyId = Hex.toHexString(longToBytes(key.getKeyID()));

                Home.PublicKey publicKey = new Home.PublicKey(name, keyId, email);
                publicKeys.add(publicKey);
                break;
            }
        }
        return publicKeys;
    }

    public ArrayList<Home.PrivateKey> getPrivateKeys(){
        ArrayList<Home.PrivateKey> privateKeys = new ArrayList<>();
        if (pgpSecretKeyRingCollection == null) return privateKeys;

        Iterator<PGPSecretKeyRing> keyRingIter = pgpSecretKeyRingCollection.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = keyRingIter.next();

            Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = keyIter.next();

                if (key.isSigningKey()) {
                    String userId = key.getUserIDs().next();
                    userId = userId.substring(0, userId.length() - 1);
                    String name = userId.split("<")[0];
                    String email = userId.split("<")[1];
                    String keyId = Hex.toHexString(longToBytes(key.getKeyID()));

                    Home.PrivateKey privateKey = new Home.PrivateKey(name, keyId, email);
                    privateKeys.add(privateKey);
                    break;
                }
            }
        }
        return privateKeys;
    }

    public void printPrivateKeys(){
        Iterator<PGPSecretKeyRing> keyRingIter = pgpSecretKeyRingCollection.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = keyRingIter.next();

            Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = keyIter.next();

                PGPKeyTools.printSecretKey(key);

            }
        }
    }

    public void addPublicKeyRing(PGPPublicKeyRing pgpPublicKeyRing) throws IOException, PGPException {
        if (pgpPublicKeyRingCollection == null)
            pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(pgpPublicKeyRing.getEncoded(), new JcaKeyFingerprintCalculator());
        else
            pgpPublicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(Keys.instance.pgpPublicKeyRingCollection, pgpPublicKeyRing);

        ArmoredOutputStream publicOut = new ArmoredOutputStream (new FileOutputStream("public.asc"));
        pgpPublicKeyRingCollection.encode(publicOut);
        publicOut.close();
    }

    public void addSecretKeyRing(PGPSecretKeyRing pgpSecretKeyRing) throws IOException, PGPException {
        if (pgpSecretKeyRingCollection == null)
            pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(pgpSecretKeyRing.getEncoded(), new JcaKeyFingerprintCalculator());
        else
            pgpSecretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(Keys.instance.pgpSecretKeyRingCollection, pgpSecretKeyRing);
        ArmoredOutputStream secretOut = new ArmoredOutputStream (new FileOutputStream("secret.asc"));
        pgpSecretKeyRingCollection.encode(secretOut);
        secretOut.close();
    }

    public static void main(String[] args){
        instance.printPrivateKeys();
    }
}
