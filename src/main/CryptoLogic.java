package main;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.Strings;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Date;
import java.util.Iterator;

public class CryptoLogic {
    public static final CryptoLogic instance = new CryptoLogic();

    private CryptoLogic() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void generateKeyPair() {
        try {
            String identity = UserState.instance.email;
            String passPhrase = UserState.instance.password;
            int keySize = UserState.instance.keySize;

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(keySize);

            KeyPair pair = kpg.generateKeyPair();

            PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, new Date());
            PGPKeyRingGenerator pgpKeyRingGenerator = new PGPKeyRingGenerator(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity,
                    sha1Calc, null, null,
                    new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                    new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase.toCharArray()));

            PGPSecretKeyRing pgpSecretKeyRing = pgpKeyRingGenerator.generateSecretKeyRing();
            PGPPublicKeyRing pgpPublicKeyRing = pgpKeyRingGenerator.generatePublicKeyRing();

            Keys.getInstance().addPublicKeyRing(pgpPublicKeyRing);
            Keys.getInstance().addSecretKeyRing(pgpSecretKeyRing);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void readKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));

        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        Iterator iter = pgpObjectFactory.iterator();
        while (iter.hasNext()) {
            Object pgpFactory = iter.next();
            if (pgpFactory instanceof PGPPublicKeyRing) {
                PGPPublicKeyRing keyRing = (PGPPublicKeyRing) pgpFactory;
                Keys.getInstance().addPublicKeyRing(keyRing);

            } else if (pgpFactory instanceof PGPSecretKeyRing) {
                PGPSecretKeyRing keyRing = (PGPSecretKeyRing) pgpFactory;
                Keys.getInstance().addSecretKeyRing(keyRing);
            }
        }
    }

    public static void exportKey(PGPKeyRing keyRing, String destination) throws IOException {
        ArmoredOutputStream outputStream = new ArmoredOutputStream(new FileOutputStream(destination));
        keyRing.encode(outputStream);
        outputStream.close();
    }


    public static void sendMessage() throws IOException, PGPException {
        final int BUFFER_SIZE = 1 << 16;

        OutputStream outputStream;
        OutputStream encryptedOut;
        OutputStream compressedOut;
        OutputStream literalOut;

        boolean sign = UserState.instance.sign;
        boolean compress = UserState.instance.compress;
        boolean encrypt = UserState.instance.encrypt;
        boolean armor = UserState.instance.radix64;

        String inputFileName = UserState.instance.inputFileName;
        String outputFileName = UserState.instance.outputFileName;

        PGPPublicKey publicKey = UserState.instance.publicKey;
        PGPSecretKey secretKey = UserState.instance.secretKey;
        char[] password = UserState.instance.pass.toCharArray();

        if (!sign && !compress && !encrypt){
            FileUtils.copyFile(new File(inputFileName), new File(outputFileName));
            return;
        }

        outputStream = new BufferedOutputStream(new FileOutputStream(outputFileName));

        if (armor)
            outputStream = new ArmoredOutputStream(outputStream);

        // Init encrypted data generator
        PGPEncryptedDataGenerator encryptedDataGenerator =
                new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));

        encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

        encryptedOut = outputStream;
        if (encrypt)
            encryptedOut = encryptedDataGenerator.open(outputStream, new byte[BUFFER_SIZE]);

        // Init compression
         PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
         compressedOut = encryptedOut;
         if (compress)
            compressedOut = compressedDataGenerator.open(encryptedOut);

        // Init signature
        PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password));
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        Iterator it = secretKey.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            spGen.setSignerUserID(false, (String) it.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        if (sign)
            signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

        // Create the Literal Data generator output stream
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY,
                String.valueOf(PGPLiteralData.TEXT), new Date(), new byte[BUFFER_SIZE]);

        // Open the input file
        InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFileName));
        int ch;
        while ((ch = inputStream.read()) >= 0)
        {
            literalOut.write(ch);
            signatureGenerator.update((byte)ch);
        }

        literalOut.close();
        literalDataGenerator.close();
        if (sign)
            signatureGenerator.generate().encode(compressedOut);
        compressedOut.close();
        compressedDataGenerator.close();
        encryptedOut.close();
        encryptedDataGenerator.close();
        inputStream.close();
        outputStream.close();
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            UserState.instance.publicKey = Keys.getInstance().pgpPublicKeyRingCollection.getPublicKey(new BigInteger("9dfa654cc9b45f65", 16).longValue());
            UserState.instance.secretKey = Keys.getInstance().pgpSecretKeyRingCollection.getSecretKey(new BigInteger("9dfa654cc9b45f65", 16).longValue());
            UserState.instance.pass = "test";

            UserState.instance.inputFileName = "poruka.txt";
            UserState.instance.outputFileName = "poruka.txt.asc";
            UserState.instance.radix64 = true;
            UserState.instance.compress = true;
            UserState.instance.encrypt = false;
            UserState.instance.sign = true;

            sendMessage();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}


