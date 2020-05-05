package main;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

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
            String identity = UserState.instance.name + "<" + UserState.instance.email + ">";
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

            Keys.instance.addPublicKeyRing(pgpPublicKeyRing);
            Keys.instance.addSecretKeyRing(pgpSecretKeyRing);
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
                Keys.instance.addPublicKeyRing(keyRing);

            } else if (pgpFactory instanceof PGPSecretKeyRing) {
                PGPSecretKeyRing keyRing = (PGPSecretKeyRing) pgpFactory;
                Keys.instance.addSecretKeyRing(keyRing);
            }
        }
    }

    public static void exportPublicKey(PGPPublicKeyRing keyRing, String destination) throws IOException {
        ArmoredOutputStream outputStream = new ArmoredOutputStream(new FileOutputStream(destination));
        keyRing.encode(outputStream);
        outputStream.close();
    }

    public static void exportSecretKey(PGPSecretKeyRing keyRing, String destination) throws IOException {
        ArmoredOutputStream outputStream = new ArmoredOutputStream(new FileOutputStream(destination));
        keyRing.encode(outputStream);
        outputStream.close();
    }

    public static void sendMessage() {
        final int BUFFER_SIZE = 1 << 16;
        //declare all streams used
        OutputStream outputStream;
        OutputStream encryptedOut = null;
        OutputStream compressedOut = null;
        OutputStream literalOut;
        PGPSignatureGenerator signatureGenerator = null;
        PGPCompressedDataGenerator compressedDataGenerator = null;
        PGPEncryptedDataGenerator encryptedDataGenerator = null;


        //get user input
        boolean sign = UserState.instance.isSign();
        boolean encrypt = UserState.instance.isEncrypt();
        boolean compress = UserState.instance.isCompress();
        boolean radix64 = UserState.instance.isRadix64();

        String inputFileName = UserState.instance.getInputFileName();
        String outputFileName = UserState.instance.getOutputFileName();

        try {
            if(!sign && !encrypt && !compress && !radix64){
                FileUtils.copyFile(new File(inputFileName), new File(outputFileName));
                return;
            }

            outputStream = new BufferedOutputStream(new FileOutputStream(outputFileName));

            if (radix64)
                outputStream = new ArmoredOutputStream(outputStream);

            if (encrypt) {
                PGPPublicKey encKey = UserState.instance.getPublicKey();

                encryptedDataGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).
                        setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));

                encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
                encryptedOut = encryptedDataGenerator.open(outputStream, new byte[BUFFER_SIZE]);
            }

            if (compress) {
                compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

                if (encrypt)
                    compressedOut = compressedDataGenerator.open(encryptedOut);
                else
                    compressedOut = compressedDataGenerator.open(outputStream);
            }

            if (sign) {
                PGPSecretKey pgpSecKey = UserState.instance.getSecretKey();
                String pass = UserState.instance.getPass();

                PGPPrivateKey pgpPrivKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass.toCharArray()));
                signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

                signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

                Iterator it = pgpSecKey.getPublicKey().getUserIDs();
                if (it.hasNext()) {
                    PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

                    spGen.setSignerUserID(false, (String) it.next());
                    signatureGenerator.setHashedSubpackets(spGen.generate());
                }

                if (compress)
                    signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
                else if (encrypt)
                    signatureGenerator.generateOnePassVersion(false).encode(encryptedOut);
                else
                    signatureGenerator.generateOnePassVersion(false).encode(outputStream);
            }

            // Create the Literal Data generator output stream
            PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

            if (compress)
                literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, inputFileName, new Date(), new byte[BUFFER_SIZE]);
            else if (encrypt)
                literalOut = literalDataGenerator.open(encryptedOut, PGPLiteralData.BINARY, inputFileName, new Date(), new byte[BUFFER_SIZE]);
            else
                literalOut = literalDataGenerator.open(outputStream, PGPLiteralData.BINARY, inputFileName, new Date(), new byte[BUFFER_SIZE]);

            // Open the input file
            InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFileName));

            BCPGOutputStream bOut = new BCPGOutputStream(literalOut);

            int ch;
            while ((ch = inputStream.read()) >= 0) {
                literalOut.write(ch);
                if (sign)
                    signatureGenerator.update((byte) ch);
            }

            literalOut.close();
            literalDataGenerator.close();

            if (sign)
                signatureGenerator.generate().encode(bOut);

            if (compress) {
                compressedOut.close();
                compressedDataGenerator.close();
            }

            if (encrypt) {
                encryptedOut.close();
                encryptedDataGenerator.close();
            }

            inputStream.close();
            bOut.close();

            //if (radix64)
            outputStream.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void checkDetachedSignature(){
        try {
            String inputFileName = UserState.instance.getInputFileName();
            String signatureFileName = UserState.instance.signatureFileName;

            InputStream signedData = new FileInputStream(inputFileName);
            InputStream signature = new FileInputStream(signatureFileName);

            signature = PGPUtil.getDecoderStream(signature);
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(signature);
            PGPSignature sig = ((PGPSignatureList) pgpFact.nextObject()).get(0);

            PGPPublicKey key = Keys.instance.findPublicKey(sig.getKeyID());
            sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

            byte[] buff = new byte[1024];
            int read = 0;
            while ((read = signedData.read(buff)) != -1) {
                sig.update(buff, 0, read);
            }
            signedData.close();
            if(sig.verify())
                System.out.println("signature verified.");
            else
                System.out.println("signature verification failed.");
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void receive(){
        try{
            //get user input
            String inputFileName = UserState.instance.getInputFileName();
            String outputFileName = UserState.instance.getOutputFileName();
            String pass = UserState.instance.getPass();

            InputStream in = new FileInputStream(inputFileName);
            in = PGPUtil.getDecoderStream(in);

            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);

            PGPEncryptedDataList enc;

            Object message = pgpF.nextObject();
            while(message != null){
                if(message instanceof PGPEncryptedDataList){
                    enc = (PGPEncryptedDataList) message;

                    Iterator it = enc.getEncryptedDataObjects();
                    PGPPrivateKey sKey = null;
                    PGPPublicKeyEncryptedData pbe = null;

                    while (sKey == null && it.hasNext()) {
                        pbe = (PGPPublicKeyEncryptedData) it.next();
                        sKey = Keys.instance.findSecretKey(pbe.getKeyID(), pass.toCharArray());
                    }

                    if (sKey == null) {
                        throw new IllegalArgumentException("secret key for message not found.");
                    }

                    InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
                    pgpF = new JcaPGPObjectFactory(clear);
                    message = pgpF.nextObject();

                    //JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
                    //message = plainFact.nextObject();
                    continue;
                }

                if (message instanceof PGPCompressedData) {
                    PGPCompressedData cData = (PGPCompressedData) message;

                    pgpF = new JcaPGPObjectFactory(cData.getDataStream());
                    message = pgpF.nextObject();

                    //JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
                    //message = pgpFact.nextObject();
                    continue;
                }

                if (message instanceof PGPLiteralData) {
                    PGPLiteralData ld = (PGPLiteralData) message;

                    String outFileName = ld.getFileName();
                    if (outFileName.length() == 0) {
                        outFileName = outputFileName;
                    }

                    InputStream unc = ld.getInputStream();
                    OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outFileName));

                    Streams.pipeAll(unc, fOut);

                    fOut.close();
                    break;
                }

                if(message instanceof PGPOnePassSignatureList){
                    PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;
                    PGPOnePassSignature ops = p1.get(0);

                    message = pgpF.nextObject();
                    PGPLiteralData p2 = (PGPLiteralData) message;

                    InputStream dIn = p2.getInputStream();
                    int ch;
                    PGPPublicKey key = Keys.instance.findPublicKey(ops.getKeyID());
                    FileOutputStream out = new FileOutputStream(outputFileName);
                    //FileOutputStream out = new FileOutputStream(p2.getFileName());

                    ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

                    while ((ch = dIn.read()) >= 0) {
                        ops.update((byte) ch);
                        out.write(ch);
                    }

                    out.close();

                    message = pgpF.nextObject();
                    PGPSignatureList p3 = (PGPSignatureList) message;

                    if (ops.verify(p3.get(0))) {
                        System.out.println("signature verified.");
                    } else {
                        System.out.println("signature verification failed.");
                    }
                    break;
                }
            }

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            UserState.instance.publicKey = Keys.instance.pgpPublicKeyRingCollection.getPublicKey(new BigInteger("9dfa654cc9b45f65", 16).longValue());
            UserState.instance.secretKey = Keys.instance.pgpSecretKeyRingCollection.getSecretKey(new BigInteger("9dfa654cc9b45f65", 16).longValue());
            UserState.instance.pass = "test";

            UserState.instance.inputFileName = "poruka.txt";
            UserState.instance.outputFileName = "poruka.txt.asc";
            UserState.instance.signatureFileName = "poruka.txt.sig";
            UserState.instance.radix64 = true;
            UserState.instance.compress = true;
            UserState.instance.encrypt = true;
            UserState.instance.sign = true;

            //checkDetachedSignature();
            //receive();
            //sendMessage();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}


