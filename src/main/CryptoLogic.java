package main;

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
    private static CryptoLogic cryptoLogic;

    private CryptoLogic() {
        //initialize bouncy castle
        Security.addProvider(new BouncyCastleProvider());
    }

    public static CryptoLogic getCryptoLogic() {
        if (cryptoLogic == null)
            cryptoLogic = new CryptoLogic();

        return cryptoLogic;
    }

    public void generateKeyPair() {
        try {
            String identity = UserState.getUserState().getEmail();
            String passPhrase = UserState.getUserState().getPassword();
            int keySize = UserState.getUserState().getKeySize();

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

    private static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn)
            throws IOException {
        bOut.reset();

        int lookAhead = -1;
        int ch;

        while ((ch = fIn.read()) >= 0) {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }

        return lookAhead;
    }

    private static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn)
            throws IOException {
        bOut.reset();

        int ch = lookAhead;

        do {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }
        while ((ch = fIn.read()) >= 0);

        if (ch < 0) {
            lookAhead = -1;
        }

        return lookAhead;
    }

    private static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn)
            throws IOException {
        int lookAhead = fIn.read();

        if (lastCh == '\r' && lookAhead == '\n') {
            bOut.write(lookAhead);
            lookAhead = fIn.read();
        }

        return lookAhead;
    }

    private static byte[] getLineSeparator() {
        String nl = Strings.lineSeparator();
        byte[] nlBytes = new byte[nl.length()];

        for (int i = 0; i != nlBytes.length; i++) {
            nlBytes[i] = (byte) nl.charAt(i);
        }

        return nlBytes;
    }

    private static void processLine(PGPSignature sig, byte[] line)
            throws SignatureException, IOException {
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sig.update(line, 0, length);
        }
    }

    private static void processLine(OutputStream aOut, PGPSignatureGenerator sGen, byte[] line)
            throws SignatureException, IOException {
        // note: trailing white space needs to be removed from the end of
        // each line for signature calculation RFC 4880 Section 7.1
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sGen.update(line, 0, length);
        }

        aOut.write(line, 0, line.length);
    }

    private static int getLengthWithoutSeparatorOrTrailingWhitespace(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isLineEnding(byte b) {
        return b == '\r' || b == '\n';
    }

    private static int getLengthWithoutWhiteSpace(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isWhiteSpace(byte b) {
        return isLineEnding(b) || b == '\t' || b == ' ';
    }

    private static void signFile(
            String fileName,
            PGPSecretKey pgpSecKey,
            OutputStream out,
            char[] pass,
            boolean armor)
            throws IOException, PGPException, SignatureException {

        PGPPrivateKey pgpPrivKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));
        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

        sGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivKey);

        Iterator it = pgpSecKey.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            spGen.setSignerUserID(false, (String) it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        InputStream fIn = new BufferedInputStream(new FileInputStream(fileName));
        ArmoredOutputStream aOut = new ArmoredOutputStream(out);

        aOut.beginClearText(PGPUtil.SHA1);

        //
        // note the last \n/\r/\r\n in the file is ignored
        //
        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = readInputLine(lineOut, fIn);

        lineOut.write((byte) '\r');
        lineOut.write((byte) '\n');
        processLine(aOut, sGen, lineOut.toByteArray());

        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, fIn);

                sGen.update((byte) '\r');
                sGen.update((byte) '\n');

                processLine(aOut, sGen, lineOut.toByteArray());
            }
            while (lookAhead != -1);
        }

        fIn.close();

        aOut.endClearText();

        BCPGOutputStream bOut = new BCPGOutputStream(aOut);

        sGen.generate().encode(bOut);

        aOut.close();
    }

    public static void encryptFile(
            String outFileName,
            OutputStream out,
            String fileName,
            PGPPublicKey encKey,
            char[] passPhrase,
            boolean armor,
            boolean withIntegrityCheck) {

        if (armor) {
            out = new ArmoredOutputStream(out);
        }
        try {
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));

            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(UserState.getUserState().getPublicKey()).setProvider("BC"));

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            PGPUtil.writeFileToLiteralData(bOut, PGPLiteralData.BINARY,
                    new File("encPoruka.txt.asc"));

            byte[] bytes = bOut.toByteArray();

            OutputStream cOut = encGen.open(out, bytes.length);

            cOut.write(bytes);
            cOut.close();

            if (armor) {
                out.close();
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void signAndEncryptFile(String actualFileName, PGPSecretKey pgpSecKey, OutputStream outputStream,
                                   char[] password, boolean armor, boolean withIntegrityCheck, PGPPublicKey encKey) throws IOException, PGPException, SignatureException {
        final int BUFFER_SIZE = 1 << 16;
        if (armor)
            outputStream = new ArmoredOutputStream(outputStream);

        // Init encrypted data generator
        PGPEncryptedDataGenerator encryptedDataGenerator =
                new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));

        encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

        OutputStream encryptedOut = encryptedDataGenerator.open(outputStream, new byte[BUFFER_SIZE]);

        // Init compression
//         PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
//         OutputStream compressedOut = compressedDataGenerator.open(encryptedOut);

        // Init signature
        PGPPrivateKey pgpPrivKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password));
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        Iterator it = pgpSecKey.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            spGen.setSignerUserID(false, (String) it.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        signatureGenerator.generateOnePassVersion(false).encode(encryptedOut);

        // Create the Literal Data generator output stream
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalDataGenerator.open(encryptedOut, PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE, new Date(), new byte[BUFFER_SIZE]);

        // Open the input file
        InputStream inputStream = new BufferedInputStream(new FileInputStream(actualFileName));
        int ch;
        while ((ch = inputStream.read()) >= 0)
        {
            literalOut.write(ch);
            signatureGenerator.update((byte)ch);
        }

        literalOut.close();
        literalDataGenerator.close();
        signatureGenerator.generate().encode(encryptedOut);
//        compressedOut.close();
//        compressedDataGenerator.close();
        encryptedOut.close();
        encryptedDataGenerator.close();
        inputStream.close();

        if (armor)
            outputStream.close();
    }

    public static void sendMessage(String fileName, String outFileName, boolean armor, boolean sign, boolean encrypt) throws IOException, PGPException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {

//        OutputStream out = new BufferedOutputStream(new FileOutputStream(outFileName));
////
//        if (sign) {
//            signFile(fileName,
//                    UserState.getUserState().getSecretKey(),
//                    out,
//                    UserState.getUserState().getPass().toCharArray(),
//                    armor);
//        }
//
//        if (encrypt){
//            boolean withIntegrityCheck = true;
//            out = new BufferedOutputStream(new FileOutputStream(outFileName));
//            encryptFile(
//                    outFileName,
//                    out,
//                    fileName,
//                    UserState.getUserState().getPublicKey(),
//                    UserState.getUserState().getPass().toCharArray(),
//                    armor,
//                    withIntegrityCheck);
//        }

        OutputStream out = new BufferedOutputStream(new FileOutputStream(outFileName));

        signAndEncryptFile(
                fileName,
                UserState.getUserState().getSecretKey(),
                out,
                UserState.getUserState().getPass().toCharArray(),
                armor,
                true,
                UserState.getUserState().getPublicKey());
    }

    public static void main(String[] args){
        Security.addProvider(new BouncyCastleProvider());

        try {
            UserState.getUserState().setPublicKey(Keys.getInstance().pgpPublicKeyRingCollection.getPublicKey(new BigInteger("9dfa654cc9b45f65", 16).longValue()));
            UserState.getUserState().setSecretKey(Keys.getInstance().pgpSecretKeyRingCollection.getSecretKey(new BigInteger("9dfa654cc9b45f65", 16).longValue()));
            UserState.getUserState().setPass("test");
            sendMessage("poruka.txt", "encPoruka.txt.asc", true, true, true);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

}
