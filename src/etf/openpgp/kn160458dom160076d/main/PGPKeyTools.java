package etf.openpgp.kn160458dom160076d.main;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.NoSuchProviderException;
import java.util.Iterator;

public class PGPKeyTools {

    public static void main(String[] args) {
        try {
            printPublicKey(readPublicKey("pEpkey.asc"));
        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }
    }

    static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    static byte[] compressFile(String fileName, int algorithm) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY,
                new File(fileName));
        comData.close();
        return bOut.toByteArray();
    }

    /**
     * Search a secret key ring collection for a secret key corresponding to keyID if it
     * exists.
     *
     * @param pgpSec a secret key ring collection.
     * @param keyID  keyID we want.
     * @param pass   passphrase to decrypt secret key with.
     * @return the private key.
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }

    static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for encryption.
     *
     * @param input data stream containing the public key data
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyIter.next();

                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    static PGPSecretKey readSecretKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn);
        keyIn.close();
        return secKey;
    }

    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for signature generation.
     *
     * @param input stream to read the secret key ring collection from.
     * @return a secret key.
     * @throws IOException  on a problem with using the input stream.
     * @throws PGPException if there is an issue parsing the input stream.
     */
    static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();

                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    static void printPublicKey(final PGPPublicKey publicKey) {
        final byte[] fingerprint = publicKey.getFingerprint();

        System.out.println(">>> pub >>>");
        System.out.println("keyID: " + Hex.toHexString(longToBytes(publicKey.getKeyID())));
        System.out.println("fingerprint: " + (fingerprint == null ? "" : Hex.toHexString(fingerprint)));
        System.out.println("masterKey: " + publicKey.isMasterKey());
        System.out.println("encryptionKey: " + publicKey.isEncryptionKey());

        for (final Iterator<?> it3 = publicKey.getUserIDs(); it3.hasNext(); ) {
            final String userId = (String) it3.next();
            System.out.println("userID: " + userId);
        }

        for (final Iterator<?> it4 = publicKey.getSignatures(); it4.hasNext(); ) {
            final PGPSignature signature = (PGPSignature) it4.next();
            System.out.println("signature.keyID: " + Hex.toHexString(longToBytes(signature.getKeyID())));
            System.out.println("signature.signatureType: " + signatureTypeToString(signature.getSignatureType()));
        }
        System.out.println("<<< pub <<<");
    }

    static void printSecretKey(final PGPSecretKey secretKey) {
        System.out.println(">>> pub >>>");
        System.out.println("keyID: " + Hex.toHexString(longToBytes(secretKey.getKeyID())));
        System.out.println("masterKey: " + secretKey.isMasterKey());

        for (final Iterator<?> it3 = secretKey.getUserIDs(); it3.hasNext(); ) {
            final String userId = (String) it3.next();
            System.out.println("userID: " + userId);
        }

        System.out.println("encriptionAlgorithm: " + secretKey.getKeyEncryptionAlgorithm());
        System.out.println("<<< pub <<<");
    }

    static String signatureTypeToString(final int signatureType) {
        switch (signatureType) {
            case PGPSignature.BINARY_DOCUMENT:
                return "BINARY_DOCUMENT";
            case PGPSignature.CANONICAL_TEXT_DOCUMENT:
                return "CANONICAL_TEXT_DOCUMENT";
            case PGPSignature.STAND_ALONE:
                return "STAND_ALONE";

            case PGPSignature.DEFAULT_CERTIFICATION:
                return "DEFAULT_CERTIFICATION";
            case PGPSignature.NO_CERTIFICATION:
                return "NO_CERTIFICATION";
            case PGPSignature.CASUAL_CERTIFICATION:
                return "CASUAL_CERTIFICATION";
            case PGPSignature.POSITIVE_CERTIFICATION:
                return "POSITIVE_CERTIFICATION";

            case PGPSignature.SUBKEY_BINDING:
                return "SUBKEY_BINDING";
            case PGPSignature.PRIMARYKEY_BINDING:
                return "PRIMARYKEY_BINDING";
            case PGPSignature.DIRECT_KEY:
                return "DIRECT_KEY";
            case PGPSignature.KEY_REVOCATION:
                return "KEY_REVOCATION";
            case PGPSignature.SUBKEY_REVOCATION:
                return "SUBKEY_REVOCATION";
            case PGPSignature.CERTIFICATION_REVOCATION:
                return "CERTIFICATION_REVOCATION";
            case PGPSignature.TIMESTAMP:
                return "TIMESTAMP";

            default:
                return Integer.toHexString(signatureType);
        }
    }
}
