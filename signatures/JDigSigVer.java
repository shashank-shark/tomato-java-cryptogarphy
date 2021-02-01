package signatures;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class JDigSigVer {

    public static void main (String[] args) {
        KeyPair dsaKeyPair = generateDSAKeyPair();
        Signature dsaSignature = getSHA256WithDSASignature(dsaKeyPair);

        /* CASE: Positive Signature Verification
         * Here we are passing the signature of the same message
         */
        byte[] message = "qwertyuiopasdfghjklzxvbnm".getBytes(StandardCharsets.UTF_8);
        byte[] signedMessage = signMessageWithSignature(message, dsaSignature);
        boolean isVerificationSuccessful = validateDigitalSignature(dsaKeyPair,message, signedMessage);
        System.out.println("Positive Scenario : " + isVerificationSuccessful);

        /* CASE: Negative Signature Verification
         * Here we are passing tampered or modified message
         */
        byte[] newMessage = "qwertyuiopasdfghjklmnbvcxz".getBytes(StandardCharsets.UTF_8);
        signedMessage = signMessageWithSignature(newMessage, dsaSignature);
        isVerificationSuccessful = validateDigitalSignature(dsaKeyPair,message, signedMessage);
        System.out.println("Negative Scenario : " + isVerificationSuccessful);
    }

    private static boolean validateDigitalSignature(KeyPair keyPair, byte[] message, byte[] digitalSignature) {
        Signature signature = getSHA256WithDSASignature(keyPair);
        try {
            signature.initVerify(keyPair.getPublic());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        try {
            signature.update(message);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        try {
            return signature.verify(digitalSignature);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    private static KeyPair generateDSAKeyPair() {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.genKeyPair();
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            System.out.println(noSuchAlgorithmException.getMessage());
        }
        return keyPair;
    }

    private static KeyPair generateRSAKeyPair() {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.genKeyPair();
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            System.out.println(noSuchAlgorithmException.getMessage());
        }
        return keyPair;
    }

    private static byte[] signMessageWithSignature(byte[] message, Signature signature) {

        try {
            signature.update(message);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        try {
            return signature.sign();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static Signature getSHA256WithDSASignature(KeyPair keyPair) {
        Signature signature = null;
        try {
            signature = Signature.getInstance("SHA256WithDSA");
            SecureRandom secureRandom = new SecureRandom();
            signature.initSign(keyPair.getPrivate(), secureRandom);
        } catch (NoSuchAlgorithmException | InvalidKeyException noSuchAlgorithmException) {
            System.out.println(noSuchAlgorithmException.getMessage());
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return signature;
    }
}
