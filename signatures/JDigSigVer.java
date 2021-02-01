package signatures;

import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * Class which demonstrates how to create and verify digital signature.
 * @author shashank-shark
 */
public class JDigSigVer {

    /**
     * The steps in generating digital signature and verification include:
     * <ol>
     *     <li>Generation of DSA KeyPair.</li>
     *     <li>Generate Signature using the DSA keypair that was generated in the above step.</li>
     *     <li>Digitally sign a message.</li>
     *     <li>Verify the signature.</li>
     * </ol>
     * @param args - command line arguments
     */
    public static void main (String[] args) {

        KeyPair dsaKeyPair = generateDSAKeyPair();
        Signature dsaSignature = getSHA256WithDSASignature(dsaKeyPair);

        /* CASE: Positive Signature Verification
         * Here we are passing the signature of the same message
         */
        byte[] message = "qwertyuiopasdfghjklzxvbnm".getBytes(StandardCharsets.UTF_8);
        byte[] signedMessage = signMessageWithSignature(message, dsaSignature);
        boolean isVerificationSuccessful = validateDigitalSignature(dsaKeyPair.getPublic(), message, signedMessage);
        System.out.println("Positive Scenario : " + isVerificationSuccessful);

        /* CASE: Negative Signature Verification
         * Here we are passing tampered or modified message
         */
        byte[] newMessage = "qwertyuiopasdfghjklmnbvcxz".getBytes(StandardCharsets.UTF_8);
        signedMessage = signMessageWithSignature(newMessage, dsaSignature);
        isVerificationSuccessful = validateDigitalSignature(dsaKeyPair.getPublic(),message, signedMessage);
        System.out.println("Negative Scenario : " + isVerificationSuccessful);
    }

    /**
     * method to check whether the message recieved is the same message that was sent from the sender.
     * @param publicKey - public key of the sender
     * @param message - message recieved
     * @param digitalSignature - the digital signature of this particular message
     * @return boolean - true on successful signature verification and false on unsuccessful verification
     * verification is not successful
     */
    public static boolean validateDigitalSignature(PublicKey publicKey, byte[] message, byte[] digitalSignature) {

        Signature signature = null;
        try {
            signature = Signature.getInstance("SHA256WithDSA");
            signature.initVerify(publicKey);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            assert signature != null;
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

    /**
     * method for generatin DSA Keypair.
     * @return KeyPair
     */
    public static KeyPair generateDSAKeyPair() {
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

    /**
     * method for generating RSA Keypair.
     * @return KeyPair
     */
    public static KeyPair generateRSAKeyPair() {
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

    /**
     * method to create digital signature of the message.
     * @param message - the message that should be digitally signed
     * @param signature - DSA signature instance.
     * @return byte[] - array stream of digitally signed bytes.
     */
    public static byte[] signMessageWithSignature(byte[] message, Signature signature) {

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

    /**
     * method to generate Signature instance from the given KeyPair instance.
     * @param keyPair - the generated DSA KeyPair.
     * @return Signature - signature instance
     */
    public static Signature getSHA256WithDSASignature(KeyPair keyPair) {
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
