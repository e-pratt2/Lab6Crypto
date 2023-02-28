package lab6;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.security.*;

public class CSCD437Crypto {
    private KeyPairGenerator keyPairGen;
    private KeyPair pair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Signature sign;

    CSCD437Crypto(String signatureAlgo, String keyPairAlgo, int keySize) throws NoSuchAlgorithmException, InvalidParameterException {
        // Throws if not a valid algorithm name - only makes sense to propagate the error to the caller
        this.keyPairGen = KeyPairGenerator.getInstance(keyPairAlgo);
        // Throws if not a valid keysize - propagate
        this.keyPairGen.initialize(keySize);
        this.pair = this.keyPairGen.generateKeyPair();
        this.privateKey = this.pair.getPrivate();
        this.publicKey = this.pair.getPublic();
        // Throws if not a valid algorithm name - propagate
        this.sign = Signature.getInstance(signatureAlgo);
    }
    /// The decrypt method decrypts the message by using your private key.
    void decrypt(String filename, String transformation)
            throws NoSuchAlgorithmException, NoSuchPaddingException, IOException,
            BadPaddingException, IllegalBlockSizeException {

        //Check if the file is available for read/write before continuing
        File check_file = new File(filename);
        if (!check_file.canRead() || !check_file.canWrite()) {
            System.err.println("Cannot get read/write access to filename " + filename);
            return;
        }

        //Get the file's system path
        Path filepath = FileSystems.getDefault().getPath(filename);

        //Throws if padding or algorithm unknown - propagate
        Cipher ctx = Cipher.getInstance(transformation);

        try {
            //May throw an error depending on key - this is an implementation detail, don't propagate.
            ctx.init(Cipher.DECRYPT_MODE, this.privateKey);
        } catch(InvalidKeyException e) {
            System.err.println("Failed to use key with algorithm " + transformation + ": " + e.getLocalizedMessage());
            return;
        }

        byte[] input;

        //We checked that the file is available for reading already - if this fails, something
        //bad happened internally.
        try {
            input = Files.readAllBytes(filepath);
        } catch (IOException e) {
            System.err.println("Unexpected read error: " + e.getLocalizedMessage());
            return;
        }

        //Do the crypto! Propagate File size errors (Bad block size or padding size).
        byte[] output = ctx.doFinal(Files.readAllBytes(filepath));

        //We checked that the file is available for writing already - if this fails, something
        //bad happened internally.
        try {
            Files.write(filepath, output, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            System.err.println("Unexpected write error: " + e.getLocalizedMessage());
            return;
        }
    }
    /// The encrypt method is overloaded to allow for a text file to be passed in.
    void encrypt(PublicKey publicKey, String transformation, File messageFile, String encryptedFilename) {

    }
    /// The encrypt method uses the message receiver's public key and the transformation string to encrypt the message to produce and encrypted file.
    void encrypt(PublicKey publicKey, String transformation, String message, String encryptedFilename) {

    }

    /// This method allows a user to generate a new public/private key and new signature.
    void
    generateKeys(String signatureAlgo, String keyPairAlgo, int keySize) {

    }

    /// This method reads the public key from the file where the public key was published.
    static PublicKey getPublicKey(String filename) {

    }
    void publishPublicKey(String filename) {

    }
}
