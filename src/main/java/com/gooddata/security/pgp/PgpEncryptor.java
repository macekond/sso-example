/*
 * Copyright (C) 2007-2011, GoodData(R) Corporation. All rights reserved.
 */
package com.gooddata.security.pgp;

/*
 * Copyright (C) 2007-2011, GoodData(R) Corporation. All rights reserved.
 */

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.Validate;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link PgpEncryptor} class can be used for making signatures of documents and encrypting them.
 * <p/>
 *
 * <h3>Initialization of @{@link com.gooddata.security.pgp.PgpEncryptor}</h3>
 * <p>
 *     At first, instance of PgpEncryptor must be created for further usage. It takes
 * <pre>
 * PgpEncryptor pgpEncryptor = new PgpEncryptor.Builder()
 *      .setPublicKeyForEncryption(new FileInputStream(path_to_gooddata_public_key))
 *      .setSecretKeyForSigning(new FileInputStream(path_to_sso_provider_private_key))
 *      .setSecretKeyPassword("mySecretPassword".toCharArray()) // for testing purposes this will be empty in most cases
 *      .createPgpEncryptor();
 * </pre>
 * </p>
 *
 * <h3>Signing</h3>
 * <p>
 * Let's have a simple json as an input message. We can sign this json message using
 * {@link com.gooddata.security.pgp.PgpEncryptor#encryptMessage(java.io.OutputStream, java.io.InputStream, boolean)} method.
 * <pre>
 *             final String message = "{\"email\": \"user@domain.com\",\"validity\": 123456789}";
 *             final String privateKeyFile = "/path/to/private_key;
 *             final ByteArrayOutputStream signedMessage = new ByteArrayOutputStream();
 *             pgpEncryptor.signMessage(
 *                     IOUtils.toInputStream(message),
 *                     signedMessage,
 *                     true);
 *            System.out.println("My signed message: " + new String(signedMessage.toByteArray()));
 *     </pre>
 *
 * Signed message can be similar to following:
 * <pre>
 *         -----BEGIN PGP MESSAGE-----
 * Version: BCPG v1.45
 *
 * owJ4nJvAy8zAJNjvMNNTYe+LG4ajsklfPT8+LNLcxMDAwNDc0sDUzNzIwtjMyN
 * 9UpyC/xr0uKrlVJzEzNzlKwUlEqLU4scUvKB3Dy95PxcJR2lssSczJTMkkqgrKGR
 * sYmpmbmFZW3HVhYGQSaGUlYmkP48GefEAvfU3My8TIWQ1OISBQ0EvwTIz8xLV8hO
 * rdRTcE/NSy1KLElNUUiqVMjKLMrUq0rMyS9NSc1W0FVIyy9SKM3LLAFrUcjPy6lU
 * 1FSwAXEckhML0sHGgdxkx8DFKQDz3+RrDPNsXfPmWj5lKwmQnmv6zH8q1+Om8/0M
 * 892/F5svEQt9GOVz7d+Jf54ix1JVlAB27GRF
 * =smgj
 * -----END PGP MESSAGE-----
 *     </pre>
 * </p>
 *
 * <h3>Encryption</h3>
 *
 * <p>
 * Signed message from previous example can be directly used for "encryption" as an input message.
 * <pre>
 *        final String publicKeyFile = "/path/to/public_key_for_encryption";
 *        final ByteArrayOutputStream encryptedMessage = new ByteArrayOutputStream();
 *        pgpEncryptor.encryptMessage(encryptedMessage, IOUtils.toInputStream(signedMessage), true);
 *       System.out.println("Encrypted message. " + new String(encryptedMessage.toByteArray()));
 * </pre>
 * Encrypted message can be similar to following:
 * <pre>
 *         -----BEGIN PGP MESSAGE-----
 * Version: BCPG v1.45
 *
 * hQIOA3sav0dr/91SEAf9H6KU1TxqtrZwRYcmj7Nbz2F3+yHYx6UGLtRcQS5PFb0L
 * oekrYgLY/dPDz0FL0FvK/6Dsc3PGW9bqH0Y6xjgvQcDSRv9T6W7X2l7vtjYEK+3I
 * jl4JLFtHb6iK2bK/kAnkU+X+rxecqKnGqA/eamdso87Rog79efYwigMlV6Hh/QS0
 * RB9KK4ZbvHdWXaJMoVFsrA3BC22PBvww/QJcUOb84etUZBbqek1eNuGHebZW1z8d
 * 1Mn+QkqvnbIfclhljmpjk3Q6UUhFiCAqigKCOkhh+dWQv8bxQtHK9qm+OfYWWO/9
 * 4IzJxvVByz4t8sX9bebAp6z8mU/HJQXGKISUAHhywQf9ERtUaJnZsIPPL7dLUDs9
 * 6VTlSOiasCCZCAufaXU0K/Fwk0siOSPgIAQAotl19tPmvNrgmnZn05yIqOaBAN21
 * 2/NPNGZnpZoipD6vQD6+y2/CaEt8vpmlyCJ1ziDoRJMR8RMF8xml/+ZdHM4glkBN
 * Rn/khxf1qavsl1QE5t2JnGpbZPki/izBwxkANFjCUuuLK/4emql2sgt3ynP4O4n8
 * FQIgdksClSNOaseRYXoCoGofsIv1Kf89dp4UCi0Qua3P6mu4/q3Q4CpzuE+UlafO
 * p43ex7k1TN1bY03CkG8imWHoIwSsV1H/ij4jhi0VcmX7GnSCfCmD/lsJycbACE/h
 * RcnAwhV+P9Cr6dOWz6TgujVCu23NIsZDMfGXCfUMc4iLz5I5CL2MeMbn5QjGVqhK
 * I0IKa7Q+obhapeTRJKgOZlhiNj33DOfi2/zY/Ooz6xJgT7VuUwWtJSZEztguHh9X
 * DfHXdfvVsW7sqEh77pgKftzFNH/rAiHEF5dpBZJRjDwqzLTzx6rQyPJML58oLOTN
 * 0Mx8cj8KsJN3FVk8926yiG3POQoXz4gWEvpyDtP1F0ylt+3TS5bPlLmfjyGGpX+p
 * UsFnNvLy7DEXj3xNrRTWRfOQZracXS7bDEzXM/pExhN1V6/L0BiutPuqscESq5hN
 * kyGdmG+N2pXdISjVMxqzJkCeOLqRWpU3Ga/3xu24UfFh7OzV12Iacb/a843NHX+Q
 * Mvk9YKpUkCEcV1p4a5JjtASkNz47CPBZqbqP9H2g++5zYWzIkhZ9F+pqZ6oAfKfQ
 * QqceSlpSJqEHz3EDvgicgRyG5GVhW8aWRfG1vYhDDQsuqAz/nN9mwM+/uLWcpCHt
 * x/JHf6Iv
 * =0K7c
 * -----END PGP MESSAGE-----
 * </pre>
 * </p>
 */
public class PgpEncryptor {

    private static final Logger logger = LoggerFactory.getLogger(PgpEncryptor.class);

    private final PGPSecretKey secretKeyForSigning;
    private final char[] secretKeyPassword;
    private final PGPPublicKey publicKeyForEncryption;


    /**
     * Constructor is private and only for internal usage - use {@link com.gooddata.security.pgp.PgpEncryptor.Builder} instead.
     * @param encryptionKey public key which will be used for encryption of messages
     * @param signingKey private key which will be used for making messages' signatures.
     * @param secretKeyPassword password for secret key
     */
    private PgpEncryptor(PGPPublicKey encryptionKey, PGPSecretKey signingKey, char[] secretKeyPassword) {
        Validate.isTrue(encryptionKey != null || signingKey != null,
                "At least one of pair (PGPPublicKey, PGPSecretKey) must be defined. Otherwise, PgpEncryptor" +
                        " cannot be used nor for signing neither decrypting and is useless.");


        final long initializationStartTime = System.currentTimeMillis();
        final Object encryptionKeyId = encryptionKey == null ? "[null]" : encryptionKey.getKeyID();
        final Object signingKeyId = signingKey == null ? "[null]" : signingKey.getKeyID();
        logger.debug("Initialization of PgpEncryptor with encryption key={} and signing key={} status=finish.",
                        encryptionKeyId, signingKeyId);

        SecurityProvider.ensureProviderAdded();

        this.publicKeyForEncryption = encryptionKey;
        this.secretKeyForSigning = signingKey;
        this.secretKeyPassword = secretKeyPassword;


        logger.debug("Initialization of PgpEncryptor with encryption key={} and signing key={} status=finish duration={} ms.",
                new Object[]{ encryptionKeyId, signingKeyId, (System.currentTimeMillis() - initializationStartTime)});
    }


    public void signMessage(InputStream message, OutputStream signedMessage, boolean armored)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {

        final long startTime = System.currentTimeMillis();
        logger.debug("Signing input message status=start");

        // create tmp file with content that we want to sign
        File tmpPlainContentFile = null;
        OutputStream tmpFileOutstream = null;
        try {
            tmpPlainContentFile = File.createTempFile("sign_", null);
            logger.debug("Tmp file={} created to be able to sign input message.", tmpPlainContentFile.getAbsolutePath());
            tmpFileOutstream = new FileOutputStream(tmpPlainContentFile);
            IOUtils.copy(message, tmpFileOutstream);
            tmpFileOutstream.close();

            signFile(tmpPlainContentFile.getAbsolutePath(), signedMessage, armored);
        } finally {
            IOUtils.closeQuietly(tmpFileOutstream);
            FileUtils.deleteQuietly(tmpPlainContentFile);
        }

        logger.debug("Signing input message status=finish duration={}", (System.currentTimeMillis() - startTime));
    }


    /**
     * Generates an encapsulated signed file.
     */
    public void signFile(String pathToFileToBeSigned, OutputStream signedContent, boolean armor)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {

        if (secretKeyForSigning == null) {
            throw new IllegalStateException("Secret key has not been set - cannot make signatures!");
        }

        final long startTime = System.currentTimeMillis();
        logger.debug("Signing file={} status=start", pathToFileToBeSigned);

        if (armor) {
            // output will be BASE64 encoded
            signedContent = new ArmoredOutputStream(signedContent);
        }

        logger.debug("Signing file={} status=start", pathToFileToBeSigned);
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
        final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        try {
            final BCPGOutputStream bcpgSignedContentOut = new BCPGOutputStream(compressedDataGenerator.open(signedContent));

            final PGPPrivateKey pgpPrivateKey = KeyUtils.extractPgpPrivateKey(secretKeyForSigning, secretKeyPassword);
            final PGPSignatureGenerator signatureGenerator = createSignatureGenerator(pgpPrivateKey);
            logger.debug("Generating one pass version of signature...");
            signatureGenerator.generateOnePassVersion(false).encode(bcpgSignedContentOut);
            OutputStream literalDataOut = literalDataGenerator.open(bcpgSignedContentOut, PGPLiteralData.BINARY,
                    new File(pathToFileToBeSigned));
            logger.debug("Updating signature generator with input message bytes...");
            updateSignatureGeneratorWithInputBytes(pathToFileToBeSigned, signatureGenerator, literalDataOut);
            logger.debug("Generating signed content...");
            signatureGenerator.generate().encode(bcpgSignedContentOut);
        } finally {
            literalDataGenerator.close();
            compressedDataGenerator.close();
            signedContent.close();
        }

        logger.debug("Signing file={} status=finish duration={}", pathToFileToBeSigned, (System.currentTimeMillis() - startTime));
    }


    /**
     * Encrypts given {@code message}. Output is written ot the {@code encryptedMessage} output stream.
     * Message is encrypted usign symmetric algorithm, default is {@link SymmetricKeyAlgorithmTags#TRIPLE_DES}.
     *
     * @param encryptedMessage
     * @param message
     * @param armor                  if output should be armored (BASE64 encoding of binary data)
     * @throws java.io.IOException
     * @throws java.security.NoSuchProviderException
     * @throws PGPException
     */
    public void encryptMessage(OutputStream encryptedMessage, InputStream message, boolean armor)
            throws IOException, NoSuchProviderException, PGPException {

        final long startTime = System.currentTimeMillis();
        logger.debug("Encrypting input message status=start");

        Validate.notNull(encryptedMessage);

        if (publicKeyForEncryption == null) {
            throw new IllegalStateException("Public key has not been set - cannot encrypt!");
        }

        logger.debug("Compressing data for encryption status=start");
        final PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
        final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

        // we want to generate compressed data
        final ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        writeClearDataToByteOut(compressedDataGenerator, literalDataGenerator, IOUtils.toByteArray(message), byteOut);

        compressedDataGenerator.close();
        logger.debug("Compressing data for encryption status=finish");

        final ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();

        OutputStream out = encryptedOut;
        if (armor) {
            // output will be BASE64 encoded
            out = new ArmoredOutputStream(out);
        }

        logger.debug("Generating encrypted data status=start");
        OutputStream encryptedDataOut = null;
        try {
            byte[] bytes = byteOut.toByteArray();
            encryptedDataOut = createEncryptedDataGenerator().open(out, bytes.length);
            encryptedDataOut.write(bytes);  // obtain the actual bytes from the compressed stream
        } finally {
            if (encryptedDataOut != null) {
                encryptedDataOut.close();
            }
            out.close();
        }
        logger.debug("Generating encrypted data status=finish");

        encryptedMessage.write(encryptedOut.toByteArray());

        logger.debug("Encrypting input message status=finish duration={}", (System.currentTimeMillis() - startTime));
    }


    //--------------------------------------------------- BUILDER ------------------------------------------------------
    public static class Builder {


        private static final char[] EMPTY_PASSWORD = new char[0];

        private PGPPublicKey publicKeyForEncryption = null;
        private PGPSecretKey secretKeyForSigning = null;
        private char[] secretKeyPassword = EMPTY_PASSWORD;

        public Builder setPublicKeyForEncryption(InputStream pgpPublicKeyIn) {
            Validate.notNull(pgpPublicKeyIn, "If you do not want to set public key, then simply do not call this method!");
            try {
                final PGPPublicKey publicKey = KeyUtils.findPublicKeyForEncryption(pgpPublicKeyIn);
                if (publicKey == null) {
                    throw new IllegalArgumentException("Cannot load public key from given input stream");
                }
                this.publicKeyForEncryption = publicKey;
            } catch (Exception e) {
                throw new IllegalArgumentException("Cannot load public key from given input stream");
            }

            return this;
        }

        public Builder setPublicKeyForEncryption(PGPPublicKey pgpPublicKey) {
            Validate.notNull(pgpPublicKey, "If you do not want to set public key, then simply do not call this method!");
            this.publicKeyForEncryption = pgpPublicKey;
            return this;
        }

        public Builder setSecretKeyForSigning(InputStream pgpSecretKeyIn) {
            Validate.notNull(pgpSecretKeyIn, "If you do not want to set private key, then simply do not call this method!");
            try {
                final PGPSecretKey secretKey = KeyUtils.findSecretKeyForSigning(pgpSecretKeyIn);
                if (secretKey == null) {
                    throw new IllegalArgumentException("Cannot load secret key from given input stream");
                }
                this.secretKeyForSigning = secretKey;
            } catch (Exception e) {
                throw new IllegalArgumentException("Cannot load secret key from given input stream");
            }

            return this;
        }

        public Builder setSecretKeyForSigning(PGPSecretKey pgpSecretKey) {
            Validate.notNull(pgpSecretKey, "If you do not want to set private key, then simply do not call this method!");
            this.secretKeyForSigning = pgpSecretKey;
            return this;
        }

        public Builder setSecretKeyPassword(char[] secretKeyPassword) {
            if (secretKeyPassword == null) {
                this.secretKeyPassword = EMPTY_PASSWORD;
            } else {
                this.secretKeyPassword = Arrays.copyOf(secretKeyPassword, secretKeyPassword.length);
            }
            return this;
        }

        public PgpEncryptor createPgpEncryptor() {
            return new PgpEncryptor(publicKeyForEncryption, secretKeyForSigning, secretKeyPassword);
        }

    }


    //--------------------------------------------------- HELPER METHODS -----------------------------------------------

    private PGPSignatureGenerator createSignatureGenerator(PGPPrivateKey pgpPrivateKey) throws PGPException {
        final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(secretKeyForSigning.getPublicKey().getAlgorithm(), PGPUtil.SHA1)
                        .setProvider(SecurityProvider.NAME)
                        .setDigestProvider(SecurityProvider.NAME));

        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);

        setSignatureSubpackets(secretKeyForSigning, signatureGenerator);
        return signatureGenerator;
    }


    private static void setSignatureSubpackets(PGPSecretKey pgpSec, PGPSignatureGenerator signatureGenerator) {
        Iterator it = pgpSec.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            spGen.setSignerUserID(false, (String) it.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }
    }


    private static void updateSignatureGeneratorWithInputBytes(String pathToFileToBeSigned,
            PGPSignatureGenerator signatureGenerator, OutputStream lOut) throws IOException, SignatureException {
        FileInputStream pathToBeSignedIn = null;
        try {
            pathToBeSignedIn = new FileInputStream(pathToFileToBeSigned);
            int ch;

            while ((ch = pathToBeSignedIn.read()) >= 0) {
                lOut.write(ch);
                signatureGenerator.update((byte) ch);
            }

        } finally {
            IOUtils.closeQuietly(pathToBeSignedIn);
        }
    }

    private void writeClearDataToByteOut(PGPCompressedDataGenerator compressedDataGenerator, PGPLiteralDataGenerator literalDataGenerator, byte[] clearData, ByteArrayOutputStream byteOut) throws IOException {
        try {
            OutputStream pOut = literalDataGenerator.open(compressedDataGenerator.open(byteOut), // the compressed output stream
                    PGPLiteralData.BINARY,
                    String.valueOf(PGPLiteralData.TEXT),  // "filename" to store
                    clearData.length, // length of clear data
                    new Date()  // current time
            );
            pOut.write(clearData);
        } finally {
            literalDataGenerator.close();
        }
    }


    private PGPEncryptedDataGenerator createEncryptedDataGenerator() {
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES)
                        .setSecureRandom(RandomUtils.SECURE_RANDOM)
                        .setProvider(SecurityProvider.NAME));
        encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(this.publicKeyForEncryption)
                .setProvider(SecurityProvider.NAME).setSecureRandom(RandomUtils.SECURE_RANDOM));
        return encryptedDataGenerator;
    }

}
