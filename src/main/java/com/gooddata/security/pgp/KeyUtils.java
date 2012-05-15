/*
 * Copyright (C) 2007-2011, GoodData(R) Corporation. All rights reserved.
 */
package com.gooddata.security.pgp;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.apache.commons.lang.Validate;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
 * Utility class containing methods useful for work with (not only) PGP keys.
 *
 * <strong> If you add new method, please ensure that it calls {@code SecurityProvider.ensureProviderAdded();}
 * at first place.</strong>
 */
public class KeyUtils {

    public static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";


    public static PGPSecretKeyRing readSecretKeyRing(InputStream secretKeyRingIn) throws IOException, PGPException {

        SecurityProvider.ensureProviderAdded();

        final PGPSecretKeyRingCollection secretRing = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(secretKeyRingIn));

        final Iterator secretRingsIterator = secretRing.getKeyRings();
        while (secretRingsIterator.hasNext()) {
            return (PGPSecretKeyRing) secretRingsIterator.next();
        }

        return null;

    }

    /**
     * Reads all PGP secret keys which can be found in passed input stream.
     * @param secretKeyRing input stream representing {@link PGPSecretKeyRing}
     * @return
     * @throws java.io.IOException
     * @throws PGPException
     */
    public static List<PGPSecretKey> readAllSecretKeys(InputStream secretKeyRing) throws IOException, PGPException {

        SecurityProvider.ensureProviderAdded();

        final PGPSecretKeyRingCollection secretRing = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(secretKeyRing));

        final List<PGPSecretKey> allSecretKeys = new ArrayList<PGPSecretKey>();

        final Iterator secretRingsIterator = secretRing.getKeyRings();
        while (secretRingsIterator.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) secretRingsIterator.next();
            Iterator secretKeysIterator = keyRing.getSecretKeys();
            while (secretKeysIterator.hasNext()) {
                allSecretKeys.add((PGPSecretKey) secretKeysIterator.next());
            }
        }

        return allSecretKeys;
    }

    /**
     * In passed {@code secretKeyRing} finds (some) instance of {@link PGPSecretKey} which is suitable for signing.
     * <p>
     *     E.g. DSA keys are suitable for signing. El-Gamal keys should be used only for encryption.
     * </p>
     * @param secretKeyRing input stream containing {@link PGPSecretKeyRing}
     * @return one PGPSecretKey suitable for decryption or null if no such secret key is found
     * @throws PGPException
     * @throws java.io.IOException
     */
    public static PGPSecretKey findSecretKeyForSigning(InputStream secretKeyRing) throws PGPException, IOException {

        SecurityProvider.ensureProviderAdded();

        final List<PGPSecretKey> pgpSecretKeys = readAllSecretKeys(secretKeyRing);
        for (PGPSecretKey pgpSecretKey : pgpSecretKeys) {
            if (pgpSecretKey.isSigningKey()) {
                return pgpSecretKey;
            }
        }

        return null;
    }

    /**
     * In passed {@code secretKeyRing} finds (some) instance of {@link PGPSecretKey} which is suitable for decryption.
     * <p>
     *     E.g. DSA keys are NOT suitable for decryption (only for signing).
     * </p>
     * @param secretKeyRing input stream containing {@link PGPSecretKeyRing}
     * @return one PGPSecretKey suitable for decryption or null if no such secret key is found
     * @throws PGPException
     * @throws java.io.IOException
     */
    public static PGPSecretKey findSecretKeyForDecryption(InputStream secretKeyRing) throws PGPException, IOException {

        SecurityProvider.ensureProviderAdded();

        final List<PGPSecretKey> pgpSecretKeys = readAllSecretKeys(secretKeyRing);
        for (PGPSecretKey pgpSecretKey : pgpSecretKeys) {
            if (pgpSecretKey.getPublicKey() != null && pgpSecretKey.getPublicKey().isEncryptionKey()) {
                return pgpSecretKey;
            }
        }

        return null;
    }

    /**
     * Load a secret key ring collection from keyIn and find the secret key corresponding to keyID if it exists.
     *
     * @param keyIn input stream representing a key ring collection.
     * @param keyID keyID we want.
     * @param secretKeyPassword  passphrase to decrypt secret key with.
     * @return
     * @throws java.io.IOException
     * @throws org.bouncycastle.openpgp.PGPException
     *
     * @throws java.security.NoSuchProviderException
     *
     */
    public static PGPPrivateKey findPrivateKey(InputStream keyIn, long keyID, char[] secretKeyPassword)
            throws IOException, PGPException, NoSuchProviderException {

        SecurityProvider.ensureProviderAdded();

        final PGPSecretKeyRingCollection pgpSecretRing = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));

        final PGPSecretKey pgpSecretKey = pgpSecretRing.getSecretKey(keyID);
        if (pgpSecretKey == null) {
            return null;
        }
        return extractPgpPrivateKey(pgpSecretKey, secretKeyPassword);
    }


    /**
     * Finds private key with given id in passed secret key ring.
     */
    public static PGPPrivateKey findPrivateKey(PGPSecretKeyRing pgpSecretKeyRing, long keyID, char[] secretKeyPassword)
            throws IOException, PGPException, NoSuchProviderException {

        Validate.notNull(pgpSecretKeyRing, "PGPSecretKeyRing cannot be null");

        SecurityProvider.ensureProviderAdded();

        final PGPSecretKey pgpSecretKey = pgpSecretKeyRing.getSecretKey(keyID);
        if (pgpSecretKey == null) {
            return null;
        }
        return extractPgpPrivateKey(pgpSecretKey, secretKeyPassword);

    }


    /**
     * Loads all PGP public keys from given input stream that must represent  PGP Public keys' ring.
     * @param publicKeyRing
     * @return
     * @throws java.io.IOException
     * @throws PGPException
     */
    public static List<PGPPublicKey> readAllPublicKeys(InputStream publicKeyRing) throws IOException, PGPException {

        SecurityProvider.ensureProviderAdded();

        final PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(publicKeyRing));

        // iterate through the key rings.
        final List<PGPPublicKey> allPublicKeys = new ArrayList<PGPPublicKey>();
        final Iterator keyRingIterator = keyRingCollection.getKeyRings();
        while (keyRingIterator.hasNext()) {
            final PGPPublicKeyRing kRing = (PGPPublicKeyRing) keyRingIterator.next();
            Iterator publicKeysIterator = kRing.getPublicKeys();
            while (publicKeysIterator.hasNext()) {
                allPublicKeys.add((PGPPublicKey) publicKeysIterator.next());
            }
        }

        if (allPublicKeys == null || allPublicKeys.size() == 0) {
            throw new IllegalArgumentException("Can't find any public key in the input stream.");
        }

        return allPublicKeys;
    }


    /**
     * @see org.bouncycastle.openpgp.PGPPublicKey#isEncryptionKey().
     */
    public static PGPPublicKey findPublicKeyForEncryption(InputStream publicKeyInputStream) throws IOException, PGPException {

        SecurityProvider.ensureProviderAdded();

        final List<PGPPublicKey> pgpPublicKeys = readAllPublicKeys(publicKeyInputStream);
        for (PGPPublicKey pgpPublicKey : pgpPublicKeys) {
            if (pgpPublicKey.isEncryptionKey()) {
                return pgpPublicKey;
            }
        }

        return null;
    }


    /**
     * @see org.bouncycastle.openpgp.PGPPublicKey#isEncryptionKey().
     */
    public static PGPPublicKey findPublicKeyForSigning(InputStream publicKeyInputStream) throws IOException, PGPException {

        SecurityProvider.ensureProviderAdded();

        final List<PGPPublicKey> pgpPublicKeys = readAllPublicKeys(publicKeyInputStream);
        for (PGPPublicKey pgpPublicKey : pgpPublicKeys) {
            if (isForSigning(pgpPublicKey)) {
                return pgpPublicKey;
            }
        }

        return null;
    }

    public static PGPPrivateKey extractPgpPrivateKey(PGPSecretKey pgpSecretKey, char[] secretKeyPassword) throws PGPException {

        SecurityProvider.ensureProviderAdded();

        Validate.notNull(pgpSecretKey);
        return pgpSecretKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder(
                        new JcaPGPDigestCalculatorProviderBuilder().setProvider(SecurityProvider.NAME).build())
                .setProvider(SecurityProvider.NAME).build(secretKeyPassword));
    }

    /**
     * Extracts {@link java.security.PrivateKey} from given {@code pgpSecretKey}.
     * @param pgpSecretKey
     * @param secretKeyPassword
     * @return
     * @throws PGPException
     * @throws IllegalArgumentException if passed {@code pgpSecretKey} is null or {@link PGPPrivateKey} cannot be extracted
     *        from it
     */
    public static PrivateKey extractPrivateKey(PGPSecretKey pgpSecretKey, char[] secretKeyPassword) throws PGPException,
            IllegalArgumentException {
        Validate.notNull(pgpSecretKey);

        SecurityProvider.ensureProviderAdded();

        final PGPPrivateKey pgpPrivateKey = pgpSecretKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder(
                        new JcaPGPDigestCalculatorProviderBuilder().setProvider(SecurityProvider.NAME).build())
                        .setProvider(SecurityProvider.NAME).build(secretKeyPassword));
        if (pgpPrivateKey == null) {
            throw new IllegalArgumentException("Cannot extract PGPPrivateKey from given PGPSecretKey and it is required for" +
                    " extraction of PrivateKey itself!");
        }
        return new JcaPGPKeyConverter().setProvider(SecurityProvider.NAME).getPrivateKey(pgpPrivateKey);
    }


    //--------------------------------------------------- PRIVATE STUFF ------------------------------------------------
    /**
     * Checks if given public key is suitable for signing.
     * Following algorithms are considered to be suitable for signing:
     * <ul>
     *  <li>DSA</li>
     *  <li>RSA_SIGN</li>
     *  <li>RSA_GENERAL</li>
     *  <li>ELGAMAL_GENERAL</li>
     * </ul>
     *
     * @param pgpPublicKey public key to be checked
     * @return
     */
    private static boolean isForSigning(PGPPublicKey pgpPublicKey) {
        final int algorithm = pgpPublicKey.getAlgorithm();
        return algorithm == PublicKeyAlgorithmTags.DSA || algorithm == PublicKeyAlgorithmTags.RSA_SIGN
                || algorithm == PublicKeyAlgorithmTags.RSA_GENERAL || algorithm == PublicKeyAlgorithmTags.ELGAMAL_GENERAL;
    }


}
