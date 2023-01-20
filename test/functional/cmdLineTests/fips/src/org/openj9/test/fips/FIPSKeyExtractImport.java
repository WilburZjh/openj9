/*******************************************************************************
 * Copyright IBM Corp. and others 2022
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse Public License 2.0 which accompanies this
 * distribution and is available at https://www.eclipse.org/legal/epl-2.0/
 * or the Apache License, Version 2.0 which accompanies this distribution and
 * is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * This Source Code may also be made available under the following
 * Secondary Licenses when the conditions for such availability set
 * forth in the Eclipse Public License, v. 2.0 are satisfied: GNU
 * General Public License, version 2 with the GNU Classpath
 * Exception [1] and GNU General Public License, version 2 with the
 * OpenJDK Assembly Exception [2].
 *
 * [1] https://www.gnu.org/software/classpath/license.html
 * [2] https://openjdk.org/legal/assembly-exception.html
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0 OR GPL-2.0 WITH Classpath-exception-2.0 OR LicenseRef-GPL-2.0 WITH Assembly-exception
 *******************************************************************************/
package org.openj9.test.fips;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.math.BigInteger;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;

import java.util.*;
import java.util.Base64;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FIPSKeyExtractImport {
    private static final String SECRET_KEY   = "78BCC9D7998EF944C69AE4E066376CE1";
    private static final String INI_VECTOR   = "ij093kj4309d43jf";

    private static List<KeyPair> EC_PUB_PRI;
    private static List<KeyPair> RSA_PUB_PRI;

    public static void main(String[] args) throws BadPaddingException, CertificateException,
                        IllegalBlockSizeException, InvalidKeyException, IOException, KeyStoreException, SignatureException,
                        NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, UnrecoverableKeyException {
        
        EC_PUB_PRI  = getKey("EC");
        RSA_PUB_PRI = getKey("RSA");

        String test = args[0];
        switch(test) {
        case "importSecret":
            importSecret("TEST");
            break;
        case "importRSA":
            importRSA("Test import RSA");
            break;
        case "importRSASignature":
            importRSASignature("Test import RSA Signature");
            break;
        case "importEC":
            importEC("Test import EC");
            break;
        case "exportEC":
            exportEC();
            break;
        case "exportRSA":
            exportRSA();
            break;
        default:
            throw new RuntimeException("incorrect parameters");
        }
    }

    public static void importSecret(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(INI_VECTOR.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(SECRET_KEY.getBytes("UTF-8"), "AES");

            byte[] encrypted = encrypt(value, "AES/CBC/PKCS5PADDING", "SunPKCS11-NSS-FIPS", skeySpec, iv);
            byte[] decrypted = decrypt(encrypted, "AES/CBC/PKCS5PADDING", "SunPKCS11-NSS-FIPS", skeySpec, iv);
            String plainText = new String(decrypted);

            if(value.equals(plainText)){
                System.out.println("Import secret key in FIPS mode test COMPLETED");
            }else{
                System.out.println("Import secret key in FIPS mode test FAILED");
                System.out.println("Decrypted message is: " + plainText);
            }
        } catch (UnsupportedEncodingException ex) {
            System.out.println("Import secret key in FIPS mode test FAILED");
            ex.printStackTrace();
        }
    }

    private static byte[] encrypt(String msg, String algo, String providerName, SecretKeySpec skeySpec, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(algo, providerName);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            return cipher.doFinal(msg.getBytes());
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException ex) {
            System.out.println("Encrypt a message by secret key in FIPS mode test FAILED");
            ex.printStackTrace();
        }
        return null;
    }

    private static byte[] decrypt(byte[] encryptMsg, String algo, String providerName, SecretKeySpec skeySpec, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(algo, providerName);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            return cipher.doFinal(encryptMsg);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException ex) {
            System.out.println("Decrypt a message by secret key in FIPS mode test FAILED");
            ex.printStackTrace();
        }
        return null;
    }

    public static void importRSA(String value) {
        System.out.println("Original message: " + value);

        try {
            PublicKey publicKey = (RSAPublicKey) RSA_PUB_PRI.get(0).getPublic();
            Cipher encryptCipher = Cipher.getInstance("RSA", "SunPKCS11-NSS-FIPS");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);        
            byte[] encrypted = encryptCipher.doFinal(value.getBytes());
            System.out.println("Encrypted message: " + Base64.getEncoder().encodeToString(encrypted));

            PrivateKey privateKey = (RSAPrivateCrtKey) RSA_PUB_PRI.get(0).getPrivate();
            Cipher decryptCipher = Cipher.getInstance("RSA","SunPKCS11-NSS-FIPS");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted = decryptCipher.doFinal(encrypted);

            String decryptedMessage = new String(decrypted);
            if(value.equals(decryptedMessage)) {
                System.out.println("Import RSA key in FIPS mode test COMPLETED");
            } else {
                System.out.println("Decrypted Message does not match original message");
                System.out.println("Decrypted Message is : " + decryptedMessage);
            }
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException ex) {
            System.out.println("Import RSA key in FIPS mode test FAILED");
            ex.printStackTrace();
        }
    }

    public static void importEC(String value) {
        try{
            byte[] sign = signatureSign("EC", value);
            boolean status = signatureVerify("EC", value, sign);
            if(status == true) {
                System.out.println("Verified");
            }else {
                System.out.println("Does not verify");
            }
        } catch (Exception e) {
            System.out.println("Import EC key in FIPS mode test FAILED");
            e.printStackTrace();
        }
    }

    public static void importRSASignature(String value) {
        try{
            byte[] sign = signatureSign("RSA", value);
            boolean status = signatureVerify("RSA", value, sign);
            if(status == true) {
                System.out.println("Verified");
            }else {
                System.out.println("Does not verify");
            }
        } catch (Exception e) {
            System.out.println("Import RSA key in FIPS mode test FAILED");
            e.printStackTrace();
        }
    }

    public static String exportEC() {
        try {
            KeyPair pair = null;
            KeyPairGenerator keyGen = null;
            SecureRandom random = null;

            keyGen = KeyPairGenerator.getInstance("EC");

            random = new SecureRandom();
            int len = 32;
            keyGen.initialize(len * 8, random);

            pair = keyGen.generateKeyPair();
            ECPublicKey ecPubKey = (ECPublicKey) pair.getPublic();
            ECPrivateKey ecPrivKey = (ECPrivateKey) pair.getPrivate();

            BigInteger s = ecPrivKey.getS();
            System.out.println(s);
            System.out.println("Extract EC keys in FIPS mode test COMPLETED");
            return "";
        } catch (NoSuchAlgorithmException ex ) {
            System.out.println("Extract EC keys in FIPS mode test FAILED");
            ex.printStackTrace();
        }
        return null;
    }

    public static String exportRSA() {
        try {
            KeyPair pair = null;
            KeyPairGenerator keyGen = null;
            SecureRandom random = null;

            keyGen = KeyPairGenerator.getInstance("RSA");

            random = new SecureRandom();
            int len = 512;
            keyGen.initialize(len * 8, random);

            pair = keyGen.generateKeyPair();
            RSAPublicKey rsaPubKey = (RSAPublicKey) pair.getPublic();
            RSAPrivateCrtKey rsaPrivKey = (RSAPrivateCrtKey) pair.getPrivate();

            BigInteger pe = rsaPrivKey.getPrivateExponent();
            System.out.println(pe);
            System.out.println("Extract RSA keys in FIPS mode test COMPLETED");
            return "";
        } catch (Exception ex) {
            System.out.println("Extract RSA keys in FIPS mode test FAILED");
            ex.printStackTrace();
        }
        return null;
    }

    public static List<KeyPair> getKey(String ksType) {
        List<KeyPair> list = new ArrayList<>();
        try {
            KeyStore ks = KeyStore.getInstance("pkcs12");
            char[] password = "changeit".toCharArray();
            ByteArrayInputStream bais;
            if(ksType.equals("RSA")) {
                bais = new ByteArrayInputStream(Files.readAllBytes(Paths.get("testKSRSA.p12")));
            } else {
                bais = new ByteArrayInputStream(Files.readAllBytes(Paths.get("testKSEC.p12")));
            }
            ks.load(bais, password);

            Enumeration<String> enumeration = ks.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                Certificate certificate = ks.getCertificate(alias);
                Key key = ks.getKey(alias, password);
                if(key instanceof PrivateKey) {
                    PublicKey publicKey = certificate.getPublicKey();
                    list.add(new KeyPair(publicKey, (PrivateKey) key));
		        }
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException ex) {
            System.out.println("Can not load key from PKCS12 keystore");
            ex.printStackTrace();
        } 
	    return list;
    }

    private static byte[] signatureSign(String algo, String value) {
        System.out.println("Original message: " + value);

        PrivateKey privateKey;
        Signature signature;
        try {
            if(algo.equals("EC")) {
                privateKey = (ECPrivateKey) EC_PUB_PRI.get(0).getPrivate();
                signature = Signature.getInstance("SHA224withECDSA", "SunPKCS11-NSS-FIPS");
            } else if(algo.equals("RSA")) {
                privateKey = (RSAPrivateCrtKey) RSA_PUB_PRI.get(0).getPrivate();
                signature = Signature.getInstance("SHA256withRSA", "SunPKCS11-NSS-FIPS");
            } else {
                System.out.println("Algorithm is not supported now");
                return null;
            }
            signature.initSign(privateKey);
            signature.update(value.getBytes());
            return signature.sign();
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            System.out.println("Can not sign through private key");
            ex.printStackTrace();
        }
        return null;
    }

    private static boolean signatureVerify(String algo, String value, byte[] sign) {
        PublicKey publicKey;
        Signature signature;
        try {
            if(algo.equals("EC")) {
                publicKey = (ECPublicKey) EC_PUB_PRI.get(0).getPublic();
                signature = Signature.getInstance("SHA224withECDSA", "SunPKCS11-NSS-FIPS");
            } else if(algo.equals("RSA")) {
                publicKey = (RSAPublicKey) RSA_PUB_PRI.get(0).getPublic();
                signature = Signature.getInstance("SHA256withRSA", "SunPKCS11-NSS-FIPS");
            } else {
                System.out.println("Algorithm is not supported now");
                return false;
            }
            signature.initVerify(publicKey);
            signature.update(value.getBytes());
            return signature.verify(sign);
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            System.out.println("Can not verify through public key");
            ex.printStackTrace();
        }
        return false;
    }
}