package com.nccgroup.collaboratorauth.server;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Utilities {

    public static PrivateKey loadPrivateKeyFromFile(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if(!Files.exists(Paths.get(path))){
            System.err.println("Cannot load private key \"" + path + "\". File does not exist!");
        }
        FileReader fileReader = new FileReader(path);
        PemObject pemObject = new PemReader(fileReader).readPemObject();
        final byte[] pemContent = pemObject.getContent();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemContent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static Certificate loadCertificateFromFile(String path) throws IOException, CertificateException {
        if(!Files.exists(Paths.get(path))){
            System.err.println("Cannot load certificate \"" + path + "\". File does not exist!");
        }
        FileReader fileReader = new FileReader(path);
        PemObject pemObject = new PemReader(fileReader).readPemObject();
        final byte[] pemContent = pemObject.getContent();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        return certificateFactory.generateCertificate(new ByteArrayInputStream(pemContent));
    }
}
