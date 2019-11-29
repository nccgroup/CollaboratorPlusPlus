package com.nccgroup.collaboratorplusplus.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

    public static final Logger logger = LogManager.getLogger(Utilities.class);

    public static PrivateKey loadPrivateKeyFromFile(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if(!Files.exists(Paths.get(path))){
            logger.error("Cannot load private key \"" + path + "\". File does not exist!");
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
            logger.error("Cannot load certificate \"" + path + "\". File does not exist!");
        }
        FileReader fileReader = new FileReader(path);
        PemObject pemObject = new PemReader(fileReader).readPemObject();
        final byte[] pemContent = pemObject.getContent();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        return certificateFactory.generateCertificate(new ByteArrayInputStream(pemContent));
    }

    public static String getAboutPage(){
        return "<h1>Collaborator++</h1>" +
                "Collaborator++ is a project designed to provide an authentication mechanism to the " +
                "Burp Collaborator service, a tool provided as part of the Burp Suite application.<br/>" +
                "<br/>" +
                "Collaborator Authenticator is an Open Source project and is released under the AGPL-v3.0 licence.<br/>" +
                "<a href=\"https://github.com/NCCGroup/CollaboratorPlusPlus\">View the project on GitHub</a>" +
                "<br/><br/>" +
                "<h2>Burp Suite</h2>" +
                "<a href=\"https://portswigger.net/burp/\">Burp Suite</a> is a web testing application " +
                "developed by PortSwigger.<br/>";
    }
}
