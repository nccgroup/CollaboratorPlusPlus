package com.nccgroup.collaboratorauth.server;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nccgroup.collaboratorauth.utilities.Encryption;
import org.apache.commons.io.IOUtils;
import org.apache.http.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class HttpHandler implements HttpRequestHandler {

    private final String actualAddress;
    private final Integer actualPort;
    private final boolean actualIsHttps;
    private final String secret;
    private final String logLevel;

    public HttpHandler(String actualAddress, Integer actualPort, boolean actualIsHttps, String secret, String logLevel){
        this.actualAddress = actualAddress;
        this.actualPort = actualPort;
        this.actualIsHttps = actualIsHttps;
        this.secret = secret;
        this.logLevel = logLevel;
    }

    @Override
    public void handle(HttpRequest request, HttpResponse response, HttpContext context) throws IOException {
        if (!(request instanceof BasicHttpEntityEnclosingRequest)) {
            //TODO Ask PortSwigger if this is okay!
            response.setEntity(new StringEntity("<h1>Collaborator Authenticator</h1>" +
                    "Collaborator Authenticator is a tool designed to provide an authentication mechanism to the " +
                    "Burp Collaborator service, a tool provided as part of the Burp Suite application.<br/>" +
                    "<br/>" +
                    "Collaborator Authenticator is an Open Source project and is released under the AGPL-v3.0 licence.<br/>" +
                    "<a href=\"https://github.com/NCCGroup/CollaboratorAuthenticator\">View the project on GitHub</a>" +
                    "<br/><br/>" +
                    "<h2>Burp Suite</h2>" +
                    "<a href=\"https://portswigger.net/burp/\">Burp Suite</a> is a web testing application " +
                    "developed by PortSwigger.<br/>", ContentType.TEXT_HTML));
            response.setStatusCode(HttpStatus.SC_OK);
            return;
        }

        CloseableHttpClient client = HttpClients.createDefault();

        try {
            try {
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                ((BasicHttpEntityEnclosingRequest) request).getEntity().writeTo(byteArrayOutputStream);
                String encodedRequest = Encryption.aesDecryptRequest(this.secret, byteArrayOutputStream.toByteArray());
                String requestDecoded = new String(Base64.getDecoder().decode(encodedRequest));

                if (!requestDecoded.startsWith("/burpresults?biid=")) { //If request is not a valid collaborator request. (SSRF protection!)
                    throw new IllegalArgumentException("The request does not look like a valid collaborator polling request!");
                }

                //Make request to actual collaborator server
                URI getURI = new URL((actualIsHttps ? "https://" : "http://") + actualAddress + ":" + actualPort
                        + requestDecoded).toURI();
                HttpGet getRequest = new HttpGet(getURI);
                getRequest.addHeader("Connection", "close");
                HttpResponse actualRequestResponse = client.execute(getRequest);
                final int actualStatus = actualRequestResponse.getStatusLine().getStatusCode();


                if (actualRequestResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    String actualResponse = IOUtils.toString(actualRequestResponse.getEntity().getContent());
                    response.setEntity(createEncryptedResponse(actualResponse));

                    for (Header header : actualRequestResponse.getAllHeaders()) {
                        if (header.getName().startsWith("X-Collaborator")) {
                            response.addHeader(header);
                        }
                    }
                } else {
                    throw new Exception("The Collaborator server responded with a status code: " + actualStatus);
                }
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidCipherTextException e) {
                //Could not decrypt the request. The client probably used an invalid secret.
                response.setStatusCode(HttpStatus.SC_UNAUTHORIZED);
                response.setEntity(new StringEntity("The server could not decrypt the request. Is the secret correct?"));
            } catch (IllegalArgumentException e) {
                response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
                response.setEntity(createEncryptedResponse(e.getMessage()));
            }
        }catch (Exception e){
            //Log exception?
            response.setStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        } finally {
            client.close();
        }
    }

    private ByteArrayEntity createEncryptedResponse(String message) throws NoSuchAlgorithmException, InvalidCipherTextException, InvalidKeySpecException {
        byte[] encrypted = Encryption.aesEncryptRequest(this.secret, message);
        return new ByteArrayEntity(encrypted);
    }
}
