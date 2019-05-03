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
        if(!(request instanceof BasicHttpEntityEnclosingRequest)){
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
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ((BasicHttpEntityEnclosingRequest) request).getEntity().writeTo(byteArrayOutputStream);
            String encodedRequest = Encryption.aesDecryptRequest(this.secret, byteArrayOutputStream.toByteArray());
            String requestDecoded = new String(Base64.getDecoder().decode(encodedRequest));

            if (!requestDecoded.startsWith("/burpresults?biid=")) { //If request is not a valid collaborator request. (SSRF protection!)
                response.setEntity(new StringEntity("The request does not look like a valid collaborator request!"));
                response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
                return;
            }

            //Make request to actual collaborator server
            URI getURI = new URL((actualIsHttps ? "https://" : "http://") + actualAddress + ":" + actualPort
                    + requestDecoded).toURI();
            HttpGet getRequest = new HttpGet(getURI);
            getRequest.addHeader("Connection", "close");
            HttpResponse actualRequestResponse = client.execute(getRequest);
            response.setStatusCode(actualRequestResponse.getStatusLine().getStatusCode());

            String actualResponse = IOUtils.toString(actualRequestResponse.getEntity().getContent());

            for (Header header : actualRequestResponse.getAllHeaders()) {
                if (header.getName().equalsIgnoreCase("X-Collaborator-Version")
                        || header.getName().equalsIgnoreCase("X-Collaborator-Time")) {
                    response.addHeader(header);
                }
            }

            if (actualRequestResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                response.setEntity(new StringEntity(actualResponse));
            } else {
                if (logLevel.equalsIgnoreCase("debug") || logLevel.equalsIgnoreCase("error"))
                    System.err.println("Actual collaborator server returned a " +
                            actualRequestResponse.getStatusLine().getStatusCode() + " response!");
            }
        }catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidCipherTextException e) {
            response.setStatusCode(HttpStatus.SC_UNAUTHORIZED);
            return;
        } catch (Exception e){
            response.setEntity(new StringEntity(e.getMessage()));
            response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
        }finally {
            client.close();
        }
    }
}
