package com.nccgroup.collaboratorplusplus.server;

import com.nccgroup.collaboratorplusplus.utilities.Encryption;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

public class HttpHandler implements HttpRequestHandler {

    private final String actualAddress;
    private final Integer actualPort;
    private final boolean actualIsHttps;
    private final String secret;

    public HttpHandler(String actualAddress, Integer actualPort, boolean actualIsHttps, String secret){
        this.actualAddress = actualAddress;
        this.actualPort = actualPort;
        this.actualIsHttps = actualIsHttps;
        this.secret = secret;
    }

    @Override
    public void handle(HttpRequest request, HttpResponse response, HttpContext context) {
        response.addHeader(new BasicHeader("X-Auth-Compatible", "true"));

        if (!(request instanceof BasicHttpEntityEnclosingRequest)) {
            response.setEntity(new StringEntity("<h1>Collaborator Authenticator</h1>" +
                    "Collaborator Authenticator is a tool designed to provide an authentication mechanism to the " +
                    "Burp Collaborator service, a tool provided as part of the Burp Suite application.<br/>" +
                    "<br/>" +
                    "Collaborator Authenticator is an Open Source project and is released under the AGPL-v3.0 licence.<br/>" +
                    "<a href=\"https://github.com/NCCGroup/CollaboratorPlusPlus\">View the project on GitHub</a>" +
                    "<br/><br/>" +
                    "<h2>Burp Suite</h2>" +
                    "<a href=\"https://portswigger.net/burp/\">Burp Suite</a> is a web testing application " +
                    "developed by PortSwigger.<br/>", ContentType.TEXT_HTML));
            response.setStatusCode(HttpStatus.SC_OK);
            return;
        }

        CollaboratorServer.logManager.logDebug("Retrieved request: ");
        CollaboratorServer.logManager.logDebug(((BasicHttpEntityEnclosingRequest) request).getEntity().toString());

        try (CloseableHttpClient client = HttpClients.createDefault()) {
            try {
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                ((BasicHttpEntityEnclosingRequest) request).getEntity().writeTo(byteArrayOutputStream);
                String encodedRequest = Encryption.aesDecryptRequest(this.secret, byteArrayOutputStream.toByteArray());
                String requestDecoded = new String(Base64.getDecoder().decode(encodedRequest));

                CollaboratorServer.logManager.logDebug("Decoded Request: " + requestDecoded);

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
            } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
                //Could not decrypt the request. The client probably used an invalid secret.
                CollaboratorServer.logManager.logError(e);
                response.setStatusCode(HttpStatus.SC_UNAUTHORIZED);
                response.setEntity(new StringEntity("The server could not decrypt the request. Is the secret correct?"));
            } catch (IllegalArgumentException e) {
                CollaboratorServer.logManager.logDebug(e.getMessage());
                response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
                response.setEntity(createEncryptedResponse(e.getMessage()));
            }
        } catch (Exception e) {
//            Log exception?
            response.setStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        }

        CollaboratorServer.logManager.logDebug("Response: ");
        CollaboratorServer.logManager.logDebug(response.toString());
    }

    private ByteArrayEntity createEncryptedResponse(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidParameterSpecException, NoSuchPaddingException {
        byte[] encrypted = Encryption.aesEncryptRequest(this.secret, message);
        return new ByteArrayEntity(encrypted);
    }
}
