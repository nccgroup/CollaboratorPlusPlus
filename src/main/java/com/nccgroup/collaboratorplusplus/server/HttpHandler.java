package com.nccgroup.collaboratorplusplus.server;

import com.nccgroup.collaboratorplusplus.extension.Globals;
import com.nccgroup.collaboratorplusplus.utilities.Encryption;
import org.apache.commons.io.IOUtils;
import org.apache.http.*;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URL;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

public class HttpHandler implements HttpRequestHandler {

    private static Logger logger = LogManager.getLogger(Globals.EXTENSION_NAME);
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

    private CloseableHttpClient buildHttpClient() {
        HttpClientBuilder httpClientBuilder =
                HttpClients.custom()
                        .setConnectionReuseStrategy(new NoConnectionReuseStrategy())
                        .setDefaultRequestConfig(RequestConfig.custom().setConnectTimeout(5000).build()); //Don't hang around!

        return httpClientBuilder.build();
    }

    @Override
    public void handle(HttpRequest request, HttpResponse response, HttpContext context) {
        response.addHeader(new BasicHeader("X-Auth-Compatible", "true"));

        if (!(request instanceof BasicHttpEntityEnclosingRequest)) {
            response.setEntity(new StringEntity(Utilities.getAboutPage(), ContentType.TEXT_HTML));
            response.setStatusCode(HttpStatus.SC_OK);
            return;
        }

        logger.debug("Retrieved request: ");
        logger.debug(((BasicHttpEntityEnclosingRequest) request).getEntity().toString());

        try (CloseableHttpClient client = buildHttpClient()) {
            try {
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                ((BasicHttpEntityEnclosingRequest) request).getEntity().writeTo(byteArrayOutputStream);
                String encodedRequest = Encryption.aesDecryptRequest(this.secret, byteArrayOutputStream.toByteArray());
                String requestDecoded = new String(Base64.getDecoder().decode(encodedRequest));

                logger.debug("Decoded Request: " + requestDecoded);

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
                logger.error(e);
                response.setStatusCode(HttpStatus.SC_UNAUTHORIZED);
                response.setEntity(new StringEntity("The server could not decrypt the request. Is the secret correct?"));
            } catch (IllegalArgumentException e) {
                logger.debug(e.getMessage());
                response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
                response.setEntity(createEncryptedResponse(e.getMessage()));
            }
        } catch (Exception e) {
//            Log exception?
            response.setStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        }

        logger.debug("Response: ");
        logger.debug(response.toString());
    }

    private ByteArrayEntity createEncryptedResponse(String message) throws GeneralSecurityException {
        byte[] encrypted = Encryption.aesEncryptRequest(this.secret, message);
        return new ByteArrayEntity(encrypted);
    }
}
