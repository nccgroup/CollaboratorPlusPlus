package com.nccgroup.collaboratorplusplus.extension;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nccgroup.collaboratorplusplus.utilities.Encryption;
import org.apache.http.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.EntityUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

import static com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus.callbacks;
import static com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus.logManager;

public class ProxyService implements HttpRequestHandler {

    private final CollaboratorContextManager contextManager;
    private final int listenPort;
    private final boolean useAuthentication;
    private final boolean ignoreCertificateErrors;
    private final boolean hostnameVerification;
    private final HttpHost proxyAddress;
    private BiConsumer<Boolean, String> testCallback;

    private String sessionKey;
    private HttpServer server;
    private URI forwardingURI;
    private boolean isTestingConnection;

    ProxyService(CollaboratorContextManager collaboratorContextManager,
                    Integer listenPort, URI forwardingURI, boolean useAuthentication,
                    String secret, boolean ignoreCertificateErrors, boolean hostnameVerification,
                    HttpHost proxyAddress){
        this.contextManager = collaboratorContextManager;
        this.listenPort = listenPort;
        this.ignoreCertificateErrors = ignoreCertificateErrors;
        this.hostnameVerification = hostnameVerification;
        this.useAuthentication = useAuthentication;
        this.forwardingURI = forwardingURI;
        this.proxyAddress = proxyAddress;
        this.sessionKey = secret;
    }

    public void start() throws IllegalStateException {
        if(server != null){
            throw new IllegalStateException();
        }

        ServerBootstrap serverBootstrap = ServerBootstrap.bootstrap()
                .setConnectionReuseStrategy(new NoConnectionReuseStrategy())
                .setLocalAddress(Inet4Address.getLoopbackAddress())
                .setListenerPort(listenPort)
                .registerHandler("*", this);

        serverBootstrap.setExceptionLogger(ex -> {
            if(!(ex instanceof SocketException) && !(ex instanceof ConnectionClosedException)){
                logManager.logError("Uncaught Exception...");
                logManager.logError(ex.getMessage());
                logManager.logDebug(ex);
            }else{
                return;
            }
        });

        server = serverBootstrap.create();
        assert server != null;
        try {
            server.start();
        }catch (Exception e){
            if(this.testCallback != null) this.testCallback.accept(false, e.getMessage());
        }

        //Server is started...
    }

    public void stop(){
        if(server != null){
            server.shutdown(10, TimeUnit.MICROSECONDS);
        }
    }

    public void setTestCallback(BiConsumer<Boolean, String> testCallback) {
        this.testCallback = testCallback;
    }

    public void testConnection(){
        this.isTestingConnection = true;
        try {
            callbacks.createBurpCollaboratorClientContext().fetchAllCollaboratorInteractions();
        } catch (Exception e) {}
        this.isTestingConnection = false;
    }

    private CloseableHttpClient buildHttpClient(boolean ignoreCertificateErrors, boolean verifyHostname, HttpHost proxyAddress)
            throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        logManager.logDebug("Creating HTTP Client...");
        HttpClientBuilder httpClientBuilder =
                HttpClients.custom().setSSLContext(createSSLContext(ignoreCertificateErrors))
                        .setSSLHostnameVerifier(verifyHostname ? new DefaultHostnameVerifier() : NoopHostnameVerifier.INSTANCE)
                        .setConnectionReuseStrategy(new NoConnectionReuseStrategy());

        if(proxyAddress != null){
            logManager.logDebug("Setting Client Proxy to: " + proxyAddress);
            httpClientBuilder.setProxy(proxyAddress);
        }

        return httpClientBuilder.build();
    }

    private SSLContext createSSLContext(boolean ignoreCertificateErrors) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        TrustStrategy trustStrategy;
        SSLContext context;
        if(ignoreCertificateErrors){
            trustStrategy = new TrustAllStrategy();
            context = SSLContextBuilder.create().loadTrustMaterial(trustStrategy).build();
        }else{
            context = SSLContextBuilder.create().build();
        }
        return context;
    }

    private CloseableHttpClient buildHttpClient() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        CloseableHttpClient client;
        try {
            client = buildHttpClient(this.ignoreCertificateErrors, this.hostnameVerification, this.proxyAddress);
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            logManager.logDebug("Could not create HTTP client, " + e.getMessage());
            logManager.logError(e);
            throw e;
        }
        logManager.logDebug("HTTP Client Created: " + client);
        return client;
    }

    public HttpResponse requestInteractionsForContext(String contextIdentifier) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnsupportedEncodingException {
        return requestInteractionsForContext(buildHttpClient(), contextIdentifier);
    }

    private HttpResponse requestInteractionsForContext(CloseableHttpClient httpClient, String contextIdentifier) throws UnsupportedEncodingException {

        //Build request to collaborator server
        HttpHost host = new HttpHost(forwardingURI.getHost(), forwardingURI.getPort(), forwardingURI.getScheme());
        HttpRequest clientRequest;
        String pollingRequestUri = "/burpresults?biid=" + URLEncoder.encode(contextIdentifier);
        logManager.logInfo("Requesting interactions from server for identifier: " + contextIdentifier);


        String responseString = null;
        HttpResponse collaboratorServerResponse = null;
        try{
            if(useAuthentication){ //If we're using authentication, send an encrypted POST
                clientRequest = new HttpPost("/");
                String encodedURI = Base64.getEncoder().encodeToString(pollingRequestUri.getBytes());
                byte[] postBody = Encryption.aesEncryptRequest(this.sessionKey, encodedURI);
                ((HttpPost) clientRequest).setEntity(new ByteArrayEntity(postBody));
            }else{ //Otherwise do a basic GET.
                clientRequest = new HttpGet(pollingRequestUri);
            }

            clientRequest.addHeader("Connection", "close");

            if(!isTestingConnection && !contextIdentifier.equalsIgnoreCase("test")) //Don't bother processing the context if we're testing
                this.contextManager.pollingRequestSent(contextIdentifier);

            //Make request
            logManager.logDebug("Sending Request.. " + clientRequest);
            collaboratorServerResponse = httpClient.execute(host, clientRequest);
            final int statusCode = collaboratorServerResponse.getStatusLine().getStatusCode();
            logManager.logDebug("Received response: Status " + statusCode + ", " + collaboratorServerResponse.getEntity());
            boolean isAuthServer = collaboratorServerResponse.getFirstHeader("X-Auth-Compatible") != null;

            //If auth server and not using auth or trying to use auth on a standard collaborator instance
            if(isAuthServer ^ useAuthentication){
                collaboratorServerResponse.setStatusCode(HttpStatus.SC_BAD_REQUEST);
                responseString = (useAuthentication
                        ? "Authentication was enabled but was not supported by the Collaborator instance." :
                        "The targeted Collaborator instance requires authentication.");
            }else {
                if (!useAuthentication || statusCode == HttpStatus.SC_UNAUTHORIZED) {
                    // Either we're not targeting the authentication server or
                    // the server could not decrypt our request. Secret is probably incorrect!
                    responseString = EntityUtils.toString(collaboratorServerResponse.getEntity());
                    logManager.logDebug("Plaintext Response Received: " + responseString);
                } else {
                    //The response should have been encrypted.
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    collaboratorServerResponse.getEntity().writeTo(outputStream);
                    byte[] responseBytes = outputStream.toByteArray();

                    if (new String(responseBytes).startsWith("<html>") && this.proxyAddress != null) {
                        //No response from the server, burp responded with its own message!
                        //Likely due to protocol mismatch.
                        throw new Exception("Communication with the authentication server failed and it was not " +
                                "possible to determine why due to Burp providing its own response. " +
                                "Try again without proxying the requests through Burp.");
                    }

                    responseString = Encryption.aesDecryptRequest(this.sessionKey, responseBytes);
                    logManager.logDebug("Decrypted Response: " + responseString);
                }

                if (statusCode == HttpStatus.SC_OK) {
                    JsonObject responseJson = new JsonParser().parse(responseString).getAsJsonObject();
                    int interactions = responseJson.has("responses")
                            ? responseJson.getAsJsonArray("responses").size()
                            : 0;
                    logManager.logInfo(interactions +
                            (interactions == 1 ? " interaction" : " interactions") + " retrieved.");
                    if (interactions != 0) {
                        if (!isTestingConnection && !contextIdentifier.equalsIgnoreCase("test")) {
                            this.contextManager.interactionEventsReceived(contextIdentifier,
                                    responseJson.getAsJsonArray("responses"));
                        }
                    }
                }
            }
        } catch (ClientProtocolException | SSLHandshakeException e) {
            //Make the invalid certificate error a bit more friendly!
            if (e.getMessage() != null && e.getMessage().contains("unable to find valid certification path to requested target")) {
                responseString = "The SSL certificate provided by the server could not be verified. " +
                        "To override this, check the \"Ignore Certificate Errors\" option but proceed with caution!";
            } else {
                responseString = e.getMessage() != null
                        ? e.getMessage()
                        : "SSL exception. Check you're targetting the correct protocol and the server is configured correctly.";
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException
                | InvalidParameterSpecException | BadPaddingException e) {
            responseString = e.getMessage();
            logManager.logDebug(e);
        } catch (Exception e) {
            responseString = e.getMessage();
            logManager.logDebug(e);
        } finally {
            if(httpClient != null) {
                try {
                    httpClient.close();
                } catch (IOException ignored) {}
            }
            isTestingConnection = false;
        }

        if(collaboratorServerResponse != null) {
            collaboratorServerResponse.setEntity(new StringEntity(responseString));
        }
        return collaboratorServerResponse;
    }

    @Override
    public void handle(HttpRequest request, HttpResponse forwardedResponse, HttpContext context) throws IOException {
        if(isTestingConnection){
            logManager.logInfo("Testing the connection to the server...");
        }

        CloseableHttpClient httpClient;

        try{
            httpClient = buildHttpClient();
        }catch (Exception e){
            if(this.testCallback != null) this.testCallback.accept(false, "Could not build the HTTP client. Unable to poll the Collaborator Authenticator server.");
            return;
        }

        String responseString = "";

        String contextId = URLDecoder.decode(request.getRequestLine().getUri().substring("/burpresults?biid=".length()), "UTF-8");
        HttpResponse collaboratorResponse = requestInteractionsForContext(httpClient, contextId);

        if(collaboratorResponse != null) {
            int statusCode = collaboratorResponse.getStatusLine().getStatusCode();
            responseString = EntityUtils.toString(collaboratorResponse.getEntity());

            if (statusCode == HttpStatus.SC_OK) {
                //Must forward collaborator headers to the client too!
                for (Header header : collaboratorResponse.getAllHeaders()) {
                    if (header.getName().startsWith("X-Collaborator")) {
                        forwardedResponse.addHeader(header);
                    }
                }

                StringEntity forwardedResponseEntity = new StringEntity(responseString);
                forwardedResponseEntity.setContentType("application/json");
                forwardedResponse.setStatusCode(HttpStatus.SC_OK);
                forwardedResponse.setEntity(forwardedResponseEntity);

                if(this.testCallback != null) this.testCallback.accept(true, responseString);
                return;

            } else if (statusCode == HttpStatus.SC_UNAUTHORIZED) {
                responseString = "The provided secret is incorrect";
            } else {
                responseString = "The server could not process the request: " + responseString;
            }
        }else{
            responseString = "Could not communicate with the Collaborator server. " +
                    "Set the log level to debug and try again for more information.";
        }

        logManager.logError(responseString);
        if(this.testCallback != null) this.testCallback.accept(false, responseString);
    }

    public HttpServer getServer() {
        return server;
    }
}
