package com.nccgroup.collaboratorplusplus.extension;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContextManager;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;
import com.nccgroup.collaboratorplusplus.extension.exception.*;
import com.nccgroup.collaboratorplusplus.utilities.Encryption;
import org.apache.http.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.SocketConfig;
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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.net.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import static com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus.logManager;

public class ProxyService implements HttpRequestHandler {

    private final CollaboratorContextManager contextManager;
    private final String collaboratorAddress;
    private final int listenPort;
    private final boolean useAuthentication;
    private final boolean ignoreCertificateErrors;
    private final boolean hostnameVerification;
    private final HttpHost proxyAddress;
    private final ArrayList<IProxyServiceListener> serviceListeners;

    private String sessionKey;
    private HttpServer server;
    private URI forwardingURI;

    ProxyService(CollaboratorContextManager collaboratorContextManager, ArrayList<IProxyServiceListener> listeners,
                 String collaboratorAddress, Integer listenPort, URI forwardingURI, boolean useAuthentication,
                 String secret, boolean ignoreCertificateErrors, boolean hostnameVerification,
                 HttpHost proxyAddress){
        this.serviceListeners = listeners;
        this.contextManager = collaboratorContextManager;
        this.collaboratorAddress = collaboratorAddress;
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
                .setSocketConfig(SocketConfig.custom().setSoReuseAddress(true).build())
                .registerHandler("*", this);

        serverBootstrap.setExceptionLogger(ex -> {
            if(!(ex instanceof SocketException) && !(ex instanceof ConnectionClosedException)){
                logManager.logError("Uncaught Exception...");
                logManager.logError(ex.getMessage());
                logManager.logDebug(ex);
            }
        });

        server = serverBootstrap.create();
        assert server != null;
        try {
            logManager.logInfo("Server Started...");
            server.start();
            logManager.logInfo("Testing connection to collaborator instance.");
            requestInteractionsForContext("test");
            handleStartupSuccess("Server Started.");
        }catch (Exception e){
            handleStartupFailure(e.getMessage());
        }

        //Server is started...
    }

    public void stop(){
        if(server != null){
            server.shutdown(500, TimeUnit.MILLISECONDS);
            server = null;
        }
    }

    private CloseableHttpClient buildHttpClient(boolean ignoreCertificateErrors, boolean verifyHostname, HttpHost proxyAddress)
            throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        logManager.logDebug("Creating HTTP Client...");
        HttpClientBuilder httpClientBuilder =
                HttpClients.custom().setSSLContext(createSSLContext(ignoreCertificateErrors))
                        .setSSLHostnameVerifier(verifyHostname ? new DefaultHostnameVerifier() : NoopHostnameVerifier.INSTANCE)
                        .setConnectionReuseStrategy(new NoConnectionReuseStrategy())
                        .setDefaultRequestConfig(RequestConfig.custom().setConnectTimeout(5000).build()); //Don't hang around!

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

    private CloseableHttpClient buildHttpClient() throws CollaboratorPollingException {
        CloseableHttpClient client;
        try {
            client = buildHttpClient(this.ignoreCertificateErrors, this.hostnameVerification, this.proxyAddress);
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            logManager.logError("Could not create HTTP client, " + e.getMessage());
            logManager.logDebug(e);
            throw new CollaboratorPollingException(e.getMessage());
        }
        logManager.logDebug("HTTP Client Created: " + client);
        return client;
    }

    public ArrayList<Interaction> requestInteractionsForContext(String contextIdentifier) throws CollaboratorPollingException {
        CloseableHttpClient client = buildHttpClient();
        try {
            return requestInteractionsForContext(client, contextIdentifier).getInteractions();
        }catch (CollaboratorPollingException e){
            this.contextManager.pollingFailure(e.getMessage());
            throw e;
        } finally {
            if (client != null) {
                try {
                    client.close();
                } catch (IOException ignored) {}
            }
        }
    }

    private CollaboratorServerResponse requestInteractionsForContext(CloseableHttpClient httpClient, String contextIdentifier) throws CollaboratorPollingException {

        //Build request to collaborator server
        HttpHost host = new HttpHost(forwardingURI.getHost(), forwardingURI.getPort(), forwardingURI.getScheme());
        HttpRequest clientRequest;
        String pollingRequestUri = "/burpresults?biid=" + URLEncoder.encode(contextIdentifier);
        logManager.logInfo("Requesting interactions from server for identifier: " + contextIdentifier);


        String responseString = null;
        HttpResponse collaboratorServerResponse = null;
        try {
            if (useAuthentication) { //If we're using authentication, send an encrypted POST
                clientRequest = new HttpPost("/");
                buildAuthenticatedRequest((HttpPost) clientRequest, pollingRequestUri);
            } else { //Otherwise do a basic GET.
                clientRequest = new HttpGet(pollingRequestUri);
            }

            clientRequest.addHeader("Connection", "close");

            //Don't process the context if we're testing connection
            if (!contextIdentifier.equalsIgnoreCase("test"))
                this.contextManager.pollingRequestSent(this.collaboratorAddress, contextIdentifier);

            //Make the request
            logManager.logDebug("Sending Request.. " + clientRequest);
            collaboratorServerResponse = httpClient.execute(host, clientRequest);
            final int statusCode = collaboratorServerResponse.getStatusLine().getStatusCode();
            boolean isAuthServer = collaboratorServerResponse.getFirstHeader("X-Auth-Compatible") != null;
            logManager.logDebug("Received response: Status " + statusCode + ", " + collaboratorServerResponse.getEntity());

            if (collaboratorServerResponse.getFirstHeader("X-Collaborator-Version") == null) {
                logManager.logDebug("Server Response: " + EntityUtils.toString(collaboratorServerResponse.getEntity()));
                throw new InvalidResponseException("Not a valid collaborator response! Are we definitely targeting a Collaborator server?");
            }


            if (isAuthServer ^ useAuthentication) {
                //If auth server and not using auth
                // or trying to use auth on a standard collaborator instance
                responseString = (useAuthentication
                        ? "Authentication was enabled but was not supported by the Collaborator instance." :
                        "The targeted Collaborator instance requires authentication.");
                throw new AuthenticationException(responseString);
            } else {
                if (!useAuthentication || statusCode == HttpStatus.SC_UNAUTHORIZED) {
                    // Either we're not targeting the authentication server or
                    // the server could not decrypt our request. Secret is probably incorrect!
                    logManager.logDebug("Plaintext Response Received: " + responseString);
                    responseString = EntityUtils.toString(collaboratorServerResponse.getEntity());
                    throw new InvalidSecretException(responseString);
                } else {
                    //The response should have been encrypted.
                    byte[] responseBytes = EntityUtils.toByteArray(collaboratorServerResponse.getEntity());

                    if (new String(responseBytes).startsWith("<html>") && this.proxyAddress != null) {
                        //No response from the server, burp responded with its own message!
                        //Likely due to protocol mismatch.
                        throw new InvalidResponseException("Communication with the authentication server failed. " +
                                "It was not possible to determine why due to Burp providing its own response. " +
                                "Try again without proxying the requests through Burp.");
                    }

                    responseString = Encryption.aesDecryptRequest(this.sessionKey, responseBytes);
                    logManager.logDebug("Decrypted Response: " + responseString);
                }

                if (statusCode == HttpStatus.SC_OK) {
                    JsonObject interactionsJson = JsonParser.parseString(responseString).getAsJsonObject();
                    ArrayList<Interaction> interactions = Utilities.parseInteractions(interactionsJson);
                    logManager.logInfo(String.format("%d interaction%s retrieved.", interactions.size(),
                            interactions.size() > 0 ? "s" : ""));

                    if (!contextIdentifier.equalsIgnoreCase("test")) {
                        this.contextManager.addInteractions(this.collaboratorAddress,  contextIdentifier, interactions);
                    }

                    return new CollaboratorServerResponse(collaboratorServerResponse, interactions);
                }else{
                    throw new InvalidResponseException("The Collaborator server responded with an error code which was not 200 OK.");
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
            logManager.logDebug(e);
            throw new CollaboratorSSLException(responseString);
        }catch (GeneralSecurityException | IOException e) {
            logManager.logDebug(e);
            throw new CollaboratorPollingException(e.getMessage());
        } catch (CollaboratorPollingException e){
            logManager.logDebug(e);
            throw e;
        }
    }

    @Override
    public void handle(HttpRequest request, HttpResponse forwardedResponse, HttpContext context) throws IOException {

        String responseString = "";
        try {
            CloseableHttpClient httpClient = buildHttpClient();
            String contextId = URLDecoder.decode(request.getRequestLine().getUri().substring("/burpresults?biid=".length()), "UTF-8");

            CollaboratorServerResponse collaboratorResponse;
            try {
                collaboratorResponse = requestInteractionsForContext(httpClient, contextId);
            }finally {
                if (httpClient != null) {
                    try {
                        httpClient.close();
                    } catch (IOException ignored) {}
                }
            }

            //Must forward collaborator headers to the client too!
            for (Header header : collaboratorResponse.getHttpResponse().getAllHeaders()) {
                if (header.getName().startsWith("X-Collaborator")) {
                    forwardedResponse.addHeader(header);
                }
            }

            JsonObject interactions =
                    Utilities.convertInteractionsToCollaboratorResponse(collaboratorResponse.getInteractions());
            StringEntity forwardedResponseEntity = new StringEntity(new Gson().toJson(interactions));
            forwardedResponseEntity.setContentType("application/json");
            forwardedResponse.setStatusCode(HttpStatus.SC_OK);
            forwardedResponse.setEntity(forwardedResponseEntity);

            return;
        }catch (Exception e){
            logManager.logError(e.getMessage());
            logManager.logDebug(e);
            responseString = e.getMessage();
        }

        this.contextManager.pollingFailure(responseString);

        forwardedResponse.setStatusCode(500);
        logManager.logInfo("Could not retrieve interactions: " + responseString);
    }

    private void buildAuthenticatedRequest(HttpPost clientRequest, String pollingRequestUri) throws GeneralSecurityException {
        String encodedURI = Base64.getEncoder().encodeToString(pollingRequestUri.getBytes());
        byte[] postBody = Encryption.aesEncryptRequest(this.sessionKey, encodedURI);
        clientRequest.setEntity(new ByteArrayEntity(postBody));
    }

    private void handleStartupSuccess(String message) {
        for (IProxyServiceListener serviceListener : this.serviceListeners) {
            try{
                serviceListener.onStartupSuccess(message);
            }catch (Exception ignored){
                ignored.printStackTrace();
            }
        }
    }

    private void handleStartupFailure(String message){
        for (IProxyServiceListener serviceListener : this.serviceListeners) {
            try{
                serviceListener.onStartupFail(message);
            }catch (Exception ignored){
                ignored.printStackTrace();
            }
        }
    }

    public void addProxyServiceListener(IProxyServiceListener listener){
        this.serviceListeners.add(listener);
    }

    public void removeProxyServiceListener(IProxyServiceListener listener){
        this.serviceListeners.remove(listener);
    }

    public HttpServer getServer() {
        return server;
    }
}
