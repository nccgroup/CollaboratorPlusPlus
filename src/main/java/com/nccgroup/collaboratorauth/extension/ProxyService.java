package com.nccgroup.collaboratorauth.extension;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nccgroup.collaboratorauth.utilities.Encryption;
import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.*;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import static com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator.logController;

public class ProxyService implements HttpRequestHandler {

    private final int listenPort;
    private final boolean ignoreCertificateErrors;
    private final boolean hostnameVerification;
    private final ArrayList<ProxyServiceListener> listeners;

    private String sessionKey;
    private HttpServer server;
    private URI forwardingURI;

    public ProxyService(Integer listenPort, URI forwardingURI, String secret,
                        boolean ignoreCertificateErrors, boolean hostnameVerification){
        this.listeners = new ArrayList<>();
        this.listenPort = listenPort;
        this.ignoreCertificateErrors = ignoreCertificateErrors;
        this.hostnameVerification = hostnameVerification;
        this.forwardingURI = forwardingURI;
        this.sessionKey = secret;
    }

    public void start() throws IOException, IllegalStateException {
        if(server != null){
            throw new IllegalStateException();
        }

        ServerBootstrap serverBootstrap = ServerBootstrap.bootstrap()
                .setConnectionReuseStrategy(new NoConnectionReuseStrategy())
                .setLocalAddress(Inet4Address.getLoopbackAddress())
                .setListenerPort(listenPort)
                .registerHandler("*", this);

        serverBootstrap.setExceptionLogger(ex -> {
            logController.logError(ex.getMessage());
            logController.logError(ex);
            for (ProxyServiceListener listener : this.listeners) {
                listener.onFail(ex.getMessage());
            }
        });

        server = serverBootstrap.create();
        assert server != null;
        server.start();

        //Server is started...
    }

    public void stop(){
        if(server != null){
            server.shutdown(10, TimeUnit.MICROSECONDS);
        }
    }

    private HttpClient buildHttpClient(boolean ignoreCertificateErrors, boolean verifyHostname) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        return HttpClients.custom().setSSLContext(createSSLContext(ignoreCertificateErrors))
                .setSSLHostnameVerifier(verifyHostname ? new DefaultHostnameVerifier() : NoopHostnameVerifier.INSTANCE)
                .setConnectionReuseStrategy(new NoConnectionReuseStrategy())
                .build();
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

    @Override
    public void handle(HttpRequest request, HttpResponse forwardedResponse, HttpContext context) throws IOException {
        CloseableHttpClient client;
        try {
            client = (CloseableHttpClient) buildHttpClient(this.ignoreCertificateErrors, this.hostnameVerification);
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            logController.logDebug("Could not create HTTP client, " + e.getMessage());
            logController.logError(e);
            for (ProxyServiceListener listener : listeners) {
                listener.onFail("Could not build the HTTP client. Unable to poll the Collaborator Authenticator server.");
            }
            return;
        }

        String responseString;
        try {
            //Build request to auth server
            HttpPost post = new HttpPost(forwardingURI);
            String decodedURI = request.getRequestLine().getUri();
            String encodedURI = Base64.getEncoder().encodeToString(decodedURI.getBytes());
            byte[] postBody = Encryption.aesEncryptRequest(this.sessionKey, encodedURI);
            post.setEntity(new ByteArrayEntity(postBody));
            post.addHeader("Connection", "close");

            logController.logDebug("Requesting interactions from authentication server for URI: " + decodedURI);

            //Make request
            final HttpResponse actualServerResponse = client.execute(post);
            final int statusCode = actualServerResponse.getStatusLine().getStatusCode();

            if(statusCode == HttpStatus.SC_UNAUTHORIZED){
                //The server could not decrypt our request. Secret is probably incorrect!
                responseString = EntityUtils.toString(actualServerResponse.getEntity());
            }else{
                //The response should have been encrypted.
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                actualServerResponse.getEntity().writeTo(outputStream);
                byte[] responseBytes = outputStream.toByteArray();
                responseString = Encryption.aesDecryptRequest(this.sessionKey, responseBytes);
            }

            logController.logDebug("Received response: Status " + statusCode + ", " + responseString);

            if (statusCode == HttpStatus.SC_OK) {
                JsonObject responseJson = new JsonParser().parse(responseString).getAsJsonObject();
                int interactions = responseJson.has("responses")
                        ? responseJson.getAsJsonArray("responses").size()
                        : 0;
                if (interactions != 0)
                    logController.logInfo(interactions +
                            (interactions == 1 ? " interaction" : " interactions") + " retrieved.");

                //Must forward collaborator headers to the client too!
                for (Header header : actualServerResponse.getAllHeaders()) {
                    if (header.getName().startsWith("X-Collaborator")) {
                        forwardedResponse.addHeader(header);
                    }
                }

                StringEntity forwardedResponseEntity = new StringEntity(responseString);
                forwardedResponseEntity.setContentType("application/json");
                forwardedResponse.setStatusCode(HttpStatus.SC_OK);
                forwardedResponse.setEntity(forwardedResponseEntity);

                handleSuccess(responseString);
                return;

            } else if (statusCode == HttpStatus.SC_UNAUTHORIZED) {
                responseString = "The provided secret is incorrect";
            } else {
                responseString = "The server could not process the request. " + responseString;
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
        } catch (NoSuchAlgorithmException | InvalidCipherTextException | InvalidKeySpecException e) {
            responseString = "Could not decrypt the response sent by the server. Is our secret correct?";
        } finally {
            if(client != null) client.close();
        }

        logController.logDebug(responseString);
        handleFailure(responseString);
    }

    private void handleFailure(String reason){
        for (ProxyServiceListener proxyServiceListener : new ArrayList<>(this.listeners)) {
            proxyServiceListener.onFail(reason);
        }
    }

    private void handleSuccess(String message){
        for (ProxyServiceListener proxyServiceListener : new ArrayList<>(this.listeners)) {
            proxyServiceListener.onSuccess(message);
        }
    }

    public HttpServer getServer() {
        return server;
    }

    public void addProxyServiceListener(ProxyServiceListener proxyServiceListener){
        this.listeners.add(proxyServiceListener);
    }

    public void removeProxyServiceListener(ProxyServiceListener proxyServiceListener){
        this.listeners.remove(proxyServiceListener);
    }
}
