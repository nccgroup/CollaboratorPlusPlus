package com.nccgroup.collaboratorauth.extension;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import java.io.*;
import java.net.Inet4Address;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import static com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator.logController;

public class ProxyService implements HttpRequestHandler {

    private final int listenPort;
    private final boolean ignoreCertificateErrors;
    private final ArrayList<ProxyServiceListener> listeners;

    private String sessionKey;
    private HttpServer server;
    private URI forwardingURI;

    public ProxyService(Integer listenPort, boolean ignoreCertificateErrors, URI forwardingURI, String secret){
        this.listeners = new ArrayList<>();
        this.listenPort = listenPort;
        this.ignoreCertificateErrors = ignoreCertificateErrors;
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
            client = HttpClients.custom().setSSLContext(createSSLContext(true))
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .setConnectionReuseStrategy(new NoConnectionReuseStrategy())
                    .build();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            logController.logDebug("Could not create HTTP client, " + e.getMessage());
            logController.logError(e);
            for (ProxyServiceListener listener : listeners) {
                listener.onFail("Could not build the HTTP client. Unable to poll the Collaborator Authenticator server.");
            }
            return;
        }

        //Build request to auth server
        HttpPost post = new HttpPost(forwardingURI);
        String encodedURI = Base64.getEncoder().encodeToString(request.getRequestLine().getUri().getBytes());
        String postData = "{\"secret\":\"" + this.sessionKey + "\",\"request\":\"" + encodedURI + "\"}";
        post.setEntity(new StringEntity(postData));
        post.addHeader("Connection", "close");

        logController.logDebug("Requesting interactions from authentication server, " + postData);

        HttpResponse actualServerResponse = null;

        try {
            //Make request
            actualServerResponse = client.execute(post);
            int statusCode = actualServerResponse.getStatusLine().getStatusCode();
            String responseString = EntityUtils.toString(actualServerResponse.getEntity());

            logController.logDebug("Received response: Status " + statusCode + ", " + responseString);

            forwardedResponse.setStatusCode(statusCode);

            if (statusCode == HttpStatus.SC_OK) {

                JsonObject responseJson = new JsonParser().parse(responseString).getAsJsonObject();
                int interactions = responseJson.has("responses")
                        ? responseJson.getAsJsonArray("responses").size()
                        : 0;
                if(interactions != 0)
                    logController.logInfo(interactions +
                        (interactions == 1 ? " interaction" : " interactions") + " retrieved.");
                handleSuccess(responseString);

                //Must forward collaborator headers to the client too!
                for (Header header : actualServerResponse.getAllHeaders()) {
                    if(header.getName().equalsIgnoreCase("X-Collaborator-Version")
                            || header.getName().equalsIgnoreCase("X-Collaborator-Time")){
                        forwardedResponse.addHeader(header);
                    }
                }

            } else if (statusCode == HttpStatus.SC_UNAUTHORIZED) {
                responseString = "The provided secret is incorrect";
                logController.logDebug(responseString);
                handleFailure(responseString);
            } else {
                responseString = "The server could not process the request. " + responseString;
                logController.logDebug(responseString);
                handleFailure(responseString);
            }

            StringEntity forwardedResponseEntity = new StringEntity(responseString);
            forwardedResponseEntity.setContentType("application/json");
            forwardedResponse.setEntity(forwardedResponseEntity);

        }catch (ClientProtocolException | SSLHandshakeException e){
            logController.logError(e);
            for (ProxyServiceListener listener : this.listeners) {
                listener.onFail(e.getMessage() != null ? e.getMessage() :
                        "SSL exception. Check you're targetting the correct protocol.");
            }
        }finally {
            client.close();
        }
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
