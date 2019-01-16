package com.nccgroup.collaboratorauth.extension;

import org.apache.commons.io.IOUtils;
import org.apache.http.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.Inet4Address;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class ProxyService implements HttpRequestHandler {

    private final CollaboratorAuthenticator extension;
    private final int listenPort;
    private final boolean useSsl;
    private final boolean ignoreCertificateErrors;
    private final ArrayList<ProxyServiceListener> listeners;

    private String sessionKey;
    private HttpServer server;
    private URI collaboratorServer;

    public ProxyService(CollaboratorAuthenticator authenticator,
                        Integer listenPort, boolean useSsl, boolean ignoreCertificateErrors,
                        URI collaboratorServer, String sessionKey){
        this.extension = authenticator;
        this.listenPort = listenPort;
        this.useSsl = useSsl;
        this.ignoreCertificateErrors = ignoreCertificateErrors;
        this.collaboratorServer = collaboratorServer;
        this.sessionKey = sessionKey;

        this.listeners = new ArrayList<>();
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
            System.out.println(ex.getMessage());
            for (ProxyServiceListener listener : this.listeners) {
                listener.onFail(ex.getMessage());
            }
        });

//        SSLContext sslContext = createSSLContext(this.ignoreCertificateErrors);
//        serverBootstrap.setSslContext(sslContext); //TODO ENABLE SSL SUPPORT

        server = serverBootstrap.create();
        assert server != null;
        server.start();

        //Server is started...
    }

    public void stop(){
        if(server != null){
            server.shutdown(10, TimeUnit.SECONDS);
        }
    }

    private SSLContext createSSLContext(boolean ignoreCertificateErrors) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        SSLContext context = SSLContextBuilder.create().loadTrustMaterial(new TrustAllStrategy()).build();
        return context;
    }

    @Override
    public void handle(HttpRequest request, HttpResponse forwardedResponse, HttpContext context) throws HttpException, IOException {
        CloseableHttpClient client = null;
        try {
            client = HttpClients.custom().setSSLContext(createSSLContext(true))
                    .setSSLHostnameVerifier(AllowAllHostnameVerifier.INSTANCE)
                    .setConnectionReuseStrategy(new NoConnectionReuseStrategy()).build();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            for (ProxyServiceListener listener : listeners) {
                listener.onFail("Could not build HttpClient.");
            }
            e.printStackTrace();
            return;
        }

        //Build request to auth server
        HttpPost post = new HttpPost(collaboratorServer);
        String encodedURI = Base64.getEncoder().encodeToString(request.getRequestLine().getUri().getBytes());
        String postData = "{\"secret\":\"" + this.sessionKey + "\",\"request\":\"" + encodedURI + "\"}";
        post.setEntity(new StringEntity(postData));

        HttpResponse actualServerResponse = null;

        try {
            //Make request
            actualServerResponse = client.execute(post);
            int statusCode = actualServerResponse.getStatusLine().getStatusCode();
            String responseString = EntityUtils.toString(actualServerResponse.getEntity());

            forwardedResponse.setStatusCode(statusCode);

            if (statusCode == HttpStatus.SC_OK) {

                for (ProxyServiceListener listener : this.listeners) {
                    listener.onSuccess(responseString);
                }

            } else if (statusCode == HttpStatus.SC_UNAUTHORIZED) {
                //Incorrect secret
                responseString = "The provided secret is incorrect";
                for (ProxyServiceListener listener : this.listeners) {
                    listener.onFail(responseString);
                }
            } else {
                responseString = "An error occurred on the server.\n" + responseString;
                for (ProxyServiceListener listener : this.listeners) {
                    listener.onFail(responseString);
                }
            }

            StringEntity forwardedResponseEntity = new StringEntity(responseString);
            forwardedResponseEntity.setContentType("application/json");
            forwardedResponse.setEntity(forwardedResponseEntity);

        }catch (ClientProtocolException | SSLHandshakeException e){
            for (ProxyServiceListener listener : this.listeners) {
                listener.onFail(e.getMessage() != null ? e.getMessage() :
                        "SSL exception. Check you're targetting the correct protocol.");
            }
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
