package com.nccgroup.collaboratorauth.server;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.io.IOUtils;
import org.apache.http.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
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
            //TODO Respond with information about what the purpose of the server is.
            response.setEntity(new StringEntity(""));
            response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
            return;
        }
        String requestPostJson = EntityUtils.toString(((BasicHttpEntityEnclosingRequest) request).getEntity());
        JsonObject requestJsonObject;
        CloseableHttpClient client = HttpClients.createDefault();

        try {
            requestJsonObject = new JsonParser().parse(requestPostJson).getAsJsonObject();
            if (requestJsonObject.has("secret") && requestJsonObject.has("request")) {
                if (!requestJsonObject.get("secret").getAsString().equals(this.secret)) {
                    if(logLevel.equalsIgnoreCase("debug") || logLevel.equalsIgnoreCase("info") || logLevel.equalsIgnoreCase("error"))
                        System.out.println("Blocked request with invalid secret: \"" + requestJsonObject.get("secret").getAsString() + "\"");
                    response.setStatusCode(HttpStatus.SC_UNAUTHORIZED);
                    return;
                }

                String requestEncoded = requestJsonObject.get("request").getAsString();
                String requestDecoded = new String(Base64.getDecoder().decode(requestEncoded));

                if(!requestDecoded.startsWith("/burpresults?biid=")){ //If request is not a valid collaborator request. (SSRF protection!)
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
                    if(header.getName().equalsIgnoreCase("X-Collaborator-Version")
                            || header.getName().equalsIgnoreCase("X-Collaborator-Time")){
                        response.addHeader(header);
                    }
                }

                if (actualRequestResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    response.setEntity(new StringEntity(actualResponse));
                } else {
                    if(logLevel.equalsIgnoreCase("debug") || logLevel.equalsIgnoreCase("error"))
                        System.err.println("Actual collaborator server returned a " +
                            actualRequestResponse.getStatusLine().getStatusCode() + " response!");
                }
            } else {
                response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
            }
        }catch (HttpHostConnectException e){
            response.setEntity(new StringEntity(e.getMessage()));
            response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
        }catch (Exception e){
            response.setEntity(new StringEntity(e.getMessage()));
            response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
        }finally {
            client.close();
        }
    }
}
