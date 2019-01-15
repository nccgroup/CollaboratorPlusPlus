package com.nccgroup.collaboratorauth.server;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;

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
    public void handle(HttpRequest request, HttpResponse response, HttpContext context) throws HttpException, IOException {
        String requestPostJson = EntityUtils.toString(((BasicHttpEntityEnclosingRequest) request).getEntity());
        JsonObject requestJsonObject;

        try {
            requestJsonObject = new JsonParser().parse(requestPostJson).getAsJsonObject();
            if (requestJsonObject.has("secret") && requestJsonObject.has("request")) {
                if (!requestJsonObject.get("secret").getAsString().equals(this.secret)) {
                    System.out.println("Blocked request with invalid secret: \"" + requestJsonObject.get("secret").getAsString() + "\"");
                    response.setStatusCode(HttpStatus.SC_UNAUTHORIZED);
                    return;
                }

                String requestPath = requestJsonObject.get("request").getAsString().split("\\?", 2)[0];
                String requestQuery = requestJsonObject.get("request").getAsString().split("\\?", 2)[1];

                //Make request to actual collaborator server
                HttpClient client = HttpClients.createDefault();
                URI getURI = new URI(actualIsHttps ? "https" : "http", "",
                        actualAddress, actualPort,
                        requestPath, requestQuery, "");
                HttpGet getRequest = new HttpGet(getURI);
                HttpResponse actualRequestResponse = client.execute(getRequest);

                response.setStatusCode(actualRequestResponse.getStatusLine().getStatusCode());

                if (actualRequestResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    response.setEntity(actualRequestResponse.getEntity());
                } else {
                    System.err.println("Actual collaborator server returned a " +
                            actualRequestResponse.getStatusLine().getStatusCode() + " response!");
                }
            } else {
                response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
            }
        }catch (HttpHostConnectException e){
            response.setEntity(new StringEntity("The collaborator auth server could not contact the actual collaborator server!"));
            response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
        }catch (Exception e){
            response.setEntity(new StringEntity("The collaborator auth server could not contact the actual collaborator server!"));
            response.setStatusCode(HttpStatus.SC_BAD_REQUEST);
        }
    }
}
