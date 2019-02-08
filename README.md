## Collaborator Auth - Client Component

#### Running the Client
1. Add the extension to Burp. *Note: This is the same jar as the server.*
2. Specify the address and the Collaborator Auth Server is listening on.
3. Specify the secret configured by the server.
4. Start the local server, this will also configure the polling settings within burp for you. 
(Note: You will still have to configure the interaction location within the collaborator settings)
5. Optional: Run Burp's Collaborator health check to make sure everything is working.


## Collaborator Auth - Server Component

#### Running the Server
1. Execute `java -jar CollaboratorAuth.jar` to generate the default configuration.
2. Edit the generated file to point to your private collaborator instance and choose a suitable secret.
3. Run the server again and specify the configuration to be used `java -jar CollaboratorAuth.jar CollaboratorServer.properties`

*Note: To allow HTTP and HTTPS requests to the Collaborator Auth server, create two copies of the configuration file, 
configuring one for HTTP and one for HTTPS and run two instances of the Collaborator Auth server.*

#### Optional: Generate the KeyStore from certificate and private key to enable polling over HTTPS

1) `openssl pkcs12 -export -in certificate.crt -inkey private.key -out polling.domain.p12 -name polling`
2) Enter a password to use for the key.
3) `keytool -importkeystore -deststorepass NEW_PASSWORD_FOR_KEYSTORE -destkeypass NEW_PASSWORD_FOR_KEY \ `
    <br/>`-destkeystore polling.domain.jks -srckeystore polling.p12 -srcstoretype PKCS12 \ `
    <br/>`-srcstorepass KEY_PASS_FROM_PREVIOUS_STEP -alias polling`  
4) Edit the configuration file to enable ssl, point the server to the keystore and specify the passwords used.
5) Run the server again and specify the configuration to be used `java -jar CollaboratorAuth.jar CollaboratorServer.properties`

#### Recommended: Secure the *actual* Collaborator Server

1) Change the interface and polling port used by Burp Collaborator.
- It is recommended to use the loopback interface for this.
 