## Collaborator Auth - Client

#### Running the Client
1. Add the extension to Burp. 
    * *Note: This is the same jar as the server.*
2. Specify the address and the port the Collaborator Auth Server is listening on within the extension config.
3. Specify the secret configured by the server.
4. Start the local server, this will also configure the collaborator settings within Burp for you.
5. Optional: Run Burp's Collaborator health check to make sure everything is working.


#### Additional Settings
A few additional settings have been added to Collaborator Auth for convenience.

**Use SSL:** Toggle the use of SSL between the client and server. 
*Be sure your server is configured to use SSL on the target port too.*

**Ignore Certificate Errors:** Disables certificate validity checks. 
*Allows usage of self-signed / expired certificates.*

**Enable SSL Hostname Verification:** Do not check the certificate hostname matches the target domain.

**Block Public Collaborator Server:** Prevents accidental usage of the public Burp collaborator server.
Adds a DNS entry for *"burpcollaborator.net"* to *127.0.0.1* in Burp's hostname resolution config.




## Collaborator Auth - Server

#### Running the Server
1. Execute `java -jar CollaboratorAuth.jar` to generate the default configuration.
2. Edit the generated file to point to your private collaborator instance and choose a suitable secret.
3. Run the server again and specify the configuration to be used `java -jar CollaboratorAuth.jar YOURCONFIGFILE.properties`

*Note: To allow HTTP and HTTPS requests to the Collaborator Auth server, create two copies of the configuration file, 
configuring one for HTTP and one for HTTPS and run two instances of the Collaborator Auth server.*

#### SSL Configuration

To enable the usage of SSL, generate a certificate for the server and use one of the below methods to configure the server.

For both methods, ensure `enable_ssl` is `true` in the config file. 

##### Recommended: Simple Configuration

1. Generate a new private key and certificate to use for the server using the following command, or use an existing one.
    - `openssl req -newkey rsa:2048 -nodes -keyout privatekey.pem -x509 -days 365 -out certificate.pem`
1. Optional: Get the certificate signed by a trusted CA.
1. Edit the config file:
    - Set `ssl_private_key_path` to the path of your private key.
    - Set `ssl_certificate_path` to the path of your certificate.
    - If your certificate chain requires an intermediate certificate:
        - Set `ssl_intermediate_certificate_path` to the path of your intermediate certificate.

##### Alternative: Java Keystore

This method was added purely for compatability reasons. I highly recommend using the simple configuration unless
there is a reason otherwise.  

1. Edit the config file and set the value for `ssl_private_key_path` to an empty string `""`. 
    - This will enable the use of the keystore for configuration. 
1. Generate a new private key and certificate to use for the server using the following command.
    - `openssl req -newkey rsa:2048 -nodes -keyout privatekey.pem -x509 -days 365 -out certificate.pem`
1. Convert the key and certificate to PKCS12. 
    - `openssl pkcs12 -export -in certificate.pem -inkey privatekey.pem -out polling.p12 -name polling`
1. Enter a password to be used for encrypting the PKCS12 file. **This will be used in the next step!** 
1. Import the PKCS12 file into a new Java Keystore. 
    - `keytool -importkeystore -deststorepass NEW_PASSWORD_FOR_KEYSTORE -destkeypass NEW_PASSWORD_FOR_PRIVATE_KEY \ `
    <br/>`-destkeystore polling.jks -srckeystore polling.p12 -srcstoretype PKCS12 \ `
    <br/>`-srcstorepass PASS_FROM_PREVIOUS_STEP -alias polling`  
1. Edit the configuration file to enable ssl, point the server to the keystore and specify the passwords used.
1. Run the server again and specify the configuration to be used `java -jar CollaboratorAuth.jar CollaboratorServer.properties`




## Recommended: Secure the *actual* Collaborator Server

To prevent polling of the Collaborator Server without the usage of Collaborator Auth, 
the Burp Collaborators polling location must be restricted. 

This may be done using your firewall, or by modifying the listening interface for polling events.

##### Option 1 - Always require usage of Collaborator Auth.
Should you wish to force users of your Burp Collaborator instance to authenticate regardless of their network, 
Burp Collaborator can be configured to listen to polling events only on the local machine (i.e. from Collaborator Auth).

This can be done by changing Burp Collaborator's listening address for polling events to the loopback interface (127.0.0.1) or 
using something like iptables to drop incoming requests.

SHAPSHOT OF COLLABORATOR CONFIG


##### Option 2 - Only require usage of Collaborator Auth on external networks.  
To allow Burp Collaborator to be used as normal when on the same network as the server, but require Collaborator Auth
to be used when on an external network, Burp Collaborator can be configured to listen to polling events from
internal addresses.

This can be done by changing Burp Collaborator's listening address to polling events to the server's internal address 
(192.168.x.x, 10.x.x.x, etc.). 

To ensure external polling events are not processed by Burp Collaborator, the polling port should be blocked on the
internet facing firewall. Alternatively, use iptables to drop incoming traffic from external networks.