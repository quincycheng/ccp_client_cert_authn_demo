# Client Cert Authentication to CyberArk Central Credential Provider 

This repo demostrates how to authenticate to CyberArk Central Credential Provider (CCP) with client certificate
Please note that there are many ways to do so, and the content here is for reference only

## Demo 1: Script

### Update truststore & trust CCP Server Cert (optional)

The following steps are required only if CCP web server SSL cert is self-signed, or issued by untrusted CA by the client machine

In this example, `ca.pem` is the certificate of internal CA that issues CCP web server SSL cert

```
sudo cp ca.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
sudo update-ca-trust extract
```

### Fetch script using curl
- `ca.pem` is the certificate of internal CA that issues CCP web server SSL cert
- `01-quincy.pem` is the client cert
- `01-quincy.key` is the client private key

```
curl --cacert ./ca.pem --cert ./01-quincy.pem --key ./01-quincy.key --silent \
 "https://<CCP FQDN>/AIMWebService/api/Accounts?AppID=<appid>&Safe=<safe name>&Object=<account name>" \
 | jq .
```

Sample result:

```
{
  "Content": "<secret value>",
  "PolicyID": "MySQL",
  "CreationMethod": "PVWA",
  "Folder": "Root",
  "Address": "database.pov.example.com",
  "Name": "Database-MySQL-database.pov.example.com-admin",
  "Safe": "POV",
  "DeviceType": "Database",
  "UserName": "admin",
  "PasswordChangeInProcess": "False"
}
```

## Demo 2: Java

### Update truststore & trust CCP Server Cert (optional, same as demo 1)

The following steps are required only if CCP web server SSL cert is self-signed, or issued by untrusted CA by the client machine

In this example, `ca.pem` is the certificate of internal CA that issues CCP web server SSL cert

```
sudo cp ca.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
sudo update-ca-trust extract
```

### Prepare Keystore
Keystore is used for storing client cert & private key for Java client app

- `01-quincy.pem` is the client cert
- `01-quincy.key` is the client private key
- `01-quincy.pfx` is the keystore in pkcs12
- `01-quincy` is the alias name in keystore

```
openssl pkcs12 -export \
 -inkey ../ccp/01-quincy.key -in ../ccp/01-quincy.pem -out 01-quincy.pfx -passout pass: -name 01-quincy
```

### Sample Code in Java

The following is a sample Java console app that fetches secret from CCP using client cert in keystore.
Please update the URL for CCP and path to keystore accordingly.

```
import java.io.*;
import java.net.*;

import java.net.http.*;
import java.security.*;
import javax.crypto.*;
import javax.net.ssl.*;

public class Demo {
    public static void main(String[] args) throws IOException, InterruptedException {

        // Update the CCP URL and path to Keystore accordingly
        String urlString = "https://<CCP FQDN>/AIMWebService/api/Accounts?AppID=<appid>&Safe=<safe name>&Object=<account name>";
        String pathKeyStore = "01-quincy.pfx";

        try {
            URL url = new URL(urlString);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(pathKeyStore), new char[0]);

            KeyManagerFactory keyManagerFactory = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, new char[0]);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            connection.setSSLSocketFactory(sslContext.getSocketFactory());

            connection.setRequestMethod("GET");
            connection.setDoInput(true);

            InputStream inputStream = connection.getInputStream();

            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }
            System.out.println(result.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
