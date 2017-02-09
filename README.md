# header-to-cert-valve

Parses a certificate in an HTTP request header and adds it to the request certificates.

## Usage

Add the HeaderToCert valve prior to the other valves (e.g. SSL Authentication value) that needs the certificate to be present on the request.

```xml
<Valve className="edu.umd.lib.tomcat.valves.HeaderToCert"
  headerName="ssl-client-cert"/>
```

The default header name is `ssl-client-cert`. The certificate must be in PEM format.

### Apache Configuration

The main use case of this valve is when Tomcat is running behind a reverse proxy server such as Apache. To configure Apache to pass the certificate to Tomcat via an HTTP request header, add the following to your Apache configuration:

```apacheconf
# turn on optional client certificate authentication
SSLVerifyClient optional

# set the path to your local CA certificate
# if a certificate is present in the request,
# it must be signed by this CA
SSLCACertificateFile /path/to/local/ca.crt
    
# initialize the SSL-Client-Cert header to a blank value
# to avoid HTTP header forgeries
RequestHeader set SSL-Client-Cert ""

# pass the client cert to the web application
RequestHeader set SSL-Client-Cert "%{SSL_CLIENT_CERT}s"
```

## License

See the [LICENSE](LICENSE.md) file for license rights and limitations (Apache 2.0).

