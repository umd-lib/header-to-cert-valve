# header-to-cert-valve

Parses a certificate in an HTTP request header and adds it to the request certificates.

## Usage

```xml
<Valve className="edu.umd.lib.tomcat.valves"
  headerName="ssl-client-cert"/>
```

The default header name is `ssl-client-cert`. The certificate must be in PEM format.
