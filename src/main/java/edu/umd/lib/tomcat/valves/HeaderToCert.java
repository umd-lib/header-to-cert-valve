package edu.umd.lib.tomcat.valves;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.Globals;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Apache Tomcat Valve that checks for the presence of a PEM-formatted X.509 certificate in an HTTP request header. If
 * it finds and successfully parses such a certificate, it adds the certificate to the request's lists of client
 * certificates.
 * 
 * The default HTTP header to check is "ssl-client-cert". This can be changed by setting the "headerName" on the Valve
 * element configuration in the webapps context.xml.
 * 
 * @author peichman
 */
public class HeaderToCert extends ValveBase implements Lifecycle {
  public static final String DEFAULT_HEADER_NAME = "ssl-client-cert";

  protected static final String info = "edu.umd.lib.tomcat.valves.HeaderToCert/1.0.0";

  private static final Log log = LogFactory.getLog(HeaderToCert.class);

  private String headerName;

  private CertificateFactory cf;

  public HeaderToCert() {
    super(true);
    headerName = DEFAULT_HEADER_NAME;
  }

  public void setHeaderName(String headerName) {
    log.debug("Setting header name to " + headerName);
    this.headerName = headerName;
  }

  @Override
  public void initInternal() throws LifecycleException {
    try {
      cf = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      e.printStackTrace();
      log.error("Unable to initialize X.509 certificate factory");
    }
  }

  @Override
  public void invoke(Request request, Response response) throws IOException, ServletException {

    HttpServletRequest httpRequest = request.getRequest();
    String pemCert = httpRequest.getHeader(headerName);
    if (pemCert != null && !pemCert.isEmpty() && !pemCert.equals("(null)")) {
      pemCert = pemCert.replaceAll(" ", "\n").replaceAll("\nCERTIFICATE", " CERTIFICATE");
      log.info("Client cert:\n" + pemCert);

      ByteArrayInputStream in = new ByteArrayInputStream(pemCert.getBytes());

      if (cf != null) {
        try {
          X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
          X509Certificate[] certs = (X509Certificate[]) request.getAttribute(Globals.CERTIFICATES_ATTR);
          if (certs == null) {
            request.setAttribute(Globals.CERTIFICATES_ATTR, new X509Certificate[] { cert });
          } else {
            List<X509Certificate> certList = new ArrayList<X509Certificate>(Arrays.asList(certs));
            certList.add(cert);
            request.setAttribute(Globals.CERTIFICATES_ATTR, certList.toArray());
          }

        } catch (CertificateException e) {
          e.printStackTrace();
          log.error("Unable to parse value of header " + headerName + " as an X.509 certificate");
        }
      }
    } else {
      log.info("No client cert found in header " + headerName);
    }

    getNext().invoke(request, response);
  }
}