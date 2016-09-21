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
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 *
 * @author peichman
 */

public class HeaderToCert extends ValveBase implements Lifecycle {

  protected static final String info = "edu.umd.lib.tomcat.valves.HeaderToCert/1.0.0";

  private static final Log log = LogFactory.getLog(HeaderToCert.class);

  @Override
  public void invoke(Request request, Response response) throws IOException, ServletException {

    String certHeader = "ssl_client_cert";

    HttpServletRequest httpRequest = request.getRequest();
    String pemCert = httpRequest.getHeader(certHeader);
    if (pemCert != null && !pemCert.isEmpty() && !pemCert.equals("(null)")) {
      pemCert = pemCert.replaceAll(" ", "\n").replaceAll("\nCERTIFICATE", " CERTIFICATE");
      log.info("Client cert:\n" + pemCert);

      ByteArrayInputStream in = new ByteArrayInputStream(pemCert.getBytes());
      CertificateFactory cf = null;
      try {
        cf = CertificateFactory.getInstance("X.509");
      } catch (CertificateException e) {
        e.printStackTrace();
        log.error("Unable to initialize X.509 certificate factory");
      }

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
          log.error("Unable to parse value of " + certHeader + " as an X.509 certificate");
        }
      }
    } else {
      log.info("No client cert found in " + certHeader);
    }

    getNext().invoke(request, response);
  }
}