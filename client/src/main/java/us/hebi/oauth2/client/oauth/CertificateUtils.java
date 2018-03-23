package us.hebi.oauth2.client.oauth;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;

/**
 * Helper class to get Java to accept our firmware server certificate.
 * Let's encrypt certificates are not yet included by default. These helpers
 * let us add the root certificate to the default certificates, or alternatively
 * disable checks entirely and allow even self-signed certificates.
 * <p>
 * Implementation based on https://stackoverflow.com/a/34111150/3574093
 * and a few other sources.
 *
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 10 Jun 2016
 */
final class CertificateUtils {

    private CertificateUtils() {
    }

    static SSLContext getContextWithLetsEncrypt() {
        return letsEncryptTLSContext.get();
    }

    static SSLContext getContextWithoutChecks() {
        return disabledTLSContext.get();
    }

    // thread-safe singleton provider w/ lazy initialization
    private static final Supplier<SSLContext> disabledTLSContext = Suppliers.memoize(
            new Supplier<SSLContext>() {
                @Override
                public SSLContext get() {
                    try {
                        return createContextWithoutChecks();
                    } catch (Exception e) {
                        throw new AssertionError();
                    }
                }
            });

    private static final Supplier<SSLContext> letsEncryptTLSContext = Suppliers.memoize(
            new Supplier<SSLContext>() {
                @Override
                public SSLContext get() {
                    try {
                        return createContextWithLetsEncryptCA();
                    } catch (Exception e) {
                        throw new AssertionError();
                    }
                }
            });


    private static SSLContext createContextWithoutChecks() throws KeyManagementException, NoSuchAlgorithmException {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, null);
        return sslContext;
    }

    private static void printTrustedCerts(KeyStore keyStore) throws KeyStoreException, InvalidAlgorithmParameterException {
        System.out.println("Truststore now trusting: ");
        PKIXParameters params = new PKIXParameters(keyStore);
        params.getTrustAnchors().stream()
                .map(TrustAnchor::getTrustedCert)
                .map(X509Certificate::getSubjectDN)
                .forEach(System.out::println);
        System.out.println();
    }

    private static SSLContext createContextWithLetsEncryptCA() throws NoSuchAlgorithmException, KeyManagementException, CertificateException, KeyStoreException, IOException, InvalidAlgorithmParameterException {
        // Add custom certificate
        X509Certificate cert = getDSTRootCAX3();
        KeyStore keyStore = getDefaultJreKeystore();
        keyStore.setCertificateEntry(cert.getSubjectX500Principal().getName(), cert);

        // Create custom context
        String algorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
        tmf.init(keyStore);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        return sslContext;
    }

    private static KeyStore getDefaultJreKeystore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        Path ksPath = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
        keyStore.load(Files.newInputStream(ksPath), "changeit".toCharArray()); // "changeit" is default password for default keystore
        return keyStore;
    }

    /**
     * @return root certificate for Let's Encrypt sites
     */
    private static X509Certificate getDSTRootCAX3() throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(DSTRootCAX3.getBytes()));
    }

    // Valid from 30. Sept 2000 until 30. Sept 2021
    private static final String DSTRootCAX3 = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\n" +
            "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n" +
            "DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\n" +
            "PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\n" +
            "Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
            "AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\n" +
            "rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\n" +
            "OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\n" +
            "xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\n" +
            "7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\n" +
            "aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n" +
            "HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\n" +
            "SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\n" +
            "ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\n" +
            "AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\n" +
            "R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\n" +
            "JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\n" +
            "Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n" +
            "-----END CERTIFICATE-----";

}
