package com.example.demo;

import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.X509TrustManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.ssl.SSLContexts;

public class Tls {

    static class TrustAll implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        // ruleid: shyena.java.insecure-tls
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class Pinned implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        // ok: shyena.java.insecure-tls
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            delegate().checkServerTrusted(chain, authType);
        }

        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        X509TrustManager delegate() { return null; }
    }

    void client() throws Exception {
        // ruleid: shyena.java.insecure-tls
        SSLContexts.custom().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build();
        // ruleid: shyena.java.insecure-tls
        Object v = NoopHostnameVerifier.INSTANCE;
        // ruleid: shyena.java.insecure-tls
        HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);
    }
}
