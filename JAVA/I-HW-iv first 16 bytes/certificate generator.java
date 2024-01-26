package IoanaVirna;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;

import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class CertificateGenerator {
	 public static PublicKey loadPublicKey(String filename) throws IOException, GeneralSecurityException {
	        Security.addProvider(new BouncyCastleProvider());
	        CertificateFactory factory = CertificateFactory.getInstance("X.509");
	        try (FileInputStream fis = new FileInputStream(filename)) {
	            X509Certificate certificate = (X509Certificate) factory.generateCertificate(fis);
	            return certificate.getPublicKey();
	        }
	    }

	    public X509Certificate generateCertificate(PublicKey publicKey, PrivateKey privateKey) throws Exception {
	    X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
	    X509Name dnName = new X509Name("CN=Test Certificate");

	    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
	    certGen.setSubjectDN(dnName);
	    certGen.setIssuerDN(dnName); // use the same
	    certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
	    certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
	    certGen.setPublicKey(publicKey);
	    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

	    return certGen.generate(privateKey, "BC"); // BC for BouncyCastle
	}
}
