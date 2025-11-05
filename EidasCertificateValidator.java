import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;


public final class EidasCertificateValidator {

	public static final String ID_ETSI_PSD2_QCSTATEMENT = "0.4.0.19495.2";
	public static final String ID_ETSI_PSD2_ROLE_PSP_AS = "0.4.0.19495.1.1";
	public static final String ID_ETSI_PSD2_ROLE_PSP_PI = "0.4.0.19495.1.2";
	public static final String ID_ETSI_PSD2_ROLE_PSP_AI = "0.4.0.19495.1.3";
	public static final String ID_ETSI_PSD2_ROLE_PSP_IC = "0.4.0.19495.1.4";

	public static List<String> eIDASRoles(X509Certificate cert) throws IOException {
		byte[] extVal = cert.getExtensionValue(Extension.qCStatements.getId());
		List<String> roles = null;
		if (null != extVal) {
			try (ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(extVal))) {
				DEROctetString oct = (DEROctetString) (stream.readObject());
				try (ASN1InputStream octstream = new ASN1InputStream(oct.getOctets())) {
					ASN1Sequence qcStatements = (ASN1Sequence) octstream.readObject();
					Enumeration<?> qcStatementEnum = qcStatements.getObjects();
					boolean qcCompliance = false;
					ASN1ObjectIdentifier statementId = null;
					while (qcStatementEnum.hasMoreElements()) {
						QCStatement qcStatement = QCStatement.getInstance(qcStatementEnum.nextElement());
						statementId = qcStatement.getStatementId();
						if (QCStatement.id_etsi_qcs_QcCompliance.equals(statementId)) {
							qcCompliance = true;
						}
						ASN1ObjectIdentifier idEtsiQcs = new ASN1ObjectIdentifier(ID_ETSI_PSD2_QCSTATEMENT);
						if (idEtsiQcs.equals(statementId)) {
							roles = extractQcRoles(qcStatement);
						}

					}
				}
			}
		}
		return roles;
	}

	/**
	 * @param roles
	 * @param qcStatement
	 * @return
	 * @throws IOException
	 */
	private static List<String> extractQcRoles(QCStatement qcStatement) throws IOException {
		List<String> rolesLocVar=new ArrayList<>();
		DEROctetString oct1 = new DEROctetString(qcStatement.getStatementInfo());
		try (ASN1InputStream octstreamasn = new ASN1InputStream(oct1.getOctets())) {
			ASN1Sequence qcS = (ASN1Sequence) octstreamasn.readObject();
			ASN1Encodable[] arrAsn = qcS.toArray();
			for (ASN1Encodable x : arrAsn) {
				ASN1Sequence asn1 = ASN1Sequence.getInstance(x);
				try (ASN1InputStream is = new ASN1InputStream(asn1.getEncoded())) {
					DLSequence sequence = (DLSequence) is.readObject();
					rolesLocVar = qcRoles(sequence);
					if (!rolesLocVar.isEmpty()) {
						break;
					}
				}
			}
		}
		return rolesLocVar;
	}

	public static List<String> qcRoles(DLSequence sequence) {
		ASN1Encodable[] arrE = sequence.toArray();
		List<String> list = new ArrayList<>();
		for (ASN1Encodable x : arrE) {
			DLSequence seq = (DLSequence) x;
			DERObjectIdentifier oid = (DERObjectIdentifier) seq.getObjectAt(0); // this
																				// object
																				// contains
																				// 1.3.6.etc...
			if (ID_ETSI_PSD2_ROLE_PSP_AS.equals(oid.toString())) {
				list.add("ASPSP");
			}

			if (ID_ETSI_PSD2_ROLE_PSP_PI.equals(oid.toString())) {
				list.add("PISP");
			}

			if (ID_ETSI_PSD2_ROLE_PSP_AI.equals(oid.toString())) {
				list.add("AISP");
			}

			if (ID_ETSI_PSD2_ROLE_PSP_IC.equals(oid.toString())) {
				list.add("CBPII");
			}
		}
		return list;
	}

	private EidasCertificateValidator(){}
}
