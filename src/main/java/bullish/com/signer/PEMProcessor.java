package bullish.com.signer;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.CharArrayReader;
import java.io.IOException;
import java.io.Reader;

/**
 * This is a wrapper class for PEMObjects that throws a {@link RuntimeException} if an invalid
 * PEMObject is passed into the constructor.  Once initialized the PEMProcessor can be used to
 * return the type, DER format, or algorithm used to create the PEMObject.
 */
public class PEMProcessor {

    private static final int PRIVATE_KEY_START_INDEX = 2;
    private static final String DER_TO_PEM_CONVERSION = "Error converting DER encoded key to PEM format!";
    private static final String ERROR_READING_PEM_OBJECT = "Error reading PEM object!";
    private static final String ERROR_PARSING_PEM_OBJECT = "Error parsing PEM object!";
    private static final String KEY_DATA_NOT_FOUND = "Key data not found in PEM object!";
    private static final String INVALID_PEM_OBJECT = "Cannot read PEM object!";

    private final PemObject pemObject;
    private final String pemObjectString;

    /**
     * Initialize PEMProcessor with PEM content in String format.
     *
     * @param pemObject - input PEM content in String format.
     * @throws RuntimeException When failing to read pem data from the input.
     */
    public PEMProcessor(String pemObject) throws RuntimeException {
        this.pemObjectString = pemObject;
        try (Reader reader = new CharArrayReader(this.pemObjectString.toCharArray());
             PemReader pemReader = new PemReader(reader)) {
            this.pemObject = pemReader.readPemObject();
            if (this.pemObject == null) {
                throw new RuntimeException(INVALID_PEM_OBJECT);
            }

        } catch (Exception e) {
            throw new RuntimeException(ERROR_PARSING_PEM_OBJECT, e);
        }

    }

    /**
     * Gets the PEM Object key type (i.e. PRIVATE KEY, PUBLIC KEY).
     *
     * @return key type as string
     */
    public String getType() {
        return pemObject.getType();
    }

    /**
     * Gets the DER encoded format of the key from its PEM format.
     *
     * @return DER format of key as string
     */

    public String getDERFormat() {
        return Hex.toHexString(pemObject.getContent());
    }

    public byte[] getKeyData() throws RuntimeException {

        Object pemObjectParsed = parsePEMObject();

        if (pemObjectParsed instanceof SubjectPublicKeyInfo) {
            return ((SubjectPublicKeyInfo) pemObjectParsed).getPublicKeyData().getBytes();
        } else if (pemObjectParsed instanceof PEMKeyPair) {

            DLSequence sequence;
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(
                    Hex.decode(this.getDERFormat()))) {
                sequence = (DLSequence) asn1InputStream.readObject();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            for (Object obj : sequence) {
                if (obj instanceof DEROctetString) {
                    byte[] key;
                    try {
                        key = ((DEROctetString) obj).getEncoded();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    return Arrays.copyOfRange(key, PRIVATE_KEY_START_INDEX, key.length);
                }
            }
            throw new RuntimeException(KEY_DATA_NOT_FOUND);

        } else {
            throw new RuntimeException(DER_TO_PEM_CONVERSION);
        }
    }

    private Object parsePEMObject() throws RuntimeException {
        try (Reader reader = new CharArrayReader(this.pemObjectString.toCharArray());
             PEMParser pemParser = new PEMParser(reader)) {
            return pemParser.readObject();
        } catch (IOException e) {
            throw new RuntimeException(ERROR_READING_PEM_OBJECT, e);
        }
    }
}
