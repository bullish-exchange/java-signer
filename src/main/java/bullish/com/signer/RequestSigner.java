package bullish.com.signer;

import com.google.common.primitives.Bytes;
import org.bitcoinj.core.Base58;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointUtil;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static org.bitcoinj.core.Utils.bigIntegerToBytes;

public class RequestSigner {
    private static final ECDomainParameters CURVE_R1;
    private static final BigInteger HALF_CURVE_ORDER_R1;
    private static final ECDomainParameters ecParamsR1;
    private static final KeyFactory KEY_FACTORY;

    private static final byte UNCOMPRESSED_PUBLIC_KEY_BYTE_INDICATOR = 0x04;
    private static final byte COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_POSITIVE_Y = 0x02;
    private static final byte COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_NEGATIVE_Y = 0x03;
    private static final int CHECKSUM_LENGTH = 8;
    private static final int CHECKSUM_BYTES = 4;
    private static final int VALUE_TO_ADD_TO_SIGNATURE_HEADER = 31;
    private static final int EXPECTED_R_OR_S_LENGTH = 32;
    private static final int FIRST_TWO_BYTES_OF_KEY = 4;
    private static final int DATA_SEQUENCE_LENGTH_BYTE_POSITION = 2;

    private static final String SECP256R1 = "secp256r1";
    private static final X9ECParameters CURVE_PARAMS_R1 = CustomNamedCurves.getByName(SECP256R1);
    private static final String ECDSA = "ECDSA";
    private static final String R1_KEY_TYPE = "R1";
    private static final String PATTERN_STRING_EOS_PREFIX_SIG_R1 = "SIG_R1_";
    private static final String PATTERN_STRING_EOS_PREFIX_PUB_R1 = "PUB_R1_";
    private static final String PATTERN_STRING_PEM_PREFIX_PUBLIC_KEY_SECP256R1_COMPRESSED = "3039301306072a8648ce3d020106082a8648ce3d030107032200";
    private static final String PEM_HEADER_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    private static final String PEM_FOOTER_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    private static final String GENERIC_ERROR = "error";

    static {
        X9ECParameters paramsR1 = SECNamedCurves.getByName(SECP256R1);
        ecParamsR1 = new ECDomainParameters(paramsR1.getCurve(), paramsR1.getG(), paramsR1.getN(), paramsR1.getH());

        FixedPointUtil.precompute(CURVE_PARAMS_R1.getG());
        CURVE_R1 = new ECDomainParameters(
                CURVE_PARAMS_R1.getCurve(),
                CURVE_PARAMS_R1.getG(),
                CURVE_PARAMS_R1.getN(),
                CURVE_PARAMS_R1.getH());
        HALF_CURVE_ORDER_R1 = CURVE_PARAMS_R1.getN().shiftRight(1);
        KEY_FACTORY = getKeyFactory();
    }

    public boolean verifySignature(byte[] request, String sigBase58, EosPublicKey eosPublicKey) {
        try {
            String sig = sigBase58.substring(sigBase58.lastIndexOf("_") + 1);
            byte[] encodedSig = Base58.decode(sig);
            BigInteger r = new BigInteger(1, encodedSig, 1, 32);
            BigInteger s = new BigInteger(1, encodedSig, 33, 32);
            byte[] decoderData = R1_KEY_TYPE.getBytes();
            byte[] new_checksumData = new byte[65 + decoderData.length];
            System.arraycopy(encodedSig, 0, new_checksumData, 0, 65);
            System.arraycopy(decoderData, 0, new_checksumData, 65, decoderData.length);
            byte[] new_checksum = calculateChecksum(new_checksumData);

            //verify the checksum, which is 4 bytes
            if (!(new_checksum[0] == encodedSig[65] || new_checksum[1] == encodedSig[66]
                    || new_checksum[2] == encodedSig[67] || new_checksum[3] == encodedSig[68])) return false;

            ECDSASigner signer = new ECDSASigner();
            X9ECParameters parameters = SECNamedCurves.getByName(SECP256R1);
            final ECPoint point = ((BCECPublicKey) eosPublicKey.getPublicKey()).getQ();
            final ECDomainParameters ecDomainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());
            final ECPublicKeyParameters cipherParameters = new ECPublicKeyParameters(point, ecDomainParameters);

            signer.init(false, cipherParameters);

            return signer.verifySignature(request, r, s);
        } catch (Exception e) {
            return false;
        }
    }

    public String signRequest(byte[] request, EosPrivateKey eosPrivateKey, EosPublicKey eosPublicKey) throws RuntimeException {
        try {
            BigInteger d = ((BCECPrivateKey) eosPrivateKey.getPrivateKey()).getD();
            X9ECParameters parameters = SECNamedCurves.getByName(SECP256R1);
            ECDomainParameters ecDomainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());
            ECPrivateKeyParameters cipherParameters = new ECPrivateKeyParameters(d, ecDomainParameters);
            BigInteger[] rAndS;
            do {
                rAndS = generateSignature(request, cipherParameters);
            } while (!isCanonical(rAndS[0], rAndS[1]));

            return convertRawRandSofSignatureToEOSFormat(
                    rAndS[0].toString(),
                    rAndS[1].toString(),
                    request,
                    convertEOSPublicKeyToPEMFormat(eosPublicKey.getEncodedPublicKey()));

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private BigInteger[] generateSignature(byte[] payload, ECPrivateKeyParameters cipherParameters) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, cipherParameters);
        return signer.generateSignature(payload);
    }

    private boolean isCanonical(BigInteger r, BigInteger s) {
        byte[] sigData = new byte[69];
        sigData[0] = (byte) 31;
        System.arraycopy(bigIntegerToBytes(r, 32), 0, sigData, 1, 32);
        System.arraycopy(bigIntegerToBytes(s, 32), 0, sigData, 33, 32);
        return isCanonical(sigData);
    }

    private boolean isCanonical(byte[] signature) {
        return (signature[1] & Integer.valueOf(128).byteValue()) == Integer.valueOf(0).byteValue() &&
                (signature[1] != Integer.valueOf(0).byteValue() ||
                        (signature[2] & Integer.valueOf(128).byteValue()) != Integer.valueOf(0).byteValue()) &&
                (signature[33] & Integer.valueOf(128).byteValue()) == Integer.valueOf(0).byteValue() &&
                (signature[33] != Integer.valueOf(0).byteValue() ||
                        (signature[34] & Integer.valueOf(128).byteValue()) != Integer.valueOf(0).byteValue());
    }

    private ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(ecParamsR1.getCurve()));
        compEnc[0] = yBit ? COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_NEGATIVE_Y : COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_POSITIVE_Y;
        return ecParamsR1.getCurve().decodePoint(compEnc);
    }

    private byte[] recoverPublicKeyFromSignature(int recId, BigInteger r, BigInteger s, byte[] message) {
        // 1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
        // 1.1 Let x = r + jn

        BigInteger n; // Curve order.
        ECPoint g;
        ECCurve.Fp curve;

        n = ecParamsR1.getN();
        g = ecParamsR1.getG();
        curve = (ECCurve.Fp) ecParamsR1.getCurve();


        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));

        //   1.2. Convert the integer x to an octet string X of length mlen using the conversion routine
        //        specified in Section 2.3.7, where mlen = ceiling((log2 p)/8) or mlen equals ceiling(m/8).
        //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R using the
        //        conversion routine specified in Section 2.3.4. If this conversion routine outputs 'invalid', then
        //        do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed public key.
        BigInteger prime = curve.getQ();
        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
            return null;
        }
        // Compressed keys require you to know an extra bit of data about the y-coord as there are two possibilities.
        // So it's encoded in the recId.
        ECPoint R = decompressKey(x, (recId & 1) == 1);
        //   1.4. If nR != point at infinity, then do another iteration of Step 1 (callers responsibility).
        if (!R.multiply(n).isInfinity()) {
            return null;
        }
        //   1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
        BigInteger e = new BigInteger(1, message);
        //   1.6. For k from 1 to 2 do the following.   (loop is outside this function via iterating recId)
        //   1.6.1. Compute a candidate public key as:
        //               Q = mi(r) * (sR - eG)
        //
        // Where mi(x) is the modular multiplicative inverse. We transform this into the following:
        //               Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
        // Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n). In the above equation
        // ** is point multiplication and + is point addition (the EC group operator).
        //
        // We can find the additive inverse by subtracting e from zero then taking the mod. For example the additive
        // inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(g, eInvrInv, R, srInv);
        return q.getEncoded(true);
    }

    private int getRecoveryId(BigInteger r, BigInteger s, byte[] sha256HashMessage, byte[] publicKey) {
        for (int i = 0; i < 4; i++) {
            byte[] recoveredPublicKey = recoverPublicKeyFromSignature(i, r, s, sha256HashMessage);

            if (Arrays.equals(publicKey, recoveredPublicKey)) {
                return i;
            }
        }

        return -1;
    }

    private BigInteger checkAndHandleLowS(BigInteger s) {
        if (!isLowS(s)) {
            return CURVE_R1.getN().subtract(s);
        }
        return s;
    }

    private boolean isLowS(BigInteger s) {
        int compareResult = s.compareTo(HALF_CURVE_ORDER_R1);
        return compareResult == 0 || compareResult < 0;
    }

    private byte[] digestRIPEMD160(byte[] input) {
        RIPEMD160Digest digest = new RIPEMD160Digest();
        byte[] output = new byte[digest.getDigestSize()];
        digest.update(input, 0, input.length);
        digest.doFinal(output, 0);

        return output;
    }

    private byte[] addCheckSumToSignature(byte[] signature, byte[] keyTypeByteArray) {
        byte[] signatureWithKeyType = Bytes.concat(signature, keyTypeByteArray);
        byte[] signatureRipemd160 = digestRIPEMD160(signatureWithKeyType);
        byte[] checkSum = Arrays.copyOfRange(signatureRipemd160, 0, CHECKSUM_BYTES);
        return Bytes.concat(signature, checkSum);
    }

    private String convertRawRandSofSignatureToEOSFormat(String signatureR,
                                                                String signatureS,
                                                                byte[] signableTransaction,
                                                                String publicKeyPEM) {
        String eosFormattedSignature;

        try {
            PEMProcessor publicKey = new PEMProcessor(publicKeyPEM);
            byte[] keyData = publicKey.getKeyData();

            BigInteger r = new BigInteger(signatureR);
            BigInteger s = new BigInteger(signatureS);

            s = checkAndHandleLowS(s);

            /*
            Get recovery ID.  This is the index of the public key (0-3) that represents the
            expected public key used to sign the transaction.
             */
            int recoverId = getRecoveryId(r, s, signableTransaction, keyData);

            if (recoverId < 0) {
                throw new RuntimeException(GENERIC_ERROR);
            }

            //Add RecoveryID + 27 + 4 to create the header byte
            recoverId += VALUE_TO_ADD_TO_SIGNATURE_HEADER;
            byte headerByte = ((Integer) recoverId).byteValue();

            byte[] decodedSignature = Bytes
                    .concat(new byte[]{headerByte}, org.bitcoinj.core.Utils.bigIntegerToBytes(r, EXPECTED_R_OR_S_LENGTH), org.bitcoinj.core.Utils.bigIntegerToBytes(s, EXPECTED_R_OR_S_LENGTH));
            if (!isCanonical(decodedSignature)) {
                throw new RuntimeException(GENERIC_ERROR);
            }

            //Add checksum to signature
            byte[] signatureWithCheckSum;
            String signaturePrefix;

            signatureWithCheckSum = addCheckSumToSignature(decodedSignature, R1_KEY_TYPE.getBytes());
            signaturePrefix = PATTERN_STRING_EOS_PREFIX_SIG_R1;

            //Base58 encode signature and add pertinent EOS prefix
            eosFormattedSignature = signaturePrefix.concat(org.bitcoinj.core.Base58.encode(signatureWithCheckSum));

        } catch (Exception e) {
            throw new RuntimeException(GENERIC_ERROR, e);
        }

        return eosFormattedSignature;
    }

    private byte[] calculateChecksum(byte[] publicKey) {
        RIPEMD160Digest ripemd160Digest = new RIPEMD160Digest();
        ripemd160Digest.update(publicKey, 0, publicKey.length);
        byte[] actualChecksum = new byte[ripemd160Digest.getDigestSize()];
        ripemd160Digest.doFinal(actualChecksum, 0);
        return actualChecksum;
    }

    public EosPublicKey decodePublicKey(String eosAddress) throws RuntimeException {
        try {
            R1PublicKeyDecoder decoder = new R1PublicKeyDecoder();
            byte[] payload = Base58.decode(decoder.addressWithoutPrefix(eosAddress));
            String hex = Hex.toHexString(payload);
            hex = hex.substring(0, hex.length() - CHECKSUM_LENGTH);
            return decodePublicKey(decoder, Hex.decode(hex));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance(ECDSA, new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException(nsae);
        }
    }

    private EosPublicKey decodePublicKey(R1PublicKeyDecoder decoder, byte[] pointData) throws Exception {
        assert pointData != null && pointData.length == 33;
        ECPoint point = decoder.getCurveSpec().getCurve().decodePoint(pointData);
        java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(
                new java.security.spec.ECPoint(point.getXCoord().toBigInteger(), point.getYCoord().toBigInteger()),
                decoder.getECParameterSpec()
        );

        EosPublicKey publicKey = new EosPublicKey();
        publicKey.setEncodedPublicKey(encodePublicKey(pointData));
        publicKey.setPublicKey(KEY_FACTORY.generatePublic(keySpec));
        return publicKey;
    }

    private String encodePublicKey(byte[] data) {
        if (data.length == 0) {
            throw new RuntimeException(GENERIC_ERROR);
        }
        byte[] checkSum = extractCheckSumRIPEMD160(data, R1_KEY_TYPE.getBytes());
        String base58Key = Base58.encode(Bytes.concat(data, checkSum));
        return PATTERN_STRING_EOS_PREFIX_PUB_R1 + base58Key;
    }

    private byte[] extractCheckSumRIPEMD160(byte[] pemKey, byte[] keyTypeByteArray) {
        if (keyTypeByteArray != null) {
            pemKey = Bytes.concat(pemKey, keyTypeByteArray);
        }

        byte[] ripemd160Digest = digestRIPEMD160(pemKey);

        return Arrays.copyOfRange(ripemd160Digest, 0, CHECKSUM_BYTES);
    }

    public EosPrivateKey decodePrivateKey(String encodedPrivateKey) throws RuntimeException {
        try {
            R1PrivateKeyDecoder decoder = new R1PrivateKeyDecoder();
            byte[] payload = Base58.decode(decoder.addressWithoutPrefix(encodedPrivateKey));
            String hex = Hex.toHexString(payload);
            hex = hex.substring(0, hex.length() - CHECKSUM_LENGTH);
            hex = hex.substring(decoder.getWIFPrefixLength());

            java.security.spec.ECPrivateKeySpec keySpec = new java.security.spec.ECPrivateKeySpec(
                    new BigInteger(hex, 16),
                    decoder.getECParameterSpec()
            );

            EosPrivateKey privateKey = new EosPrivateKey();
            privateKey.setPrivateKey(KEY_FACTORY.generatePrivate(keySpec));
            return privateKey;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] compressPublickey(byte[] compressedPublicKey) {
        byte compressionPrefix;
        try {
            ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(SECP256R1);
            ECPoint ecPoint = parameterSpec.getCurve().decodePoint(compressedPublicKey);
            byte[] x = ecPoint.getXCoord().getEncoded();
            byte[] y = ecPoint.getYCoord().getEncoded();

            //Check whether y is negative(odd in field) or positive(even in field) and assign compressionPrefix
            BigInteger bigIntegerY = new BigInteger(Hex.toHexString(y), 16);
            BigInteger bigIntegerTwo = BigInteger.valueOf(2);
            BigInteger remainder = bigIntegerY.mod(bigIntegerTwo);

            if (remainder.equals(BigInteger.ZERO)) {
                compressionPrefix = COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_POSITIVE_Y;
            } else {
                compressionPrefix = COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_NEGATIVE_Y;
            }

            return Bytes.concat(new byte[]{compressionPrefix}, x);
        } catch (Exception e) {
            throw new RuntimeException(GENERIC_ERROR, e);
        }
    }

    private byte[] decodePublicKey(String strKey, String keyPrefix) throws RuntimeException {
        if (strKey.isEmpty()) {
            throw new RuntimeException("Input key to decode can't be empty.");
        }

        byte[] decodedKey;

        try {
            byte[] base58Decoded = org.bitcoinj.core.Base58.decode(strKey);
            byte[] firstCheckSum = Arrays.copyOfRange(base58Decoded, base58Decoded.length - CHECKSUM_BYTES, base58Decoded.length);
            decodedKey = Arrays.copyOfRange(base58Decoded, 0, base58Decoded.length - CHECKSUM_BYTES);

            if (invalidRipeMD160CheckSum(decodedKey, firstCheckSum, R1_KEY_TYPE.getBytes())) {
                throw new RuntimeException(GENERIC_ERROR);
            }

        } catch (Exception ex) {
            throw new RuntimeException(GENERIC_ERROR, ex);
        }

        return decodedKey;
    }

    private boolean invalidRipeMD160CheckSum(byte[] inputKey,
                                                    byte[] checkSumToValidate,
                                                    byte[] keyTypeByteArray) {
        if (inputKey.length == 0 || checkSumToValidate.length == 0) {
            throw new RuntimeException(GENERIC_ERROR);
        }

        byte[] keyWithType = Bytes.concat(inputKey, keyTypeByteArray);
        byte[] digestRIPEMD160 = digestRIPEMD160(keyWithType);
        byte[] checkSumFromInputKey = Arrays.copyOfRange(digestRIPEMD160, 0, CHECKSUM_BYTES);

        //This checksum returns whether the checksum comparison was invalid.
        return !Arrays.equals(checkSumToValidate, checkSumFromInputKey);
    }

    private String convertEOSPublicKeyToPEMFormat(String publicKeyEOS) {
        String pemFormattedPublickKey = publicKeyEOS;
        String keyPrefix;
        keyPrefix = PATTERN_STRING_EOS_PREFIX_PUB_R1;
        pemFormattedPublickKey = pemFormattedPublickKey
                .replace(PATTERN_STRING_EOS_PREFIX_PUB_R1, "");


        //Base58 decode the key
        byte[] base58DecodedPublicKey;
        try {
            base58DecodedPublicKey = decodePublicKey(pemFormattedPublickKey, keyPrefix);
        } catch (Exception e) {
            throw new RuntimeException(GENERIC_ERROR, e);
        }

        //Convert decoded array to string
        pemFormattedPublickKey = Hex.toHexString(base58DecodedPublicKey);

        /*
        Compress the public key if necessary.
        Compression is only necessary if the key has a value of 0x04 for the first byte, which
        indicates it is uncompressed.
         */
        if (base58DecodedPublicKey[0] == UNCOMPRESSED_PUBLIC_KEY_BYTE_INDICATOR) {
            try {
                pemFormattedPublickKey = Hex.toHexString(compressPublickey(Hex.decode(pemFormattedPublickKey)));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        pemFormattedPublickKey = PATTERN_STRING_PEM_PREFIX_PUBLIC_KEY_SECP256R1_COMPRESSED + pemFormattedPublickKey;

        /*
        Correct the sequence length value.  According to the ASN.1 specification.  For a DER encoded public key the second byte reflects the number of bytes following
        the second byte.  Here we take the length of the entire string, subtract 4 to remove the first two bytes, divide by 2 (i.e. two characters per byte) and replace
        the second byte in the string with the corrected length.
         */
        int i = (pemFormattedPublickKey.length() - FIRST_TWO_BYTES_OF_KEY) / 2;
        String correctedLength = Integer.toHexString(i);
        pemFormattedPublickKey =
                pemFormattedPublickKey.substring(0, DATA_SEQUENCE_LENGTH_BYTE_POSITION)
                        + correctedLength
                        + pemFormattedPublickKey.substring(FIRST_TWO_BYTES_OF_KEY);

        try {
            pemFormattedPublickKey = derToPEM(Hex.decode(pemFormattedPublickKey));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return pemFormattedPublickKey;
    }

    private String derToPEM(byte[] derEncodedByteArray) throws RuntimeException {
        StringBuilder pemForm = new StringBuilder();
        try {
            pemForm.append(PEM_HEADER_PUBLIC_KEY);
            pemForm.append("\n");
            //Base64 Encode DER Encoded Byte Array And Add to PEM Object
            String base64EncodedByteArray = new String(Base64.encode(derEncodedByteArray));
            pemForm.append(base64EncodedByteArray);
            pemForm.append("\n");
            //Build Footer
            pemForm.append(PEM_FOOTER_PUBLIC_KEY);
        } catch (Exception e) {
            throw new RuntimeException(GENERIC_ERROR, e);
        }

        return pemForm.toString();
    }

    static class R1PrivateKeyDecoder {
        java.security.spec.ECParameterSpec getECParameterSpec() {
            return EC5Util.convertSpec(EC5Util.convertCurve(getCurveSpec().getCurve(), getCurveSpec().getSeed()), this.getCurveSpec());
        }

        public ECNamedCurveParameterSpec getCurveSpec() {
            return ECNamedCurveTable.getParameterSpec(SECP256R1);
        }

        public String addressWithoutPrefix(String address) {
            return address.substring(7);
        }

        public int getWIFPrefixLength() {
            return 0;
        }
    }

    static class R1PublicKeyDecoder {
        java.security.spec.ECParameterSpec getECParameterSpec() {
            return EC5Util.convertSpec(EC5Util.convertCurve(getCurveSpec().getCurve(), getCurveSpec().getSeed()), this.getCurveSpec());
        }

        public ECNamedCurveParameterSpec getCurveSpec() {
            return ECNamedCurveTable.getParameterSpec(SECP256R1);
        }

        public String addressWithoutPrefix(String address) {
            return address.substring(7);
        }
    }

    static class EosPrivateKey {
        private PrivateKey privateKey;

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }
    }

    static class EosPublicKey {
        private String encodedPublicKey;
        private PublicKey publicKey;

        public void setEncodedPublicKey(String encodedPublicKey) {
            this.encodedPublicKey = encodedPublicKey;
        }

        public void setPublicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        public String getEncodedPublicKey() {
            return encodedPublicKey;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }
    }
}
