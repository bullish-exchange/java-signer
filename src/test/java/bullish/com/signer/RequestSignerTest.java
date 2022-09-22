package bullish.com.signer;

import org.bitcoinj.core.Sha256Hash;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class RequestSignerTest {
    @Test
    public void testSigning() throws RuntimeException {
        RequestSigner requestSigner = new RequestSigner();
        String request = "{\"accountId\":\"222000000000000\",\"nonce\":1639393131,\"expirationTime\":1639393731,\"biometricsUsed\":false,\"sessionKey\":null}";
        byte[] digest = Sha256Hash.hash(request.getBytes());

        // The private key in this test is coded into the source.
        // In production settings please retrieve the private key in a more secure manner, such as through an environment variable
        String privateKeyString = "PVT_R1_2qZH5Pi9MJ7P3AB8Q4es6Mv56q54omL5xbpYZG4CC75GUPSEe";
        String publicKeyString = "PUB_R1_6ZNjnsuzXsdhgMzP2JkfWYtWVPfajpzvgA7xn8ytaTCEJoXkYk";

        RequestSigner.EosPrivateKey privateKey = requestSigner.decodePrivateKey(privateKeyString);
        RequestSigner.EosPublicKey publicKey = requestSigner.decodePublicKey(publicKeyString);

        String signature = requestSigner.signRequest(digest, privateKey, publicKey);
        assertTrue(requestSigner.verifySignature(digest, signature, publicKey));
    }
}
