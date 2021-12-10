package bullish.com.signer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class RequestSignerTest {
    @Test
    public void testSigning() throws RuntimeException {
        RequestSigner requestSigner = new RequestSigner();
        byte[] payload = "bass".getBytes();

        // The private key in this test is coded into the source.
        // In production settings please retrieve the private key in a more secure manner, such as through an environment variable
        String privateKeyString = "PVT_R1_2qZH5Pi9MJ7P3AB8Q4es6Mv56q54omL5xbpYZG4CC75GUPSEe";
        String publicKeyString = "PUB_R1_6ZNjnsuzXsdhgMzP2JkfWYtWVPfajpzvgA7xn8ytaTCEJoXkYk";

        RequestSigner.EosPrivateKey privateKey = requestSigner.decodePrivateKey(privateKeyString);
        RequestSigner.EosPublicKey publicKey = requestSigner.decodePublicKey(publicKeyString);

        String signature = requestSigner.signRequest(payload, privateKey, publicKey);
        assertTrue(requestSigner.verifySignature(payload, signature, publicKey));
    }
}
