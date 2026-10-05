package com.github.vzakharchenko.radius.radius.server;

import org.testng.annotations.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class MessageAuthenticatorTest {

    private static final String SECRET = "testing123";
    private static final byte[] REQUEST_AUTH = bytes(16, 0x11);

    private static byte[] bytes(int length, int value) {
        byte[] b = new byte[length];
        Arrays.fill(b, (byte) value);
        return b;
    }

    private static byte[] packet(int code, byte[] authenticator, byte[]... attributes) {
        int length = 20;
        for (byte[] a : attributes) {
            length += a.length;
        }
        byte[] p = new byte[length];
        p[0] = (byte) code;
        p[1] = 42;
        p[2] = (byte) (length >> 8);
        p[3] = (byte) length;
        System.arraycopy(authenticator, 0, p, 4, 16);
        int pos = 20;
        for (byte[] a : attributes) {
            System.arraycopy(a, 0, p, pos, a.length);
            pos += a.length;
        }
        return p;
    }

    private static byte[] attribute(int type, byte[] value) {
        byte[] a = new byte[value.length + 2];
        a[0] = (byte) type;
        a[1] = (byte) a.length;
        System.arraycopy(value, 0, a, 2, value.length);
        return a;
    }

    private static byte[] userName() {
        return attribute(1, "alice".getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] hmac(byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacMD5"));
        return mac.doFinal(data);
    }

    /**
     * Signs an Access-Request the way a RADIUS client does (RFC 3579 3.2).
     */
    private static byte[] signedRequest(byte[]... attributes) throws Exception {
        byte[][] all = Arrays.copyOf(attributes, attributes.length + 1);
        all[attributes.length] = attribute(80, new byte[16]);
        byte[] p = packet(1, REQUEST_AUTH, all);
        System.arraycopy(hmac(p), 0, p, p.length - 16, 16);
        return p;
    }

    @Test
    public void testValidRequest() throws Exception {
        assertEquals(MessageAuthenticator.verifyRequest(signedRequest(userName()), SECRET),
                MessageAuthenticator.Result.VALID);
    }

    @Test
    public void testRequestWithWrongSecret() throws Exception {
        assertEquals(MessageAuthenticator.verifyRequest(signedRequest(userName()), "other"),
                MessageAuthenticator.Result.INVALID);
    }

    @Test
    public void testTamperedRequest() throws Exception {
        byte[] p = signedRequest(userName());
        p[22] = 'b';
        assertEquals(MessageAuthenticator.verifyRequest(p, SECRET),
                MessageAuthenticator.Result.INVALID);
    }

    @Test
    public void testRequestWithoutMessageAuthenticator() {
        byte[] p = packet(1, REQUEST_AUTH, userName());
        assertEquals(MessageAuthenticator.verifyRequest(p, SECRET),
                MessageAuthenticator.Result.MISSING);
    }

    @Test
    public void testRequestWithTwoMessageAuthenticators() throws Exception {
        byte[] p = signedRequest(userName(), attribute(80, new byte[16]));
        assertEquals(MessageAuthenticator.verifyRequest(p, SECRET),
                MessageAuthenticator.Result.INVALID);
    }

    @Test
    public void testMalformedRequests() {
        assertEquals(MessageAuthenticator.verifyRequest(new byte[5], SECRET),
                MessageAuthenticator.Result.MALFORMED);
        assertEquals(MessageAuthenticator.verifyRequest(null, SECRET),
                MessageAuthenticator.Result.MALFORMED);
        byte[] wrongLength = packet(1, REQUEST_AUTH, attribute(80, new byte[4]));
        assertEquals(MessageAuthenticator.verifyRequest(wrongLength, SECRET),
                MessageAuthenticator.Result.MALFORMED);
        byte[] truncated = packet(1, REQUEST_AUTH, userName());
        truncated[21] = 50;
        assertEquals(MessageAuthenticator.verifyRequest(truncated, SECRET),
                MessageAuthenticator.Result.MALFORMED);
        byte[] zeroLength = packet(1, REQUEST_AUTH, userName());
        zeroLength[21] = 0;
        assertEquals(MessageAuthenticator.verifyRequest(zeroLength, SECRET),
                MessageAuthenticator.Result.MALFORMED);
        byte[] badHeader = packet(1, REQUEST_AUTH, userName());
        badHeader[3] = 10;
        assertEquals(MessageAuthenticator.verifyRequest(badHeader, SECRET),
                MessageAuthenticator.Result.MALFORMED);
    }

    @Test
    public void testSignResponse() throws Exception {
        byte[] response = packet(2, bytes(16, 0x55), userName());
        byte[] signed = MessageAuthenticator.signResponse(response, REQUEST_AUTH, SECRET);

        assertEquals(signed.length, response.length + 18);
        assertEquals(((signed[2] & 0xff) << 8) | (signed[3] & 0xff), signed.length);
        // Message-Authenticator is the first attribute, original attributes follow
        assertEquals(signed[20], 80);
        assertEquals(signed[21], 18);
        assertEquals(Arrays.copyOfRange(signed, 38, signed.length), userName());

        // independent check of the Message-Authenticator
        byte[] check = Arrays.copyOf(signed, signed.length);
        System.arraycopy(REQUEST_AUTH, 0, check, 4, 16);
        Arrays.fill(check, 22, 38, (byte) 0);
        assertEquals(Arrays.copyOfRange(signed, 22, 38), hmac(check));

        // independent check of the Response Authenticator (RFC 2865 section 3)
        byte[] withRequestAuth = Arrays.copyOf(signed, signed.length);
        System.arraycopy(REQUEST_AUTH, 0, withRequestAuth, 4, 16);
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(withRequestAuth);
        md5.update(SECRET.getBytes(StandardCharsets.UTF_8));
        assertEquals(Arrays.copyOfRange(signed, 4, 20), md5.digest());
    }

    @Test
    public void testSignResponseReplacesExistingMessageAuthenticator() {
        byte[] response = packet(3, bytes(16, 0x55), userName(),
                attribute(80, bytes(16, 0x7f)));
        byte[] signed = MessageAuthenticator.signResponse(response, REQUEST_AUTH, SECRET);
        assertEquals(signed.length, response.length);
        int count = 0;
        for (int pos = 20; pos < signed.length; pos += signed[pos + 1]) {
            if (signed[pos] == 80) {
                count++;
            }
        }
        assertEquals(count, 1);
    }

    @Test
    public void testSignChallenge() {
        byte[] response = packet(11, bytes(16, 0x55));
        byte[] signed = MessageAuthenticator.signResponse(response, REQUEST_AUTH, SECRET);
        assertEquals(signed.length, 38);
    }

    @Test
    public void testNonAccessPacketsAreUnchanged() {
        byte[] accountingResponse = packet(5, bytes(16, 0x55));
        assertSame(MessageAuthenticator.signResponse(accountingResponse, REQUEST_AUTH, SECRET),
                accountingResponse);
        byte[] malformed = new byte[3];
        assertSame(MessageAuthenticator.signResponse(malformed, REQUEST_AUTH, SECRET),
                malformed);
    }

    @Test
    public void testResponseTooLarge() {
        byte[][] attributes = new byte[17][];
        Arrays.fill(attributes, attribute(26, new byte[238]));
        attributes[16] = attribute(26, new byte[228]);
        byte[] response = packet(2, bytes(16, 0x55), attributes);
        assertEquals(response.length, 4090);
        assertThrows(IllegalStateException.class,
                () -> MessageAuthenticator.signResponse(response, REQUEST_AUTH, SECRET));
    }

    @Test
    public void testIsAccessResponse() {
        assertTrue(MessageAuthenticator.isAccessResponse(2));
        assertTrue(MessageAuthenticator.isAccessResponse(3));
        assertTrue(MessageAuthenticator.isAccessResponse(11));
        assertTrue(!MessageAuthenticator.isAccessResponse(1));
        assertTrue(!MessageAuthenticator.isAccessResponse(5));
    }
}
