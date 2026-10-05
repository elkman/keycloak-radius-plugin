package com.github.vzakharchenko.radius.radius.server;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Message-Authenticator (RADIUS attribute 80) handling according to
 * RFC 2869 section 5.14 and RFC 3579 section 3.2.
 * <p>
 * Required by clients that mitigate BlastRADIUS (CVE-2024-3596), e.g. MikroTik
 * RouterOS with "require-message-auth=yes-for-request-resp".
 */
public final class MessageAuthenticator {

    public static final int ATTRIBUTE_TYPE = 80;

    public static final int ACCESS_REQUEST = 1;
    public static final int ACCESS_ACCEPT = 2;
    public static final int ACCESS_REJECT = 3;
    public static final int ACCESS_CHALLENGE = 11;

    private static final int HEADER_LENGTH = 20;
    private static final int AUTHENTICATOR_OFFSET = 4;
    private static final int AUTHENTICATOR_LENGTH = 16;
    private static final int ATTRIBUTE_LENGTH = 2 + AUTHENTICATOR_LENGTH;
    private static final int MAX_PACKET_LENGTH = 4096;
    private static final int BYTE_MASK = 0xff;
    private static final int BYTE_SHIFT = 8;

    public enum Result {
        VALID, MISSING, INVALID, MALFORMED
    }

    private MessageAuthenticator() {
    }

    public static boolean isAccessResponse(int code) {
        return code == ACCESS_ACCEPT || code == ACCESS_REJECT || code == ACCESS_CHALLENGE;
    }

    /**
     * Verifies the Message-Authenticator of an Access-Request.
     */
    public static Result verifyRequest(byte[] packet, String secret) {
        int length = packetLength(packet);
        if (length < 0) {
            return Result.MALFORMED;
        }
        int offset = findAttribute(packet, length);
        if (offset == -1) {
            return Result.MISSING;
        }
        if (offset < 0) {
            return offset == -2 ? Result.INVALID : Result.MALFORMED;
        }
        byte[] received = Arrays.copyOfRange(packet, offset + 2, offset + ATTRIBUTE_LENGTH);
        byte[] copy = Arrays.copyOf(packet, length);
        Arrays.fill(copy, offset + 2, offset + ATTRIBUTE_LENGTH, (byte) 0);
        return MessageDigest.isEqual(received, hmacMd5(secret, copy)) ?
                Result.VALID : Result.INVALID;
    }

    /**
     * Adds a Message-Authenticator as first attribute to an encoded Access-Accept,
     * Access-Reject or Access-Challenge and recalculates the Response Authenticator.
     * An existing Message-Authenticator is replaced.
     *
     * @return the signed packet, or the unchanged packet if it is not an Access response
     */
    public static byte[] signResponse(byte[] packet, byte[] requestAuthenticator,
                                      String secret) {
        int length = packetLength(packet);
        if (length < 0 || !isAccessResponse(packet[0] & BYTE_MASK)) {
            return packet;
        }
        byte[] signed = withEmptyMessageAuthenticator(packet, length, requestAuthenticator);
        System.arraycopy(hmacMd5(secret, signed), 0, signed, HEADER_LENGTH + 2,
                AUTHENTICATOR_LENGTH);
        System.arraycopy(responseAuthenticator(signed, secret), 0, signed,
                AUTHENTICATOR_OFFSET, AUTHENTICATOR_LENGTH);
        return signed;
    }

    /**
     * Rebuilds the packet with the Request Authenticator in the header and a zeroed
     * Message-Authenticator as first attribute.
     */
    private static byte[] withEmptyMessageAuthenticator(byte[] packet, int length,
                                                        byte[] requestAuthenticator) {
        byte[] attributes = withoutMessageAuthenticator(packet, length);
        int newLength = HEADER_LENGTH + ATTRIBUTE_LENGTH + attributes.length;
        if (newLength > MAX_PACKET_LENGTH) {
            throw new IllegalStateException("RADIUS response too large for Message-Authenticator");
        }
        byte[] signed = new byte[newLength];
        signed[0] = packet[0];
        signed[1] = packet[1];
        writeLength(signed, newLength);
        System.arraycopy(requestAuthenticator, 0, signed, AUTHENTICATOR_OFFSET,
                AUTHENTICATOR_LENGTH);
        signed[HEADER_LENGTH] = (byte) ATTRIBUTE_TYPE;
        signed[HEADER_LENGTH + 1] = (byte) ATTRIBUTE_LENGTH;
        System.arraycopy(attributes, 0, signed, HEADER_LENGTH + ATTRIBUTE_LENGTH,
                attributes.length);
        return signed;
    }

    /**
     * @return the declared packet length, or -1 if the packet is malformed
     */
    private static int packetLength(byte[] packet) {
        if (packet == null || packet.length < HEADER_LENGTH) {
            return -1;
        }
        int length = ((packet[2] & BYTE_MASK) << BYTE_SHIFT) | (packet[3] & BYTE_MASK);
        if (length < HEADER_LENGTH || length > packet.length || length > MAX_PACKET_LENGTH) {
            return -1;
        }
        return walkAttributes(packet, length) ? length : -1;
    }

    private static boolean walkAttributes(byte[] packet, int length) {
        int pos = HEADER_LENGTH;
        while (pos < length) {
            if (pos + 2 > length) {
                return false;
            }
            int attributeLength = packet[pos + 1] & BYTE_MASK;
            if (attributeLength < 2 || pos + attributeLength > length) {
                return false;
            }
            pos += attributeLength;
        }
        return true;
    }

    /**
     * @return offset of the Message-Authenticator attribute, -1 if missing,
     * -2 if present more than once, -3 if it has a wrong length
     */
    private static int findAttribute(byte[] packet, int length) {
        int found = -1;
        for (int pos = HEADER_LENGTH; pos < length; pos += packet[pos + 1] & BYTE_MASK) {
            if ((packet[pos] & BYTE_MASK) != ATTRIBUTE_TYPE) {
                continue;
            }
            if ((packet[pos + 1] & BYTE_MASK) != ATTRIBUTE_LENGTH) {
                return -3;
            }
            if (found != -1) {
                return -2;
            }
            found = pos;
        }
        return found;
    }

    private static byte[] withoutMessageAuthenticator(byte[] packet, int length) {
        ByteArrayOutputStream attributes = new ByteArrayOutputStream(length);
        int pos = HEADER_LENGTH;
        while (pos < length) {
            int attributeLength = packet[pos + 1] & BYTE_MASK;
            if ((packet[pos] & BYTE_MASK) != ATTRIBUTE_TYPE) {
                attributes.write(packet, pos, attributeLength);
            }
            pos += attributeLength;
        }
        return attributes.toByteArray();
    }

    private static void writeLength(byte[] packet, int length) {
        packet[2] = (byte) (length >> BYTE_SHIFT);
        packet[3] = (byte) length;
    }

    private static byte[] hmacMd5(String secret, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacMD5"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] responseAuthenticator(byte[] packet, String secret) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(packet);
            md5.update(secret.getBytes(StandardCharsets.UTF_8));
            return md5.digest();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
