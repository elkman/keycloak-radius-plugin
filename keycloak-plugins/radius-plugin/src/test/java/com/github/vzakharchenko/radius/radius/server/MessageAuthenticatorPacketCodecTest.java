package com.github.vzakharchenko.radius.radius.server;

import com.github.vzakharchenko.radius.test.AbstractRadiusTest;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.socket.DatagramPacket;
import org.testng.annotations.Test;
import org.tinyradius.packet.AccessRequest;
import org.tinyradius.packet.PacketEncoder;
import org.tinyradius.packet.RadiusPacket;
import org.tinyradius.packet.RadiusPackets;
import org.tinyradius.server.ResponseCtx;
import org.tinyradius.server.SecretProvider;
import org.tinyradius.util.RadiusEndpoint;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.tinyradius.packet.PacketType.ACCESS_ACCEPT;
import static org.tinyradius.packet.PacketType.ACCOUNTING_RESPONSE;

public class MessageAuthenticatorPacketCodecTest extends AbstractRadiusTest {

    private static final String SECRET = "testing123";
    private static final InetSocketAddress CLIENT = new InetSocketAddress("127.0.0.10", 40000);
    private static final InetSocketAddress SERVER = new InetSocketAddress("127.0.0.1", 1812);
    private static final byte[] REQUEST_AUTH = new byte[16];

    static {
        Arrays.fill(REQUEST_AUTH, (byte) 0x22);
    }

    private static final InetSocketAddress NO_SECRET_CLIENT =
            new InetSocketAddress("127.0.0.11", 40000);

    private final SecretProvider secretProvider = address -> {
        if (CLIENT.equals(address)) {
            return SECRET;
        }
        return NO_SECRET_CLIENT.equals(address) ? "" : null;
    };

    private MessageAuthenticatorPacketCodec codec(boolean require) {
        return new MessageAuthenticatorPacketCodec(new PacketEncoder(realDictionary),
                secretProvider, require);
    }

    private static byte[] hmac(byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacMD5"));
        return mac.doFinal(data);
    }

    /**
     * Access-Request with User-Name "alice", a User-Password and optionally a
     * Message-Authenticator.
     */
    private static byte[] request(boolean withMessageAuthenticator) throws Exception {
        int length = 20 + 7 + 18 + (withMessageAuthenticator ? 18 : 0);
        byte[] p = new byte[length];
        p[0] = 1;
        p[1] = 7;
        p[3] = (byte) length;
        System.arraycopy(REQUEST_AUTH, 0, p, 4, 16);
        p[20] = 1;
        p[21] = 7;
        System.arraycopy("alice".getBytes(StandardCharsets.UTF_8), 0, p, 22, 5);
        p[27] = 2;
        p[28] = 18;
        Arrays.fill(p, 29, 45, (byte) 0x33);
        if (withMessageAuthenticator) {
            p[45] = 80;
            p[46] = 18;
            System.arraycopy(hmac(p), 0, p, 47, 16);
        }
        return p;
    }

    private static DatagramPacket datagram(byte[] data, InetSocketAddress sender) {
        return new DatagramPacket(Unpooled.wrappedBuffer(data), SERVER, sender);
    }

    @Test
    public void testDecodeValidRequest() throws Exception {
        assertNotNull(codec(true).decodePacket(datagram(request(true), CLIENT)));
    }

    @Test
    public void testDecodeTamperedRequest() throws Exception {
        byte[] p = request(true);
        p[22] = 'b';
        assertNull(codec(false).decodePacket(datagram(p, CLIENT)));
    }

    @Test
    public void testDecodeMissingMessageAuthenticator() throws Exception {
        assertNull(codec(true).decodePacket(datagram(request(false), CLIENT)));
        assertNotNull(codec(false).decodePacket(datagram(request(false), CLIENT)));
    }

    @Test
    public void testDecodeUnknownClient() throws Exception {
        InetSocketAddress unknown = new InetSocketAddress("127.0.0.99", 40000);
        assertNull(codec(true).decodePacket(datagram(request(true), unknown)));
    }

    @Test
    public void testDecodeClientWithEmptySecret() throws Exception {
        assertNull(codec(false).decodePacket(datagram(request(true), NO_SECRET_CLIENT)));
    }

    @Test
    public void testEncodeSignsAccessResponse() throws Exception {
        AccessRequest request = new AccessRequest(realDictionary, 7, REQUEST_AUTH);
        RadiusPacket response = RadiusPackets.create(realDictionary, ACCESS_ACCEPT, 7);
        ResponseCtx ctx = new ResponseCtx(request, new RadiusEndpoint(CLIENT, SECRET), response);

        DatagramPacket packet = codec(true).encodePacket(SERVER, ctx);
        byte[] signed = ByteBufUtil.getBytes(packet.content());
        packet.release();

        assertEquals(signed[20], 80);
        byte[] check = Arrays.copyOf(signed, signed.length);
        System.arraycopy(REQUEST_AUTH, 0, check, 4, 16);
        Arrays.fill(check, 22, 38, (byte) 0);
        assertEquals(Arrays.copyOfRange(signed, 22, 38), hmac(check));
    }

    @Test
    public void testEncodeAccountingResponseUnchanged() {
        RadiusPacket request = new AccessRequest(realDictionary, 7, REQUEST_AUTH);
        RadiusPacket response = RadiusPackets.create(realDictionary, ACCOUNTING_RESPONSE, 7);
        ResponseCtx ctx = new ResponseCtx(request, new RadiusEndpoint(CLIENT, SECRET), response);

        DatagramPacket packet = codec(true).encodePacket(SERVER, ctx);
        assertEquals(packet.content().readableBytes(), 20);
        packet.release();
    }

    @Override
    protected List<? extends Object> resetMock() {
        return null;
    }
}
