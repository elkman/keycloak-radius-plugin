package com.github.vzakharchenko.radius.radius.server;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.socket.DatagramPacket;
import org.jboss.logging.Logger;
import org.tinyradius.packet.PacketEncoder;
import org.tinyradius.server.RequestCtx;
import org.tinyradius.server.ResponseCtx;
import org.tinyradius.server.SecretProvider;
import org.tinyradius.server.handler.ServerPacketCodec;

import java.net.InetSocketAddress;

/**
 * Verifies the Message-Authenticator of incoming Access-Requests and signs all
 * Access-Accept/Reject/Challenge responses with a Message-Authenticator
 * (BlastRADIUS / CVE-2024-3596 mitigation).
 */
@ChannelHandler.Sharable
public class MessageAuthenticatorPacketCodec extends ServerPacketCodec {

    private static final Logger LOGGER = Logger.getLogger(MessageAuthenticatorPacketCodec.class);

    private final SecretProvider secretProvider;
    private final boolean requireMessageAuthenticator;

    public MessageAuthenticatorPacketCodec(PacketEncoder packetEncoder,
                                           SecretProvider secretProvider,
                                           boolean requireMessageAuthenticator) {
        super(packetEncoder, secretProvider);
        this.secretProvider = secretProvider;
        this.requireMessageAuthenticator = requireMessageAuthenticator;
    }

    @Override
    protected RequestCtx decodePacket(DatagramPacket packet) {
        ByteBuf content = packet.content();
        if (content.readableBytes() > 0 && content.getUnsignedByte(content.readerIndex())
                == MessageAuthenticator.ACCESS_REQUEST && !isAcceptable(packet)) {
            return null;
        }
        return super.decodePacket(packet);
    }

    private boolean isAcceptable(DatagramPacket packet) {
        String secret = secretProvider.getSharedSecret(packet.sender());
        if (secret == null) {
            // unknown client, rejected by ServerPacketCodec
            return true;
        }
        if (secret.isEmpty()) {
            // no secret configured for this client (empty global sharedSecret)
            return false;
        }
        MessageAuthenticator.Result result = MessageAuthenticator
                .verifyRequest(ByteBufUtil.getBytes(packet.content()), secret);
        boolean acceptable = result == MessageAuthenticator.Result.VALID ||
                result == MessageAuthenticator.Result.MISSING && !requireMessageAuthenticator;
        if (!acceptable) {
            LOGGER.warn("Dropping Access-Request from " + hostAddress(packet.sender())
                    + ": Message-Authenticator " + result);
        }
        return acceptable;
    }

    @Override
    protected DatagramPacket encodePacket(InetSocketAddress localAddress, ResponseCtx ctx) {
        DatagramPacket packet = super.encodePacket(localAddress, ctx);
        if (packet == null) {
            return null;
        }
        try {
            byte[] signed = MessageAuthenticator.signResponse(
                    ByteBufUtil.getBytes(packet.content()),
                    ctx.getRequest().getAuthenticator(),
                    ctx.getEndpoint().getSecret());
            return new DatagramPacket(Unpooled.wrappedBuffer(signed),
                    packet.recipient(), packet.sender());
        } finally {
            packet.release();
        }
    }

    private static String hostAddress(InetSocketAddress address) {
        return address == null || address.getAddress() == null ?
                String.valueOf(address) : address.getAddress().getHostAddress();
    }
}
