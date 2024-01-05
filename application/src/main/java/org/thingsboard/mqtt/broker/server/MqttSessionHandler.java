/**
 * Copyright © 2016-2023 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.mqtt.broker.server;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.handler.codec.mqtt.MqttConnectMessage;
import io.netty.handler.codec.mqtt.MqttMessage;
import io.netty.handler.codec.mqtt.MqttMessageIdVariableHeader;
import io.netty.handler.codec.mqtt.MqttMessageType;
import io.netty.handler.codec.mqtt.MqttPubAckMessage;
import io.netty.handler.codec.mqtt.MqttPublishMessage;
import io.netty.handler.codec.mqtt.MqttSubscribeMessage;
import io.netty.handler.codec.mqtt.MqttUnsubscribeMessage;
import io.netty.handler.codec.mqtt.MqttVersion;
import io.netty.handler.ssl.NotSslRecordException;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.thingsboard.mqtt.broker.actors.client.messages.SessionInitMsg;
import org.thingsboard.mqtt.broker.actors.client.messages.mqtt.MqttDisconnectMsg;
import org.thingsboard.mqtt.broker.adaptor.NettyMqttConverter;
import org.thingsboard.mqtt.broker.common.data.StringUtils;
import org.thingsboard.mqtt.broker.common.util.BrokerConstants;
import org.thingsboard.mqtt.broker.exception.ProtocolViolationException;
import org.thingsboard.mqtt.broker.service.analysis.ClientLogger;
import org.thingsboard.mqtt.broker.service.limits.RateLimitService;
import org.thingsboard.mqtt.broker.session.ClientMqttActorManager;
import org.thingsboard.mqtt.broker.session.ClientSessionCtx;
import org.thingsboard.mqtt.broker.session.DisconnectReason;
import org.thingsboard.mqtt.broker.session.DisconnectReasonType;
import org.thingsboard.mqtt.broker.session.SessionContext;

import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.UUID;

@Slf4j
public class MqttSessionHandler extends ChannelInboundHandlerAdapter implements GenericFutureListener<Future<? super Void>>, SessionContext {

    public static final AttributeKey<InetSocketAddress> ADDRESS = AttributeKey.newInstance("SRC_ADDRESS");

    private final ClientMqttActorManager clientMqttActorManager;
    private final ClientLogger clientLogger;
    private final RateLimitService rateLimitService;

    //mqtt客户端channel
    private final ClientSessionCtx clientSessionCtx;

    //session-id
    @Getter
    private final UUID sessionId = UUID.randomUUID();

    //mqtt客户端id
    private String clientId;

    //mqtt客户端ip
    private InetSocketAddress address;

    public MqttSessionHandler(ClientMqttActorManager clientMqttActorManager, ClientLogger clientLogger,
                              RateLimitService rateLimitService, SslHandler sslHandler, int maxInFlightMsgs) {
        this.clientMqttActorManager = clientMqttActorManager;
        this.clientLogger = clientLogger;
        this.rateLimitService = rateLimitService;
        this.clientSessionCtx = new ClientSessionCtx(sessionId, sslHandler, maxInFlightMsgs);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (address == null) {
            address = getAddress(ctx);
            clientSessionCtx.setAddress(address);
        }
        if (log.isTraceEnabled()) {
            log.trace("[{}][{}][{}] Processing msg: {}", address, clientId, sessionId, msg);
        }
        clientSessionCtx.setChannel(ctx);
        try {
            //不是mqtt消息则断开channel
            if (!(msg instanceof MqttMessage)) {
                log.warn("[{}][{}] Received unknown message", clientId, sessionId);
                disconnect(new DisconnectReason(DisconnectReasonType.ON_PROTOCOL_ERROR, "Received unknown message"));
                return;
            }

            MqttMessage message = (MqttMessage) msg;
            //处理错误格式的mqtt消息
            if (!message.decoderResult().isSuccess()) {
                log.warn("[{}][{}] Message decoding failed: {}", clientId, sessionId, message.decoderResult().cause().getMessage());
                if (message.decoderResult().cause() instanceof TooLongFrameException) {
                    disconnect(new DisconnectReason(DisconnectReasonType.ON_PACKET_TOO_LARGE));
                } else {
                    disconnect(new DisconnectReason(DisconnectReasonType.ON_MALFORMED_PACKET, "Message decoding failed"));
                }
                return;
            }

            //处理正确格式的mqtt消息
            processMqttMsg(message);
        } finally {
            ReferenceCountUtil.safeRelease(msg);
        }
    }

    private void processMqttMsg(MqttMessage msg) {
        if (msg.fixedHeader() == null) {
            throw new ProtocolViolationException("Invalid message received");
        }

        MqttMessageType msgType = msg.fixedHeader().messageType();
        if (StringUtils.isEmpty(clientId)) {
            //首次登录初始化Session
            if (msgType == MqttMessageType.CONNECT) {
                initSession((MqttConnectMessage) msg);
            } else {
                throw new ProtocolViolationException("Received " + msgType + " while session wasn't initialized");
            }
        }

        clientLogger.logEvent(clientId, this.getClass(), "Received msg " + msgType);
        switch (msgType) {
            case DISCONNECT:
                disconnect(NettyMqttConverter.createMqttDisconnectMsg(clientSessionCtx, msg));
                break;
            case CONNECT:
                clientMqttActorManager.connect(clientId, NettyMqttConverter.createMqttConnectMsg(sessionId, (MqttConnectMessage) msg));
                break;
            case SUBSCRIBE:
                clientMqttActorManager.processMqttMsg(clientId, NettyMqttConverter.createMqttSubscribeMsg(sessionId, (MqttSubscribeMessage) msg));
                break;
            case UNSUBSCRIBE:
                clientMqttActorManager.processMqttMsg(clientId, NettyMqttConverter.createMqttUnsubscribeMsg(sessionId, (MqttUnsubscribeMessage) msg));
                break;
            case PUBLISH:
                processPublish(msg);
                break;
            case PUBACK:
                clientMqttActorManager.processMqttMsg(clientId, NettyMqttConverter.createMqttPubAckMsg(sessionId, (MqttPubAckMessage) msg));
                break;
            case PUBREC:
                clientMqttActorManager.processMqttMsg(clientId, NettyMqttConverter.createMqttPubRecMsg(sessionId, (MqttMessageIdVariableHeader) msg.variableHeader()));
                break;
            case PUBREL:
                clientMqttActorManager.processMqttMsg(clientId, NettyMqttConverter.createMqttPubRelMsg(sessionId, (MqttMessageIdVariableHeader) msg.variableHeader()));
                break;
            case PUBCOMP:
                clientMqttActorManager.processMqttMsg(clientId, NettyMqttConverter.createMqttPubCompMsg(sessionId, (MqttMessageIdVariableHeader) msg.variableHeader()));
                break;
            case PINGREQ:
                clientMqttActorManager.processMqttMsg(clientId, NettyMqttConverter.createMqttPingMsg(sessionId));
                break;
        }
    }

    //处理发送消息
    private void processPublish(MqttMessage msg) {
        if (checkLimits(msg)) {
            clientMqttActorManager.processMqttMsg(clientId, NettyMqttConverter.createMqttPublishMsg(sessionId, (MqttPublishMessage) msg));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("[{}][{}] Disconnecting client on rate limits detection!", clientId, sessionId);
            }
            disconnect(new DisconnectReason(DisconnectReasonType.ON_RATE_LIMITS, "Rate limits detected"));
        }
    }

    /**
     * 检查客户端速率
     * @param msg
     */
    private boolean checkLimits(MqttMessage msg) {
        return rateLimitService.checkLimits(clientId, sessionId, msg);
    }

    /**
     * 初始化session
     * @param connectMessage
     */
    private void initSession(MqttConnectMessage connectMessage) {
        //mqtt客户端ID
        clientId = connectMessage.payload().clientIdentifier();
        boolean isClientIdGenerated = StringUtils.isEmpty(clientId);
        clientId = isClientIdGenerated ? generateClientId() : clientId;
        //mqtt客户端版本上下文
        clientSessionCtx.setMqttVersion(getMqttVersion(connectMessage));
        clientMqttActorManager.initSession(clientId, isClientIdGenerated, new SessionInitMsg(
                //客户端上下文
                clientSessionCtx,
                //用户名
                connectMessage.payload().userName(),
                //用户密码
                connectMessage.payload().passwordInBytes()));
    }

    /**
     * 生成客户端ID
     */
    private String generateClientId() {
        return UUID.randomUUID().toString().replaceAll("-", BrokerConstants.EMPTY_STR);
    }

    /**
     * 获取mqtt版本
     */
    private MqttVersion getMqttVersion(MqttConnectMessage connectMessage) {
        var version = (byte) connectMessage.variableHeader().version();
        var protocolName = version > 3 ? BrokerConstants.MQTT_PROTOCOL_NAME : BrokerConstants.MQTT_V_3_1_PROTOCOL_NAME;
        return MqttVersion.fromProtocolNameAndLevel(protocolName, version);
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        ctx.flush();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        String exceptionMessage;
        if (cause.getCause() instanceof SSLHandshakeException) {
            log.warn("[{}] Exception on SSL handshake. Reason - {}", sessionId, cause.getCause().getMessage());
            exceptionMessage = cause.getCause().getMessage();
        } else if (cause.getCause() instanceof NotSslRecordException) {
            log.warn("[{}] NotSslRecordException: {}", sessionId, cause.getCause().getMessage());
            exceptionMessage = cause.getCause().getMessage();
        } else if (cause instanceof IOException) {
            log.warn("[{}] IOException: {}", sessionId, cause.getMessage());
            exceptionMessage = cause.getMessage();
        } else if (cause instanceof ProtocolViolationException) {
            log.warn("[{}] ProtocolViolationException: {}", sessionId, cause.getMessage());
            exceptionMessage = cause.getMessage();
        } else {
            log.error("[{}] Unexpected Exception", sessionId, cause);
            exceptionMessage = cause.getMessage();
        }
        disconnect(new DisconnectReason(DisconnectReasonType.ON_ERROR, exceptionMessage));
    }

    /**
     * 客户端关闭时会回调此方法
     */
    @Override
    public void operationComplete(Future<? super Void> future) {
        if (clientId != null) {
            disconnect(new DisconnectReason(DisconnectReasonType.ON_CHANNEL_CLOSED));
        }
    }

    /**
     * 关闭连接
     */
    void disconnect(DisconnectReason reason) {
        if (clientId == null) {
            if (log.isDebugEnabled()) {
                log.debug("[{}] Session wasn't initialized yet, closing channel. Reason - {}.", sessionId, reason);
            }
            try {
                //不存在客户端ID，说明还没有完成登录动作，直接关闭channel.
                clientSessionCtx.closeChannel();
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("[{}] Failed to close channel.", sessionId, e);
                }
            }
        } else {
            //发送关闭报文
            disconnect(new MqttDisconnectMsg(sessionId, reason));
        }
    }

    /**
     * 发送关闭报文
     */
    void disconnect(MqttDisconnectMsg disconnectMsg) {
        clientMqttActorManager.disconnect(clientId, disconnectMsg);
    }

    /**
     * 获取客户端ip
     */
    InetSocketAddress getAddress(ChannelHandlerContext ctx) {
        var address = ctx.channel().attr(ADDRESS).get();
        if (address == null) {
            if (log.isTraceEnabled()) {
                log.trace("[{}] Received empty address.", ctx.channel().id());
            }
            InetSocketAddress remoteAddress = (InetSocketAddress) ctx.channel().remoteAddress();
            if (log.isTraceEnabled()) {
                log.trace("[{}] Going to use address: {}", ctx.channel().id(), remoteAddress);
            }
            return remoteAddress;
        } else {
            if (log.isTraceEnabled()) {
                log.trace("[{}] Received address: {}", ctx.channel().id(), address);
            }
        }
        return address;
    }
}
