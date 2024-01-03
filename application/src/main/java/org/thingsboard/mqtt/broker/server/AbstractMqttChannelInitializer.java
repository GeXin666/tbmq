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

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.mqtt.MqttDecoder;
import io.netty.handler.codec.mqtt.MqttEncoder;
import io.netty.handler.ssl.SslHandler;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

@Slf4j
@Getter
public abstract class AbstractMqttChannelInitializer extends ChannelInitializer<SocketChannel> implements MqttChannelInitializer {

    @Value("${mqtt.version-3-1.max-client-id-length}")
    private int maxClientIdLength;

    private final MqttHandlerFactory handlerFactory;

    public AbstractMqttChannelInitializer(MqttHandlerFactory handlerFactory) {
        this.handlerFactory = handlerFactory;
    }

    @Override
    public void initChannel(SocketChannel ch) {
        ChannelPipeline pipeline = ch.pipeline();
        SslHandler sslHandler = getSslHandler();
        if (sslHandler != null) {
            pipeline.addLast(sslHandler);
        }

        //挂载websocket的编解码器
        constructWsPipeline(ch);

        //挂载mqtt的编解码器
        pipeline.addLast("decoder", new MqttDecoder(getMaxPayloadSize(), getMaxClientIdLength()));
        pipeline.addLast("encoder", MqttEncoder.INSTANCE);

        //创建mqtt业务处理器
        MqttSessionHandler handler = handlerFactory.create(sslHandler);
        pipeline.addLast(handler);

        //mqtt连接断开时回调
        ch.closeFuture().addListener(handler);

        if (log.isDebugEnabled()) {
            log.debug("[{}] Created {} channel for IP {}.", handler.getSessionId(), getChannelInitializerName(), ch.localAddress());
        }
    }

    /**
     * 挂载websocket的编解码器
     */
    protected void constructWsPipeline(SocketChannel ch) {

    }

}
