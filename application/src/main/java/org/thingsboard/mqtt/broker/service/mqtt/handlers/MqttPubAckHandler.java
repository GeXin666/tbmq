/**
 * Copyright © 2016-2020 The Thingsboard Authors
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
package org.thingsboard.mqtt.broker.service.mqtt.handlers;

import io.netty.handler.codec.mqtt.MqttPubAckMessage;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.thingsboard.mqtt.broker.exception.MqttException;
import org.thingsboard.mqtt.broker.service.processing.PublishMsgDistributor;
import org.thingsboard.mqtt.broker.session.ClientSessionCtx;

@Service
@AllArgsConstructor
@Slf4j
public class MqttPubAckHandler {

    private final PublishMsgDistributor publishMsgDistributor;

    public void process(ClientSessionCtx ctx, MqttPubAckMessage msg) throws MqttException {
        int packetId = msg.variableHeader().messageId();
        publishMsgDistributor.acknowledgeDelivery(packetId, ctx);
    }
}