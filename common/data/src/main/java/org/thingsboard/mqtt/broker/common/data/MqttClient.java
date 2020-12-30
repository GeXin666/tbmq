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
package org.thingsboard.mqtt.broker.common.data;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@EqualsAndHashCode(callSuper = true)
public class MqttClient extends BaseData {
    @Getter
    @Setter
    private String clientId;
    @Getter
    @Setter
    private String name;
    @Getter
    @Setter
    private UUID createdBy;

    public MqttClient() {
    }

    public MqttClient(UUID id) {
        super(id);
    }

    public MqttClient(MqttClient mqttClient) {
        super(mqttClient);
        this.clientId = mqttClient.clientId;
        this.name = mqttClient.name;
        this.createdBy = mqttClient.createdBy;
    }


    @Override
    public String toString() {
        return "MqttClient [clientId=" +
                clientId +
                ", name=" +
                name +
                ", createdBy=" +
                createdBy +
                ", createdTime=" +
                createdTime +
                ", id=" +
                id +
                "]";
    }
}