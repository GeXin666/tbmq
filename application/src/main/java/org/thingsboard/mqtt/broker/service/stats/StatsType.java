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
package org.thingsboard.mqtt.broker.service.stats;

public enum StatsType {
    MSG_DISPATCHER_PRODUCER("incomingPublishMsg.published"),
    PUBLISH_MSG_CONSUMER("incomingPublishMsg.consumed"),
    SUBSCRIPTION_TOPIC_TRIE_SIZE("subscriptionTopicTrieSize"),
    CONNECTED_CLIENTS("connectedClients"),
    LAST_WILL_CLIENTS("lastWillClients"),
    CONNECTED_SESSIONS("connectedSessions"),
    SUBSCRIPTION_TRIE_NODES("subscriptionTrieNodes"),
    ACTIVE_APP_PROCESSORS("activeAppProcessors"),
    ;

    private final String printName;

    StatsType(String printName) {
        this.printName = printName;
    }

    public String getPrintName() {
        return printName;
    }
}