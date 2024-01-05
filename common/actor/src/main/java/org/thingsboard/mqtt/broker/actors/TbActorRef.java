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
package org.thingsboard.mqtt.broker.actors;


import org.thingsboard.mqtt.broker.actors.msg.TbActorMsg;

public interface TbActorRef {

    /**
     * 获取客户端ID
     */
    TbActorId getActorId();

    /**
     * 处理普通优先级消息
     * @param actorMsg
     */
    void tell(TbActorMsg actorMsg);

    /**
     * 处理高优先级消息
     * @param actorMsg
     */
    void tellWithHighPriority(TbActorMsg actorMsg);

}
