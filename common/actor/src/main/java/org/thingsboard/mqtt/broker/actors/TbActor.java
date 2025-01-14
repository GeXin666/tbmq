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

/**
 * 相当于mqtt客户端
 */
public interface TbActor {

    boolean process(TbActorMsg msg);

    TbActorRef getActorRef();

    default void init(TbActorCtx ctx) throws TbActorException {
    }

    default void destroy() throws TbActorException {
    }

    /**
     * 返回出错尝试策略
     * @param attempt 错误次数
     * @return InitFailureStrategy 5000 * attempt 每次延迟时间递增
     */
    default InitFailureStrategy onInitFailure(int attempt, Throwable t) {
        return InitFailureStrategy.retryWithDelay(5000 * attempt);
    }

    default ProcessFailureStrategy onProcessFailure(Throwable t) {
        if (t instanceof Error) {
            return ProcessFailureStrategy.stop();
        } else {
            return ProcessFailureStrategy.resume();
        }
    }
}
