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

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.thingsboard.mqtt.broker.actors.msg.TbActorMsg;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;
import java.util.function.Supplier;

@Slf4j
@Data
public final class TbActorMailbox implements TbActorCtx {

    private static final boolean HIGH_PRIORITY = true;
    private static final boolean NORMAL_PRIORITY = false;

    private static final boolean FREE = false;

    private static final boolean BUSY = true;

    private static final boolean NOT_READY = false;
    private static final boolean READY = true;

    private final TbActorSystem system;
    private final TbActorSystemSettings settings;
    private final TbActorId selfId;
    private final TbActorRef parentRef;
    private final TbActor actor;

    //业务线程池
    private final Dispatcher dispatcher;

    //高优先级消息队列
    private final ConcurrentLinkedQueue<TbActorMsg> highPriorityMsgs = new ConcurrentLinkedQueue<>();
    //低优先级消息队列
    private final ConcurrentLinkedQueue<TbActorMsg> normalPriorityMsgs = new ConcurrentLinkedQueue<>();

    private final AtomicBoolean busy = new AtomicBoolean(FREE);
    private final AtomicBoolean ready = new AtomicBoolean(NOT_READY);
    private final AtomicBoolean destroyInProgress = new AtomicBoolean();

    private final boolean isTraceEnabled = log.isTraceEnabled();
    private final boolean isDebugEnabled = log.isDebugEnabled();

    public void initActor() {
        //初始化 --> 尝试启动
        dispatcher.getExecutor().execute(() -> tryInit(1));
    }

    private void tryInit(int attempt) {
        try {
            if (log.isDebugEnabled()) {
                log.debug("[{}] Trying to init actor, attempt: {}", selfId, attempt);
            }
            if (!destroyInProgress.get()) {
                actor.init(this);
                if (!destroyInProgress.get()) {
                    //设置为启动状态
                    ready.set(READY);
                    //启动任务队列
                    tryProcessQueue(false);
                }
            }
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug("[{}] Failed to init actor, attempt: {}", selfId, attempt, t);
            }
            int attemptIdx = attempt + 1;
            InitFailureStrategy strategy = actor.onInitFailure(attempt, t);
            //如果尝试策略返回暂停  或者 尝试错误次数大于限定值
            if (strategy.isStop() || (settings.getMaxActorInitAttempts() > 0 && attemptIdx > settings.getMaxActorInitAttempts())) {
                log.info("[{}] Failed to init actor, attempt {}, going to stop attempts.", selfId, attempt, t);
                system.stop(selfId);
            } else if (strategy.getRetryDelay() > 0) {
                log.info("[{}] Failed to init actor, attempt {}, going to retry in attempts in {}ms", selfId, attempt, strategy.getRetryDelay());
                if (log.isDebugEnabled()) {
                    log.debug("[{}] Error", selfId, t);
                }
                //延迟尝试启动
                system.getScheduler().schedule(() -> dispatcher.getExecutor().execute(() -> tryInit(attemptIdx)), strategy.getRetryDelay(), TimeUnit.MILLISECONDS);
            } else {
                log.info("[{}] Failed to init actor, attempt {}, going to retry immediately", selfId, attempt);
                if (log.isDebugEnabled()) {
                    log.debug("[{}] Error", selfId, t);
                }
                //立即尝试启动
                dispatcher.getExecutor().execute(() -> tryInit(attemptIdx));
            }
        }
    }

    private void enqueue(TbActorMsg msg, boolean highPriority) {
        //如果已经关闭了,直接回调。
        if (destroyInProgress.get()) {
            msg.onTbActorStopped(selfId);
            return;
        }
        //根据高低优先级投入到不同队列。
        if (highPriority) {
            highPriorityMsgs.add(msg);
        } else {
            normalPriorityMsgs.add(msg);
        }
        //开始处理队列中消息。
        tryProcessQueue(true);
    }

    /**
     * 尝试处理队列中的消息
     * @param newMsg 是否有新消息立即处理 </p>
     *               newMsg：true 说明有新消息，立即启动处理逻辑</p>
     *               newMsg：false 没有新消息，如果消息队列中有消息，则启动处理逻辑。
     *
     */
    private void tryProcessQueue(boolean newMsg) {
        if (ready.get() == READY) {
            if (newMsg || !highPriorityMsgs.isEmpty() || !normalPriorityMsgs.isEmpty()) {
                //如果是FREE则设置为BUSY.设置成功了才开始处理消息.
                if (busy.compareAndSet(FREE, BUSY)) {
                    //处理消息
                    dispatcher.getExecutor().execute(this::processMailbox);
                } else {
                    if (isTraceEnabled) {
                        log.trace("[{}] MessageBox is busy, new msg: {}", selfId, newMsg);
                    }
                }
            } else {
                if (isTraceEnabled) {
                    log.trace("[{}] MessageBox is empty, new msg: {}", selfId, newMsg);
                }
            }
        } else {
            if (isTraceEnabled) {
                log.trace("[{}] MessageBox is not ready, new msg: {}", selfId, newMsg);
            }
        }
    }

    //处理队列中的消息
    private void processMailbox() {
        boolean noMoreElements = false;
        //处理一个批次的消息
        for (int i = 0; i < settings.getActorThroughput(); i++) {
            //先高优先级 在低优先级
            TbActorMsg msg = highPriorityMsgs.poll();
            if (msg == null) {
                msg = normalPriorityMsgs.poll();
            }
            if (msg != null) {
                try {
                    if (isDebugEnabled) {
                        log.debug("[{}] Going to process message: {}", selfId, msg);
                    }
                    //交给客户端去处理
                    actor.process(msg);
                } catch (Throwable t) {
                    if (isDebugEnabled) {
                        log.debug("[{}] Failed to process message: {}", selfId, msg, t);
                    }
                    ProcessFailureStrategy strategy = actor.onProcessFailure(t);
                    if (strategy.isStop()) {
                        system.stop(selfId);
                    }
                }
            } else {
                //队列中已经没有消息,暂停循环.
                noMoreElements = true;
                break;
            }
        }
        if (noMoreElements) {
            //没有消息则设置FREE状态.
            busy.set(FREE);
            //然后在处理一次消息队列.
            dispatcher.getExecutor().execute(() -> tryProcessQueue(false));
        } else {
            //如果队列中还存在消息，则放入执行器等待下一轮任务调度.
            dispatcher.getExecutor().execute(this::processMailbox);
        }
    }

    @Override
    public TbActorId getSelf() {
        return selfId;
    }

    @Override
    public void tell(TbActorId target, TbActorMsg actorMsg) {
        system.tell(target, actorMsg);
    }

    @Override
    public void broadcastToChildren(TbActorMsg msg) {
        system.broadcastToChildren(selfId, msg);
    }

    @Override
    public void broadcastToChildren(TbActorMsg msg, Predicate<TbActorId> childFilter) {
        system.broadcastToChildren(selfId, childFilter, msg);
    }

    @Override
    public List<TbActorId> filterChildren(Predicate<TbActorId> childFilter) {
        return system.filterChildren(selfId, childFilter);
    }

    @Override
    public void stop(TbActorId target) {
        system.stop(target);
    }

    @Override
    public TbActorRef getOrCreateChildActor(TbActorId actorId, Supplier<String> dispatcher, Supplier<TbActorCreator> creator) {
        TbActorRef actorRef = system.getActor(actorId);
        if (actorRef == null) {
            return system.createChildActor(dispatcher.get(), creator.get(), selfId);
        } else {
            return actorRef;
        }
    }

    public void destroy() {
        destroyInProgress.set(true);
        dispatcher.getExecutor().execute(() -> {
            try {
                //设置关闭状态.
                ready.set(NOT_READY);
                actor.destroy();
                //队列中还未处理的消息，循环回调函数。
                highPriorityMsgs.forEach(msg -> msg.onTbActorStopped(selfId));
                normalPriorityMsgs.forEach(msg -> msg.onTbActorStopped(selfId));
            } catch (Throwable t) {
                log.warn("[{}] Failed to destroy actor", selfId, t);
            }
        });
    }

    @Override
    public TbActorId getActorId() {
        return selfId;
    }

    @Override
    public void tell(TbActorMsg actorMsg) {
        enqueue(actorMsg, NORMAL_PRIORITY);
    }

    @Override
    public void tellWithHighPriority(TbActorMsg actorMsg) {
        enqueue(actorMsg, HIGH_PRIORITY);
    }

}
