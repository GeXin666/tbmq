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

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.thingsboard.mqtt.broker.actors.msg.TbActorMsg;
import org.thingsboard.mqtt.broker.common.util.ThingsBoardThreadFactory;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Slf4j
public class DefaultTbActorSystem implements TbActorSystem {

    /**
     * 线程池
     * key: "persisted-device-dispatcher" value: ExecutorService
     * key: "client-dispatcher" value: ExecutorService
     */
    private final ConcurrentMap<String, Dispatcher> dispatchers = new ConcurrentHashMap<>();


    private final ConcurrentMap<TbActorId, TbActorMailbox> actors = new ConcurrentHashMap<>();

    /**
     * 一个客户端一把锁
     * kye: 代表mqtt客户端 value:ReentrantLock
     */
    private final ConcurrentMap<TbActorId, ReentrantLock> actorCreationLocks = new ConcurrentHashMap<>();

    private final ConcurrentMap<TbActorId, Set<TbActorId>> parentChildMap = new ConcurrentHashMap<>();

    @Getter
    private final TbActorSystemSettings settings;

    @Getter
    //任务调度线程池
    private final ScheduledExecutorService scheduler;

    public DefaultTbActorSystem(TbActorSystemSettings settings, ActorStatsManager statsManager) {
        this.settings = settings;
        this.scheduler = Executors.newScheduledThreadPool(settings.getSchedulerPoolSize(), ThingsBoardThreadFactory.forName("actor-system-scheduler"));
        statsManager.registerActorsStats(actors);
    }

    /**
     * 创建线程池
     * @param dispatcherId key
     * @param executor 线程池
     */
    @Override
    public void createDispatcher(String dispatcherId, ExecutorService executor) {
        Dispatcher current = dispatchers.putIfAbsent(dispatcherId, new Dispatcher(dispatcherId, executor));
        if (current != null) {
            throw new RuntimeException("Dispatcher with id [" + dispatcherId + "] is already registered!");
        }
    }

    /**
     * 销毁线程池
     * @param dispatcherId key
     */
    @Override
    public void destroyDispatcher(String dispatcherId) {
        Dispatcher dispatcher = dispatchers.remove(dispatcherId);
        if (dispatcher != null) {
            dispatcher.getExecutor().shutdownNow();
        } else {
            throw new RuntimeException("Dispatcher with id [" + dispatcherId + "] is not registered!");
        }
    }

    @Override
    public TbActorRef getActor(TbActorId actorId) {
        return actors.get(actorId);
    }

    @Override
    public TbActorRef createRootActor(String dispatcherId, TbActorCreator creator) {
        return createActor(dispatcherId, creator, null);
    }

    @Override
    public TbActorRef createChildActor(String dispatcherId, TbActorCreator creator, TbActorId parent) {
        return createActor(dispatcherId, creator, parent);
    }

    private TbActorRef createActor(String dispatcherId, TbActorCreator creator, TbActorId parent) {
        Dispatcher dispatcher = dispatchers.get(dispatcherId);
        if (dispatcher == null) {
            log.warn("Dispatcher with id [{}] is not registered!", dispatcherId);
            throw new RuntimeException("Dispatcher with id [" + dispatcherId + "] is not registered!");
        }

        TbActorId actorId = creator.createActorId();
        //客户端封装对象存储
        TbActorMailbox actorMailbox = actors.get(actorId);
        if (actorMailbox != null) {
            if (log.isDebugEnabled()) {
                log.debug("Actor with id [{}] is already registered!", actorId);
            }
        } else {
            //每个客户端一把锁
            Lock actorCreationLock = actorCreationLocks.computeIfAbsent(actorId, id -> new ReentrantLock());
            actorCreationLock.lock();
            try {
                actorMailbox = actors.get(actorId);
                //二次判断是否为空
                if (actorMailbox == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Creating actor with id [{}]!", actorId);
                    }
                    TbActor actor = creator.createActor();
                    TbActorRef parentRef = null;
                    if (parent != null) {
                        parentRef = getActor(parent);
                        if (parentRef == null) {
                            throw new TbActorNotRegisteredException(parent, "Parent Actor with id [" + parent + "] is not registered!");
                        }
                    }
                    //创建客户端封装对象
                    TbActorMailbox mailbox = new TbActorMailbox(this, settings, actorId, parentRef, actor, dispatcher);
                    actors.put(actorId, mailbox);
                    mailbox.initActor();
                    actorMailbox = mailbox;
                    if (parent != null) {
                        parentChildMap.computeIfAbsent(parent, id -> ConcurrentHashMap.newKeySet()).add(actorId);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Actor with id [{}] is already registered!", actorId);
                    }
                }
            } finally {
                //删除锁
                actorCreationLock.unlock();
                actorCreationLocks.remove(actorId);
            }
        }
        return actorMailbox;
    }

    @Override
    public void tellWithHighPriority(TbActorId target, TbActorMsg actorMsg) {
        tell(target, actorMsg, true);
    }

    @Override
    public void tell(TbActorId target, TbActorMsg actorMsg) {
        tell(target, actorMsg, false);
    }

    private void tell(TbActorId target, TbActorMsg actorMsg, boolean highPriority) {
        TbActorMailbox mailbox = actors.get(target);
        if (mailbox == null) {
            throw new TbActorNotRegisteredException(target, "Actor with id [" + target + "] is not registered!");
        }
        if (highPriority) {
            mailbox.tellWithHighPriority(actorMsg);
        } else {
            mailbox.tell(actorMsg);
        }
    }


    @Override
    public void broadcastToChildren(TbActorId parent, TbActorMsg msg) {
        broadcastToChildren(parent, id -> true, msg);
    }

    @Override
    public void broadcastToChildren(TbActorId parent, Predicate<TbActorId> childFilter, TbActorMsg msg) {
        Set<TbActorId> children = parentChildMap.get(parent);
        if (children != null) {
            children.stream().filter(childFilter).forEach(id -> tell(id, msg));
        }
    }

    @Override
    public List<TbActorId> filterChildren(TbActorId parent, Predicate<TbActorId> childFilter) {
        Set<TbActorId> children = parentChildMap.get(parent);
        if (children != null) {
            return children.stream().filter(childFilter).collect(Collectors.toList());
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    public void stop(TbActorRef actorRef) {
        stop(actorRef.getActorId());
    }

    @Override
    public void stop(TbActorId actorId) {
        //如果actorId是父级别，则停止全部子节点。
        Set<TbActorId> children = parentChildMap.remove(actorId);
        if (children != null) {
            for (TbActorId child : children) {
                stop(child);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Stopping actor with id [{}]!", actorId);
        }

        //删除自身并销毁
        TbActorMailbox mailbox = actors.remove(actorId);
        if (mailbox != null) {
            mailbox.destroy();
        }
    }

    @Override
    public Set<TbActorId> getAllActorIds() {
        return new HashSet<>(actors.keySet());
    }

    public void destroy() {
        log.info("Stopping actor system.");
        dispatchers.values().forEach(dispatcher -> {
            dispatcher.getExecutor().shutdown();
            try {
                boolean terminationSuccessful = dispatcher.getExecutor().awaitTermination(3, TimeUnit.SECONDS);
                log.info("[{}] Dispatcher termination is: [{}]", dispatcher.getDispatcherId(), terminationSuccessful ? "successful" : "failed");
            } catch (InterruptedException e) {
                log.warn("[{}] Failed to stop dispatcher due to interruption!", dispatcher.getDispatcherId(), e);
            }
        });
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
        actors.clear();
        log.info("Actor system stopped.");
    }
}
