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
package org.thingsboard.mqtt.broker.service.auth.providers;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.thingsboard.mqtt.broker.cache.CacheConstants;
import org.thingsboard.mqtt.broker.common.data.StringUtils;
import org.thingsboard.mqtt.broker.common.data.client.credentials.BasicMqttCredentials;
import org.thingsboard.mqtt.broker.common.data.security.MqttClientCredentials;
import org.thingsboard.mqtt.broker.common.util.JacksonUtil;
import org.thingsboard.mqtt.broker.common.util.MqttClientCredentialsUtil;
import org.thingsboard.mqtt.broker.dao.client.MqttClientCredentialsService;
import org.thingsboard.mqtt.broker.dao.util.protocol.ProtocolUtil;
import org.thingsboard.mqtt.broker.exception.AuthenticationException;
import org.thingsboard.mqtt.broker.service.auth.AuthorizationRuleService;
import org.thingsboard.mqtt.broker.service.security.authorization.AuthRulePatterns;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


@Slf4j
@Service
@RequiredArgsConstructor
public class BasicMqttClientAuthProvider implements MqttClientAuthProvider {

    private final AuthorizationRuleService authorizationRuleService;
    private final MqttClientCredentialsService clientCredentialsService;
    private final CacheManager cacheManager;
    private BCryptPasswordEncoder passwordEncoder;
    private HashFunction hashFunction;

    @Autowired
    public BasicMqttClientAuthProvider(AuthorizationRuleService authorizationRuleService,
                                       MqttClientCredentialsService clientCredentialsService,
                                       CacheManager cacheManager,
                                       @Lazy BCryptPasswordEncoder passwordEncoder) {
        this.authorizationRuleService = authorizationRuleService;
        this.clientCredentialsService = clientCredentialsService;
        this.cacheManager = cacheManager;
        this.passwordEncoder = passwordEncoder;
        this.hashFunction = Hashing.sha256();
    }

    /**
     * 通过账号密码认证
     */
    @Override
    public AuthResponse authenticate(AuthContext authContext) throws AuthenticationException {
        if (log.isTraceEnabled()) {
            log.trace("[{}] Authenticating client with basic credentials", authContext.getClientId());
        }
        MqttClientCredentials basicCredentials = authWithBasicCredentials(authContext.getClientId(), authContext.getUsername(), authContext.getPasswordBytes());
        if (basicCredentials == null) {
            return new AuthResponse(false, null, null);
        }
        if (log.isTraceEnabled()) {
            log.trace("[{}] Authenticated with username {}", authContext.getClientId(), authContext.getUsername());
        }
        BasicMqttCredentials credentials = JacksonUtil.fromString(basicCredentials.getCredentialsValue(), BasicMqttCredentials.class);
        AuthRulePatterns authRulePatterns = authorizationRuleService.parseBasicAuthorizationRule(credentials);
        return new AuthResponse(true, basicCredentials.getClientType(), Collections.singletonList(authRulePatterns));
    }

    private MqttClientCredentials authWithBasicCredentials(String clientId, String username, byte[] passwordBytes) {
        //"username|gexin"
        //"client_id|pm-1704338112091"
        //"mixed|gexin|pm-1704338112091"
        List<String> credentialIds = getCredentialIds(clientId, username);

        //查询匹配到的记录集合
        List<MqttClientCredentials> matchingCredentialsList = clientCredentialsService.findMatchingCredentials(credentialIds);
        if (log.isDebugEnabled()) {
            log.debug("Found credentials {} for credentialIds {}", matchingCredentialsList, credentialIds);
        }

        String password = passwordBytesToString(passwordBytes);
        if (password != null) {
            //使用密码的哈希值查询缓存
            MqttClientCredentials credentialsFromCache = getCache().get(toHashString(password), MqttClientCredentials.class);
            //如果缓存命中，并且缓存中的数据与matchingCredentialsList集合中的匹配，说明可以找到记录。
            if (credentialsFromCache != null && matchingCredentialsList.contains(credentialsFromCache)) {
                return credentialsFromCache;
            }
        }

        for (MqttClientCredentials credentials : matchingCredentialsList) {
            //{"clientId":"pm-1704338112092","userName":"gexin","password":"$2a$10$oCLe1ZhEV1DVWf7KXflg6OrPI1N2Ch0ZbIcSv.zLIiDdqbnLDuNaq","authRules":{"pubAuthRulePatterns":[".*"],"subAuthRulePatterns":[".*"]}}
            //把JSON格式转为实体类
            BasicMqttCredentials basicMqttCredentials = MqttClientCredentialsUtil.getMqttCredentials(credentials, BasicMqttCredentials.class);
            if (isMatchingPassword(password, basicMqttCredentials)) {
                //如果密码匹配，则用密码哈希值当做key，然后存储到缓存中。
                if (password != null && basicMqttCredentials.getPassword() != null) {
                    getCache().put(toHashString(password), credentials);
                }
                return credentials;
            }
        }

        //都匹配不上，则返回空，说明认证失败。
        return null;
    }

    private List<String> getCredentialIds(String clientId, String username) {
        List<String> credentialIds = new ArrayList<>();
        if (!StringUtils.isEmpty(username)) {
            credentialIds.add(ProtocolUtil.usernameCredentialsId(username));
        }
        if (!StringUtils.isEmpty(clientId)) {
            credentialIds.add(ProtocolUtil.clientIdCredentialsId(clientId));
        }
        if (!StringUtils.isEmpty(username) && !StringUtils.isEmpty(clientId)) {
            credentialIds.add(ProtocolUtil.mixedCredentialsId(username, clientId));
        }
        return credentialIds;
    }

    private boolean isMatchingPassword(String password, BasicMqttCredentials basicMqttCredentials) {
        return basicMqttCredentials.getPassword() == null
                || (password != null && passwordEncoder.matches(password, basicMqttCredentials.getPassword()));
    }

    private String passwordBytesToString(byte[] passwordBytes) {
        return passwordBytes != null ? new String(passwordBytes, StandardCharsets.UTF_8) : null;
    }

    private Cache getCache() {
        return cacheManager.getCache(CacheConstants.BASIC_CREDENTIALS_PASSWORD_CACHE);
    }

    private String toHashString(String rawPassword) {
        return hashFunction.newHasher().putString(rawPassword, StandardCharsets.UTF_8).hash().toString();
    }
}
