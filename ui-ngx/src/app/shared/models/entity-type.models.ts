///
/// Copyright © 2016-2022 The Thingsboard Authors
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.
///

import { BaseData, HasId } from '@shared/models/base-data';

export enum EntityType {
  USER = 'USER',
  MQTT_CLIENT_CREDENTIALS = 'MQTT_CLIENT_CREDENTIALS',
  MQTT_SESSION = 'MQTT_SESSION'
}

export interface EntityTypeTranslation {
  type?: string;
  typePlural?: string;
  list?: string;
  nameStartsWith?: string;
  details?: string;
  add?: string;
  noEntities?: string;
  selectedEntities?: string;
  search?: string;
}

export interface EntityTypeResource<T> {
  helpLinkId: string;
  helpLinkIdForEntity?(entity: T): string;
}

export const entityTypeTranslations = new Map<EntityType, EntityTypeTranslation>(
  [
    [
      EntityType.USER,
      {
        type: 'entity.type-user',
        typePlural: 'entity.type-users',
        list: 'entity.list-of-users',
        nameStartsWith: 'entity.user-name-starts-with',
        details: 'user.user-details',
        add: 'user.add',
        noEntities: 'user.no-users-text',
        search: 'user.search',
        selectedEntities: 'user.selected-users'
      }
    ],
    [
      EntityType.MQTT_CLIENT_CREDENTIALS,
      {
        type: 'mqtt-client-credentials.type-client-credentials',
        typePlural: 'mqtt-client-credentials.type-clients-credentials',
        list: 'mqtt-client-credentials.list-of-client-credentials',
        nameStartsWith: 'mqtt-client-credentials.client-credentials-name-starts-with',
        details: 'mqtt-client-credentials.client-credentials-details',
        add: 'mqtt-client-credentials.add',
        noEntities: 'mqtt-client-credentials.no-client-credentials-text',
        search: 'mqtt-client-credentials.search',
        selectedEntities: 'mqtt-client-credentials.selected-client-credentials'
      }
    ],
    [
      EntityType.MQTT_SESSION,
      {
        type: 'mqtt-client-session.type-session',
        typePlural: 'mqtt-client-session.type-sessions',
        list: 'mqtt-client-session.list-of-sessions',
        nameStartsWith: 'mqtt-client-session.session-name-starts-with',
        details: 'mqtt-client-session.session-details',
        add: 'mqtt-client-session.add',
        noEntities: 'mqtt-client-session.no-session-text',
        search: 'mqtt-client-session.search',
        selectedEntities: 'mqtt-client-session.selected-sessions'
      }
    ]
  ]
);

export const entityTypeResources = new Map<EntityType, EntityTypeResource<BaseData<HasId>>>(
  [
    [
      EntityType.USER,
      {
        helpLinkId: 'users'
      }
    ],
    [
      EntityType.MQTT_CLIENT_CREDENTIALS,
      {
        helpLinkId: 'mqttClientCredentials'
      }
    ],
    [
      EntityType.MQTT_SESSION,
      {
        helpLinkId: 'mqttSession'
      }
    ]
  ]
);