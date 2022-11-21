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

import { Injectable } from '@angular/core';
import { defaultHttpOptionsFromConfig, RequestConfig } from './http-utils';
import { Observable } from 'rxjs';
import { HttpClient } from '@angular/common/http';
import { User } from '@shared/models/user.model';

@Injectable({
  providedIn: 'root'
})
export class MqttAdminService {

  constructor(
    private http: HttpClient
  ) { }

  public saveAdmin(user: User, config?: RequestConfig): Observable<User> {
    return this.http.post<User>(`/api/admin`, user, defaultHttpOptionsFromConfig(config));
  }

}