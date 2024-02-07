/*
 * Copyright 2024 The Backstage Authors
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

import { Request, Response, Handler } from 'express';
import {
  BackstageUserCredentials,
  BackstageServiceCredentials,
  BackstageCredentials,
} from './AuthService';

export type BackstageUnauthorizedCredentials = {
  $$type: '@backstage/BackstageCredentials';

  type: 'unauthorized';
};

export type BackstageCredentialTypes = {
  user: BackstageUserCredentials;
  service: BackstageServiceCredentials;
  unauthorized: BackstageUnauthorizedCredentials;
};

export interface HttpAuthService {
  createHttpPluginRouterMiddleware(): Handler;

  credentials<TAllowed extends keyof BackstageCredentialTypes>(
    req: Request,
    options: {
      allow: Array<TAllowed>;
    },
  ): Promise<BackstageCredentialTypes[TAllowed]>;

  // TODO: Keep an eye on this, might not be needed
  requestHeaders(options?: {
    forward?: BackstageCredentials;
  }): Promise<Record<string, string>>;

  issueUserCookie(res: Response): Promise<void>;
}
