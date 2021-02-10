/* Copyright (c) 2018-2020, RTE (http://www.rte-france.com)
 * See AUTHORS.txt
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * SPDX-License-Identifier: MPL-2.0
 * This file is part of the OperatorFabric project.
 */


import {inject, TestBed} from '@angular/core/testing';

import {CardService} from './card.service';
import {HttpClientTestingModule, HttpTestingController} from '@angular/common/http/testing';
import {AuthenticationService} from '@ofServices/authentication/authentication.service';
import {GuidService} from "@ofServices/guid.service";
import {StoreModule} from "@ngrx/store";
import {appReducer} from "@ofStore/index";
import SpyObj = jasmine.SpyObj;
import createSpyObj = jasmine.createSpyObj;
import {injectedSpy} from '@tests/helpers';


describe('CardService', () => {
    let httpMock: HttpTestingController;
    let authenticationService: SpyObj<AuthenticationService>;

    beforeEach(() => {
        const authenticationServiceSpy = createSpyObj('authenticationService'
            , ['extractToken'
                , 'verifyExpirationDate'
                , 'clearAuthenticationInformation'
                , 'registerAuthenticationInformation'
            ]);

        TestBed.configureTestingModule({
            imports: [HttpClientTestingModule,
                StoreModule.forRoot(appReducer)],
            providers: [CardService
                , AuthenticationService
                ,GuidService
            ]
        });
        httpMock = TestBed.inject(HttpTestingController);
        authenticationService = injectedSpy(AuthenticationService);
    });
});
