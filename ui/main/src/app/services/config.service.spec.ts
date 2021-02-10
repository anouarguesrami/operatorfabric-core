/* Copyright (c) 2018-2020, RTE (http://www.rte-france.com)
 * See AUTHORS.txt
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * SPDX-License-Identifier: MPL-2.0
 * This file is part of the OperatorFabric project.
 */



import {getTestBed, TestBed} from '@angular/core/testing';
import {HttpClientTestingModule, HttpTestingController} from '@angular/common/http/testing';
import {environment} from '../../environments/environment';
import {Store, StoreModule} from "@ngrx/store";
import {appReducer, AppState} from "../store/index";
import {ConfigService} from "@ofServices/config.service";
import {AcceptLogIn, PayloadForSuccessfulAuthentication} from "@ofActions/authentication.actions";

describe('Businessconfig Services', () => {
    let injector: TestBed;
    let configService: ConfigService;
    let httpMock: HttpTestingController;
    let store: Store<AppState>;
    let config = {
        level1:{
            level2: 'value'
        }
    };
    let url = `${environment.urls.config}`;
    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [
                StoreModule.forRoot(appReducer),
                HttpClientTestingModule,
                // RouterTestingModule,
                ],
            providers: [
                // {provide: store, useClass: Store},
                ConfigService,
            ]
        });
        injector = getTestBed();
        store = TestBed.inject(Store);
        // spyOn(store, 'dispatch').and.callThrough();
        // avoid exceptions during construction and init of the component
        // spyOn(store, 'select').and.callFake(() => of('/test/url'));
        httpMock = injector.get(HttpTestingController);
        configService = TestBed.inject(ConfigService);
        store.dispatch(new AcceptLogIn(new PayloadForSuccessfulAuthentication('test-user',null,null,null)))
    });
    afterEach(() => {
        httpMock.verify();
    });

    it('should be created', () => {
        expect(configService).toBeTruthy();
    });
    describe('#fetchConfiguration', () => {
        it('should return configuration on 200', () => {
            configService.fetchConfiguration().subscribe(
                result => expect(eval(result)).toBe(config)
            )
            let calls = httpMock.match(req => req.url == url);
            expect(calls.length).toEqual(1);
            calls[0].flush(config);
        });

    });
})
;

