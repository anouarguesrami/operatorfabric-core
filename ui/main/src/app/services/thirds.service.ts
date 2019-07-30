/* Copyright (c) 2018, RTE (http://www.rte-france.com)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import {Injectable, Injector} from '@angular/core';
import {HttpClient, HttpParams, HttpUrlEncodingCodec} from "@angular/common/http";
import {environment} from "../../environments/environment";
import {AuthenticationService} from "@ofServices/authentication.service";
import {EMPTY, from, merge, Observable, of, throwError} from "rxjs";
import {TranslateLoader, TranslateService} from "@ngx-translate/core";
import {catchError, filter, map, mergeMap, reduce, switchMap, tap} from "rxjs/operators";
import * as _ from 'lodash';
import {Store} from "@ngrx/store";
import {AppState} from "../store/index";
import {LightCard} from "../model/light-card.model";
import {Action, Third, ThirdActionHolder, ThirdMenu} from "@ofModel/thirds.model";
import {Card} from "@ofModel/card.model";

@Injectable()
export class ThirdsService {
    readonly thirdsUrl: string;
    private loadedI18n: string[] = [];
    private loadingI18n: string[] = [];
    private urlCleaner: HttpUrlEncodingCodec;
    private thirdCache = new Map();

    constructor(private httpClient: HttpClient,
                private authenticationService: AuthenticationService,
                private store: Store<AppState>,
                private $injector: Injector,
    ) {
        this.urlCleaner = new HttpUrlEncodingCodec();
        this.thirdsUrl = `${environment.urls.thirds}`;
    }

    queryThirdFromCard(card: Card): Observable<Third> {
        return this.queryThird(card.publisher, card.publisherVersion);
    }

    queryThird(thirdName: string, version: string): Observable<Third> {
        const key = `${thirdName}.${version}`;
        let third = this.thirdCache.get(key);
        if (third) {
            return of(third);
        }
        return this.fetchThird(thirdName, version)
            .pipe(
                tap(t => {
                    if (t) Object.setPrototypeOf(t, Third.prototype)
                }),
                tap(t => {
                    if (t) this.thirdCache.set(key, t)
                })
            );
    }

    private fetchThird(publisher: string, version: string): Observable<Third> {
        const params = new HttpParams()
            .set("version", version);
        return this.httpClient.get<Third>(`${this.thirdsUrl}/${publisher}/`, {
            params
        });
    }

    queryMenuEntryURL(thirdMenuId: string, thirdMenuVersion: string, thirdMenuEntryId: string): Observable<string> {
        return this.queryThird(thirdMenuId, thirdMenuVersion).pipe(
            //filter((third :Third)=>!(!third.menuEntries)),
            switchMap(third => {
                const entry = third.menuEntries.filter(entry => entry.id === thirdMenuEntryId)
                if (entry.length == 1) {
                    return entry;
                } else {
                    throwError(new Error('No such menu entry.'))
                }
            }),
            catchError((err, caught) => {
                console.log(err)
                return throwError(err);
            }),
            map(menuEntry => menuEntry.url)
        )
    }

    fetchHbsTemplate(publisher: string, version: string, name: string, locale: string): Observable<string> {
        const params = new HttpParams()
            .set("locale", locale)
            .set("version", version);
        return this.httpClient.get(`${this.thirdsUrl}/${publisher}/templates/${name}`, {
            params,
            responseType: 'text'
        });
    }

    computeThirdCssUrl(publisher: string, styleName: string, version: string) {
        //manage url character encoding
        const resourceUrl = this.urlCleaner.encodeValue(`${this.thirdsUrl}/${publisher}/css/${styleName}`);
        const versionParam = new HttpParams().set('version', version);
        return `${resourceUrl}?${versionParam.toString()}`;
    }

    fetchI18nJson(publisher: string, version: string, locales: string[]): Observable<any> {
        let previous: Observable<any>;
        for (let locale of locales) {
            const params = new HttpParams()
                .set("locale", locale)
                .set("version", version);
            const httpCall = this.httpClient.get(`${this.thirdsUrl}/${publisher}/i18n`, {
                params
            }).pipe(
                map(r => {
                        const object = {};
                        object[locale] = {};
                        object[locale][publisher] = {};
                        object[locale][publisher][version] = r;
                        return object;
                    }
                ));
            if (previous) {
                previous = merge(previous, httpCall);
            } else {
                previous = httpCall;
            }
        }
        if (previous == null) {
            return EMPTY;
        }
        const result = previous.pipe(
            reduce((acc, val) => _.merge(acc, val))
        );

        return result;
    }

    computeThirdsMenu(): Observable<ThirdMenu[]> {
        return this.httpClient.get<Third[]>(`${this.thirdsUrl}/`).pipe(
            switchMap(ts => from(ts)),
            filter((t: Third) => !(!t.menuEntries)),
            map(t =>
                new ThirdMenu(t.name, t.version, t.i18nLabelKey, t.menuEntries)
            ),
            reduce((menus: ThirdMenu[], menu: ThirdMenu) => {
                menus.push(menu);
                return menus;
            }, [])
        );
    }

    loadI18nForLightCards(cards: LightCard[]) {
        let observable = from(cards).pipe(
            map(card => card.publisher + '###' + card.publisherVersion));
        return this.subscribeToLoadI18n(observable);
    }

    loadI18nForMenuEntries(menus: ThirdMenu[]) {
        const observable = from(menus).pipe(
            map(menu => menu.id + '###' + menu.version)
        );
        return this.subscribeToLoadI18n(observable);
    }

    private subscribeToLoadI18n(observable) {
        return observable
            .pipe(
                reduce((ids: string[], id: string) => {
                    ids.push(id);
                    return ids;
                }, []),
                switchMap((ids: string[]) => {
                    let work = _.uniq(ids);
                    work = _.difference<string>(work, this.loadingI18n)
                    return from(_.difference<string>(work, this.loadedI18n))
                }),
                mergeMap((id: string) => {
                    this.loadingI18n.push(id);
                    const input = id.split('###');

                    let publisher = input[0];
                    let version = input[1];
                    return this.fetchI18nJson(publisher, version, this.translate().getLangs())
                        .pipe(map(trans => {
                                return {id: id, translation: trans};
                            }),
                            catchError(err => {
                                _.remove(this.loadingI18n, id);
                                return throwError(err);
                            })
                        );
                }),
                reduce((acc, val) => _.merge(acc, val)),
                map(
                    (result: any) => {
                        const langs = this.translate().getLangs();
                        const currentLang = this.translate().currentLang;
                        for (let lang of langs) {
                            let translationElement = result.translation[lang];
                            if (translationElement) {
                                this.translate().setTranslation(lang, translationElement, true);
                                // needed otherwise only one translation apply
                                this.translate().use(lang);
                            }
                        }
                        this.translate().use(currentLang);
                        _.remove(this.loadingI18n, result.id);
                        this.loadedI18n.push(result.id);
                        return true;
                    }
                ),
                catchError((error, caught) => {
                    console.error('something went wrong during translation', error);
                    return caught;
                })
            )
    }

    private translate(): TranslateService {
        return this.$injector.get(TranslateService);
    }

    fetchActionsFromLightCard(card: LightCard): Observable<[Array<Action>, ThirdActionHolder]> {
        return this.fetchActions(card.publisher,
            card.process,
            card.state,
            card.publisherVersion,
            card.processId);
    }

    fetchActions(publisher: string,
                 process: string,
                 state: string,
                 version: string,
                 processInstanceId: string): Observable<[Array<Action>, ThirdActionHolder]> {
        return this.fetchActionMap(publisher, process, state,version)
            .pipe(map((actionDictionary: Map<string, Action>) => {
                const entries = Array.from(actionDictionary.entries()) as Array<[string, Action]>;
                // clone action with a key set for id purpose
                const actionRootKey = `${publisher}_${processInstanceId}_${version}_${state}`;
                let actionId = [];
                const thirdActions =
                    _.map(entries,
                        ([key, action]: [string, Action]) => {
                            const actionKey = `${actionRootKey}_${key}`;
                            actionId.push(actionKey)
                            return {...action, actionRootKey: actionRootKey, key: actionKey};
                        }
                    );

                return [thirdActions, new ThirdActionHolder(publisher,
                    process,
                    processInstanceId,
                    version,
                    state,
                    actionId)] as [Array<Action>, ThirdActionHolder];

            }));
    }


    private fetchActionMap(publisher: string, process: string, state: string, apiVersion?:string) {

       let params:HttpParams;
        if(apiVersion) params = new HttpParams().set("apiVersion", apiVersion);

        return this.httpClient.get(`${this.thirdsUrl}/${publisher}/${process}/${state}/actions`, {
            params,
            responseType: 'text'
        }).pipe(map((json: string) => {
            const obj = JSON.parse(json);
            return new Map<string, Action>(Object.entries(obj));
        }));
    }
}

export class ThirdsI18nLoader implements TranslateLoader {

    constructor(thirdsService: ThirdsService) {
    }

    getTranslation(lang: string): Observable<any> {
        return of({});
    }

}

export function ThirdsI18nLoaderFactory(thirdsService: ThirdsService): TranslateLoader {
    return new ThirdsI18nLoader(thirdsService);
}
