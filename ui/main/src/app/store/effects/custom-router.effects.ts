/* Copyright (c) 2018, RTE (http://www.rte-france.com)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import {Injectable} from "@angular/core";
import {Action, Store} from "@ngrx/store";
import {AppState} from "@ofStore/index";
import {Actions, Effect, ofType} from "@ngrx/effects";
import {Observable, of} from "rxjs";
import {
    ROUTER_NAVIGATED,
    ROUTER_NAVIGATION,
    ROUTER_REQUEST,
    RouterNavigationAction,
    RouterRequestAction
} from "@ngrx/router-store";
import {filter, map, switchMap, tap} from "rxjs/operators";
import {LoadCard} from "@ofActions/card.actions";
import {ClearLightCardSelection, SelectLightCard} from "@ofActions/light-card.actions";
import {SelectMenuLink} from "@ofActions/menu.actions";
import {AuthenticationActionTypes, TryToLogOut} from "@ofActions/authentication.actions";

@Injectable()
export class CustomRouterEffects {

    constructor(private store: Store<AppState>,
                private actions$: Actions
    ) {}

    @Effect()
    navigateToCard: Observable<Action> = this.actions$.pipe(
        ofType(ROUTER_NAVIGATION),
        filter((action: RouterNavigationAction, index)=> {
            return action.payload.event.url.indexOf("/feed/cards/")>=0;
        }),
        switchMap(action=>{
            const routerState:any = action.payload.routerState;
            return [
                new LoadCard({id: routerState.params['cid']}),
                new SelectLightCard({selectedCardId: routerState.params['cid']})
            ];
        })
    );

    /**
     * This {Observable} listens for {ROUTER_NAVIGATION} type, filtering only actions navigating to an url containing "/thirdparty/".
     * This will typically be triggered when clicking on a third-party menu link.
     * It then fires a {SelectMenuLink} action containing the route parameters (identifying the third-party menu entry that was clicked) as payload.

     * @name navigateToMenuURL
     */
    @Effect()
    navigateToMenuURL: Observable<Action> = this.actions$.pipe(
        ofType(ROUTER_NAVIGATION),
        filter((action: RouterNavigationAction, index)=> {
            return action.payload.event.url.indexOf("/thirdparty/")>=0;
        }),
        switchMap(action=>{
            const routerState:any = action.payload.routerState;
            return [
                new SelectMenuLink({menu_id: routerState.params['menu_id'], menu_version: routerState.params['menu_version'],menu_entry_id: routerState.params['menu_entry_id']})
            ];
        })
    );

    @Effect({dispatch: false})
    navigateAndResize = this.actions$.pipe(
        ofType(ROUTER_NAVIGATED),
        //TODO On end of navigation? Only on certain paths ?
        switchMap(action => {
            //Trigger resize event
                if (typeof(Event) === 'function') {
                    // modern browsers
                    window.dispatchEvent(new Event('resize'));
                } else {
                    // for IE and other old browsers
                    // causes deprecation warning on modern browsers
                    var evt = window.document.createEvent('UIEvents');
                    evt.initUIEvent('resize', true, false, window, 0);
                    window.dispatchEvent(evt);
                }

                return of({});
            }
        )
    )

    @Effect()
    navigateAwayFromFeed: Observable<Action> = this.actions$.pipe(
        ofType(ROUTER_REQUEST),
        filter((action: RouterRequestAction, index)=> {
            return (action.payload.routerState.url.indexOf("/feed/cards/")>=0) && (action.payload.event.url.indexOf("/feed/")<0); //If navigating from /feed/cards/ to somewhere else
        }),
        map( action => new ClearLightCardSelection())
    )

}
