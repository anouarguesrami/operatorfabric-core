/* Copyright (c) 2018-2021, RTE (http://www.rte-france.com)
 * See AUTHORS.txt
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * SPDX-License-Identifier: MPL-2.0
 * This file is part of the OperatorFabric project.
 */


import {Injectable} from '@angular/core';
import {Actions, createEffect, ofType} from '@ngrx/effects';
import {CardService} from '@ofServices/card.service';
import {Observable, of} from 'rxjs';
import {catchError, filter, map, switchMap, withLatestFrom} from 'rxjs/operators';
import {
    LightCardActionTypes,
    LoadLightCardsSuccess,
    UpdateALightCard
} from '@ofActions/light-card.actions';
import {Store} from '@ngrx/store';
import {AppState} from '@ofStore/index';
import {ApplyFilter, FeedActionTypes} from '@ofActions/feed.actions';
import {FilterType} from '@ofServices/filter.service';
import {selectCardStateSelectedId} from '@ofSelectors/card.selectors';
import {LoadCard} from '@ofActions/card.actions';
import {SoundNotificationService} from '@ofServices/sound-notification.service';
import {selectSortedFilterLightCardIds} from '@ofSelectors/feed.selectors';


@Injectable()
export class CardOperationEffects {


    constructor(private store: Store<AppState>,
                private actions$: Actions,
                private service: CardService,
                private soundNotificationService: SoundNotificationService) {
    }



    
    triggerSoundNotifications = createEffect(() => this.actions$
        /* Creating a dedicated effect was necessary because this handling needs to be done once the added cards have been
         * processed since we take a look at the feed state to know if the card is currently visible or not */
        .pipe(
            ofType(LightCardActionTypes.LoadLightCardsSuccess),
            map((loadedCardAction: LoadLightCardsSuccess) => loadedCardAction.payload.lightCard),
            withLatestFrom(this.store.select(selectSortedFilterLightCardIds)),
            /* Since both this effect and the feed state update are triggered by LoadLightCardSuccess, there could
            * theoretically be an issue if the feed state update by the reducer hasn't been done before we take the
            * list of visible cards using withLatestFrom. However, this hasn't cropped up in any of the tests so far so
            * we'll deal with it if the need arises.*/
            map(([lightCard, currentlyVisibleIds]) => {
                    this.soundNotificationService.handleCards(lightCard, currentlyVisibleIds);
                }
            )
        ), {dispatch: false});


    
    triggerSoundNotificationsWhenRemind = createEffect(() => this.actions$
        .pipe(
            ofType(LightCardActionTypes.UpdateALightCard),
            map((updateCard: UpdateALightCard) => {
                    const card = updateCard.payload.card;
                    // in case it is a remind the card is update with hasBeenRead set to false
                    if (!card.hasBeenRead) this.soundNotificationService.playSoundForCard(card);
                })
        ), {dispatch: false});

    
    updateSubscription: Observable<any> = createEffect(() => this.actions$
        .pipe(
            ofType(FeedActionTypes.ApplyFilter),
            filter((af: ApplyFilter) => af.payload.name === FilterType.BUSINESSDATE_FILTER),
            switchMap((af: ApplyFilter) => {
                    this.service.setSubscriptionDates(af.payload.status.start, af.payload.status.end);
                    return of();
                }
            ),
            catchError((error, caught) => {
                console.error('CardOperationEffect - Error in update subscription ', error);
                return caught;
            })
        ), { dispatch: false });

    
    refreshIfSelectedCard: Observable<any> = createEffect(() => this.actions$
        .pipe(
            ofType(LightCardActionTypes.LoadLightCardsSuccess),
            map((a: LoadLightCardsSuccess) => a.payload.lightCard), 
            withLatestFrom(this.store.select(selectCardStateSelectedId)), // retrieve currently selected card
            switchMap(([lightCard, selectedCardId]) =>  {
                if (lightCard.id === selectedCardId)  this.store.dispatch(new LoadCard({id: lightCard.id}));
                return of();
            })
            ), { dispatch: false });
}
