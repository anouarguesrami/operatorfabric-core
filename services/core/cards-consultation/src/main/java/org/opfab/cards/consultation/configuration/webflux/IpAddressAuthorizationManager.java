/* Copyright (c) 2021, RTE (http://www.rte-france.com)
 * See AUTHORS.txt
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * SPDX-License-Identifier: MPL-2.0
 * This file is part of the OperatorFabric project.
 */

package org.opfab.cards.consultation.configuration.webflux;

import java.util.List;


import org.opfab.users.model.CurrentUserWithPerimeters;
import org.opfab.users.model.User;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class IpAddressAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authenticationMono, AuthorizationContext object) {

        return authenticationMono.map(authentication -> {

            if (authentication.isAuthenticated()) {

                User userData = null;
                if (authentication.getPrincipal()  instanceof String) {
                    return new AuthorizationDecision(true);
                }
                else if (authentication.getPrincipal()  instanceof CurrentUserWithPerimeters){
                    CurrentUserWithPerimeters current = (CurrentUserWithPerimeters) authentication.getPrincipal();
                    userData = current.getUserData();
                    
                } else {
                    userData = (User) authentication.getPrincipal();
                }

                WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();

                if (userData != null && details != null) {
                                        
                    String userIp = details.getRemoteAddress();
                    
                    List<String> ipAddresses = userData.getAuthorizedIPAddresses();
                    if (!CollectionUtils.isEmpty(ipAddresses)){
                        return new AuthorizationDecision(ipAddresses.contains(userIp));
                    }
                }
                return new AuthorizationDecision(true);
            }
            return new AuthorizationDecision(false);
            
        });

    }
    
}
