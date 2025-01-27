/* Copyright (c) 2018-2021, RTE (http://www.rte-france.com)
 * See AUTHORS.txt
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * SPDX-License-Identifier: MPL-2.0
 * This file is part of the OperatorFabric project.
 */



package org.opfab.users.configuration.oauth2;

import org.opfab.users.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * WebSecurityChecks
 * This class defines the access checks that can be performed, for use in {@link WebSecurityConfiguration}
 *
 *
 */

@Component
@Slf4j
public class WebSecurityChecks {

    public boolean checkUserLogin(Authentication authentication, String login) {

        String user;

        //authentication.getPrincipal() is UserData type if there is authentication
        //but is String type if there is no authentication (jira : OC-655)
        if (authentication.getPrincipal()  instanceof String)
            user = (String) authentication.getPrincipal();
        else
            user = ((User) authentication.getPrincipal()).getLogin();

            log.debug("login from the principal {} login parameter {}", user, login);

        return user.equals(login);
    }
      
}
