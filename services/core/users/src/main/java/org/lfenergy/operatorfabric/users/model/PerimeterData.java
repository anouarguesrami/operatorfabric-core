/* Copyright (c) 2020, RTE (http://www.rte-france.com)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.lfenergy.operatorfabric.users.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.*;

/**
 * Perimeter Model, documented at {@link Perimeter}
 *
 * {@inheritDoc}
 *
 */
@Document(collection = "perimeter")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PerimeterData implements Perimeter {
    @Id
    private String id;
    private String process;

    @JsonIgnore
    @Singular
    private List<? extends StateRight> stateRights;

    @Override
    public void setStateRights(List<? extends StateRight> stateRights) {
        this.stateRights = new ArrayList<>(stateRights);
    }

    @Override
    public List<? extends StateRight> getStateRights() {
        if(stateRights == null)
            return Collections.emptyList();
        return new ArrayList<>(stateRights);
    }
}