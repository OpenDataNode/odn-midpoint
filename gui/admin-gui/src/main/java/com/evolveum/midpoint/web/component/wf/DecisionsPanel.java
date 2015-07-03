/*
 * Copyright (c) 2010-2013 Evolveum
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

package com.evolveum.midpoint.web.component.wf;

import com.evolveum.midpoint.web.component.data.TablePanel;
import com.evolveum.midpoint.web.component.util.ListDataProvider;
import com.evolveum.midpoint.web.component.util.SimplePanel;
import com.evolveum.midpoint.web.page.admin.workflow.dto.DecisionDto;
import org.apache.wicket.extensions.markup.html.repeater.data.table.IColumn;
import org.apache.wicket.extensions.markup.html.repeater.data.table.ISortableDataProvider;
import org.apache.wicket.extensions.markup.html.repeater.data.table.PropertyColumn;
import org.apache.wicket.model.IModel;

import java.util.ArrayList;
import java.util.List;

/**
 * @author lazyman
 * @author mederly
 */
public class DecisionsPanel extends SimplePanel<List<DecisionDto>> {

    private static final String ID_DECISIONS_TABLE = "decisionsTable";

    // todo options to select which columns will be shown
    public DecisionsPanel(String id, IModel<List<DecisionDto>> model) {
        super(id, model);
    }

    @Override
    protected void initLayout() {
        List<IColumn<DecisionDto, String>> columns = new ArrayList<IColumn<DecisionDto, String>>();
        columns.add(new PropertyColumn(createStringResource("DecisionsPanel.user"), DecisionDto.F_USER));
        columns.add(new PropertyColumn(createStringResource("DecisionsPanel.result"), DecisionDto.F_RESULT));
        columns.add(new PropertyColumn(createStringResource("DecisionsPanel.comment"), DecisionDto.F_COMMENT));
        columns.add(new PropertyColumn(createStringResource("DecisionsPanel.when"), DecisionDto.F_TIME));

        ISortableDataProvider provider = new ListDataProvider(this, getModel());
        TablePanel decisionsTable = new TablePanel<>(ID_DECISIONS_TABLE, provider, columns);
        add(decisionsTable);
    }
}
