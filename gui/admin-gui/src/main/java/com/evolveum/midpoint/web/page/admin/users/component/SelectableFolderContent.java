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

package com.evolveum.midpoint.web.page.admin.users.component;

import com.evolveum.midpoint.web.page.admin.users.dto.OrgTreeDto;
import org.apache.commons.lang.StringUtils;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.extensions.markup.html.repeater.tree.AbstractTree;
import org.apache.wicket.extensions.markup.html.repeater.tree.content.Folder;
import org.apache.wicket.model.AbstractReadOnlyModel;
import org.apache.wicket.model.IModel;

/**
 * @author lazyman
 */
public class SelectableFolderContent extends Folder<OrgTreeDto> {

    private AbstractTree tree;
    private IModel<OrgTreeDto> selected;

    public SelectableFolderContent(String id, AbstractTree<OrgTreeDto> tree, IModel<OrgTreeDto> model,
                                   IModel<OrgTreeDto> selected) {
        super(id, tree, model);

        this.tree = tree;
        this.selected = selected;
    }

    @Override
    protected IModel<?> newLabelModel(final IModel<OrgTreeDto> model) {
        return new AbstractReadOnlyModel<String>() {

            @Override
            public String getObject() {
                OrgTreeDto dto = model.getObject();
                if (StringUtils.isNotEmpty(dto.getDisplayName())) {
                    return dto.getDisplayName();
                }
                return dto.getName();
            }
        };
    }

    @Override
    protected void onClick(AjaxRequestTarget target) {
        if (selected.getObject() != null) {
            tree.updateNode(selected.getObject(), target);
        }

        OrgTreeDto dto = getModelObject();
        selected.setObject(dto);
        tree.updateNode(dto, target);
    }

    @Override
    protected boolean isClickable() {
        return true;
    }

    @Override
    protected boolean isSelected() {
        OrgTreeDto dto = getModelObject();
        return dto.equals(selected.getObject());
    }

    @Override
    protected String getSelectedStyleClass() {
        return null;
    }
}
