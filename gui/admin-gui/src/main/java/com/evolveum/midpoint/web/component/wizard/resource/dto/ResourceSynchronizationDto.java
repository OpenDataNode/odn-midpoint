/*
 * Copyright (c) 2010-2014 Evolveum
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

package com.evolveum.midpoint.web.component.wizard.resource.dto;

import com.evolveum.midpoint.xml.ns._public.common.common_3.ObjectSynchronizationType;

import javax.xml.namespace.QName;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *  @author shood
 * */
public class ResourceSynchronizationDto implements Serializable{

    public static final String F_OBJECT_SYNC_LIST = "objectSyncList";
    public static final String F_SELECTED = "selected";
    public static final String F_OBJECT_CLASS_LIST = "objectClassList";

    private List<ObjectSynchronizationTypeDto> objectSyncList = new ArrayList<>();
    private ObjectSynchronizationType selected;
    private List<QName> objectClassList;
    private Map<String, String> objectTemplateMap = new HashMap<>();

    public List<ObjectSynchronizationTypeDto> getObjectSyncList() {
        return objectSyncList;
    }

    public void setObjectSyncList(List<ObjectSynchronizationTypeDto> objectSyncList) {
        this.objectSyncList = objectSyncList;
    }

    public ObjectSynchronizationType getSelected() {
        return selected;
    }

    public void setSelected(ObjectSynchronizationType selected) {
        this.selected = selected;
    }

    public List<QName> getObjectClassList() {
        if(objectClassList == null){
            objectClassList = new ArrayList<>();
        }

        return objectClassList;
    }

    public void setObjectClassList(List<QName> objectClassList) {
        this.objectClassList = objectClassList;
    }

    public Map<String, String> getObjectTemplateMap() {
        return objectTemplateMap;
    }

    public void setObjectTemplateMap(Map<String, String> objectTemplateMap) {
        this.objectTemplateMap = objectTemplateMap;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ResourceSynchronizationDto)) return false;

        ResourceSynchronizationDto that = (ResourceSynchronizationDto) o;

        if (objectClassList != null ? !objectClassList.equals(that.objectClassList) : that.objectClassList != null)
            return false;
        if (objectSyncList != null ? !objectSyncList.equals(that.objectSyncList) : that.objectSyncList != null)
            return false;
        if (objectTemplateMap != null ? !objectTemplateMap.equals(that.objectTemplateMap) : that.objectTemplateMap != null)
            return false;
        if (selected != null ? !selected.equals(that.selected) : that.selected != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = objectSyncList != null ? objectSyncList.hashCode() : 0;
        result = 31 * result + (selected != null ? selected.hashCode() : 0);
        result = 31 * result + (objectClassList != null ? objectClassList.hashCode() : 0);
        result = 31 * result + (objectTemplateMap != null ? objectTemplateMap.hashCode() : 0);
        return result;
    }
}
