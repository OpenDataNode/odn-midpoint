/**
 * Copyright (c) 2011 Evolveum
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.opensource.org/licenses/cddl1 or
 * CDDLv1.0.txt file in the source code distribution.
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted 2011 [name of copyright owner]"
 * 
 */
package com.evolveum.midpoint.model.sync;

import java.util.Collection;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;

import com.evolveum.midpoint.provisioning.api.ProvisioningService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.evolveum.midpoint.common.Clock;
import com.evolveum.midpoint.common.refinery.RefinedResourceSchema;
import com.evolveum.midpoint.model.api.PolicyViolationException;
import com.evolveum.midpoint.model.importer.ImportConstants;
import com.evolveum.midpoint.model.lens.ChangeExecutor;
import com.evolveum.midpoint.model.lens.Clockwork;
import com.evolveum.midpoint.model.lens.LensContext;
import com.evolveum.midpoint.model.lens.LensFocusContext;
import com.evolveum.midpoint.model.lens.LensUtil;
import com.evolveum.midpoint.model.util.AbstractSearchIterativeResultHandler;
import com.evolveum.midpoint.model.util.AbstractSearchIterativeTaskHandler;
import com.evolveum.midpoint.model.util.Utils;
import com.evolveum.midpoint.prism.PrismContext;
import com.evolveum.midpoint.prism.PrismObject;
import com.evolveum.midpoint.prism.PrismObjectDefinition;
import com.evolveum.midpoint.prism.PrismProperty;
import com.evolveum.midpoint.prism.PrismPropertyDefinition;
import com.evolveum.midpoint.prism.PrismPropertyValue;
import com.evolveum.midpoint.prism.PrismValue;
import com.evolveum.midpoint.prism.delta.ItemDelta;
import com.evolveum.midpoint.prism.delta.PropertyDelta;
import com.evolveum.midpoint.prism.path.ItemPath;
import com.evolveum.midpoint.prism.query.AndFilter;
import com.evolveum.midpoint.prism.query.GreaterFilter;
import com.evolveum.midpoint.prism.query.LessFilter;
import com.evolveum.midpoint.prism.query.ObjectFilter;
import com.evolveum.midpoint.prism.query.ObjectPaging;
import com.evolveum.midpoint.prism.query.ObjectQuery;
import com.evolveum.midpoint.prism.query.OrFilter;
import com.evolveum.midpoint.repo.api.RepositoryService;
import com.evolveum.midpoint.schema.constants.SchemaConstants;
import com.evolveum.midpoint.schema.result.OperationConstants;
import com.evolveum.midpoint.schema.result.OperationResult;
import com.evolveum.midpoint.schema.result.OperationResultStatus;
import com.evolveum.midpoint.schema.util.ObjectQueryUtil;
import com.evolveum.midpoint.task.api.Task;
import com.evolveum.midpoint.task.api.TaskCategory;
import com.evolveum.midpoint.task.api.TaskHandler;
import com.evolveum.midpoint.task.api.TaskManager;
import com.evolveum.midpoint.task.api.TaskRunResult;
import com.evolveum.midpoint.task.api.TaskRunResult.TaskRunResultStatus;
import com.evolveum.midpoint.util.DOMUtil;
import com.evolveum.midpoint.util.QNameUtil;
import com.evolveum.midpoint.util.exception.CommonException;
import com.evolveum.midpoint.util.exception.CommunicationException;
import com.evolveum.midpoint.util.exception.ConfigurationException;
import com.evolveum.midpoint.util.exception.ExpressionEvaluationException;
import com.evolveum.midpoint.util.exception.ObjectAlreadyExistsException;
import com.evolveum.midpoint.util.exception.ObjectNotFoundException;
import com.evolveum.midpoint.util.exception.SchemaException;
import com.evolveum.midpoint.util.exception.SecurityViolationException;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;
import com.evolveum.midpoint.xml.ns._public.common.common_2a.ActivationType;
import com.evolveum.midpoint.xml.ns._public.common.common_2a.FocusType;
import com.evolveum.midpoint.xml.ns._public.common.common_2a.LayerType;
import com.evolveum.midpoint.xml.ns._public.common.common_2a.ResourceType;
import com.evolveum.midpoint.xml.ns._public.common.common_2a.ShadowType;
import com.evolveum.midpoint.xml.ns._public.common.common_2a.UserType;

/**
 * 
 * @author Radovan Semancik
 *
 */
@Component
public class FocusValidityScannerTaskHandler extends AbstractSearchIterativeTaskHandler<UserType> {

	public static final String HANDLER_URI = SynchronizationConstants.NS_SYNCHRONIZATION_TASK_PREFIX + "/focus-validation-scanner/handler-2";

	private XMLGregorianCalendar lastRecomputeTimestamp;
	private XMLGregorianCalendar thisRecomputeTimestamp;
	
    @Autowired(required=true)
	private TaskManager taskManager;
	
	@Autowired(required=true)
	private RepositoryService repositoryService;
	
	@Autowired(required=true)
	private PrismContext prismContext;

    @Autowired(required = true)
    private ProvisioningService provisioningService;

    @Autowired(required = true)
    private Clockwork clockwork;
    
    @Autowired(required = true)
    private Clock clock;
    
    @Autowired
    private ChangeExecutor changeExecutor;
    	
	private static final transient Trace LOGGER = TraceManager.getTrace(FocusValidityScannerTaskHandler.class);

	public FocusValidityScannerTaskHandler() {
        super(UserType.class, "Focus validity scan", OperationConstants.FOCUS_VALIDITY_SCAN);
    }

	@PostConstruct
	private void initialize() {
		taskManager.registerHandler(HANDLER_URI, this);
	}
	
	@Override
	protected boolean initialize(TaskRunResult runResult, Task task, OperationResult opResult) {
		boolean cont = super.initialize(runResult, task, opResult);
		if (!cont) {
			return cont;
		}
		
		lastRecomputeTimestamp = null;
    	PrismProperty<XMLGregorianCalendar> lastRecomputeTimestampProperty = task.getExtension(SynchronizationConstants.LAST_RECOMPUTE_TIMESTAMP_PROPERTY_NAME);
        if (lastRecomputeTimestampProperty != null) {
            lastRecomputeTimestamp = lastRecomputeTimestampProperty.getValue().getValue();
        }
        
        thisRecomputeTimestamp = clock.currentTimeXMLGregorianCalendar();
		        
        return true;
	}
	
	@Override
	protected ObjectQuery createQuery(TaskRunResult runResult, Task task, OperationResult opResult) throws SchemaException {
		ObjectQuery query = new ObjectQuery();
		ObjectFilter filter;
		PrismObjectDefinition<FocusType> focusObjectDef = prismContext.getSchemaRegistry().findObjectDefinitionByCompileTimeClass(FocusType.class);
		
		if (lastRecomputeTimestamp == null) {
			filter = OrFilter.createOr(
						LessFilter.createLessFilter(new ItemPath(FocusType.F_ACTIVATION), focusObjectDef, 
								ActivationType.F_VALID_FROM, new PrismPropertyValue<XMLGregorianCalendar>(thisRecomputeTimestamp), true),
						LessFilter.createLessFilter(new ItemPath(FocusType.F_ACTIVATION), focusObjectDef, 
								ActivationType.F_VALID_TO, new PrismPropertyValue<XMLGregorianCalendar>(thisRecomputeTimestamp), true));
		} else {
			filter = OrFilter.createOr(
						AndFilter.createAnd(
							GreaterFilter.createGreaterFilter(new ItemPath(FocusType.F_ACTIVATION), focusObjectDef, 
									ActivationType.F_VALID_FROM, new PrismPropertyValue<XMLGregorianCalendar>(lastRecomputeTimestamp), false),
							LessFilter.createLessFilter(new ItemPath(FocusType.F_ACTIVATION), focusObjectDef, 
									ActivationType.F_VALID_FROM, new PrismPropertyValue<XMLGregorianCalendar>(thisRecomputeTimestamp), true)),
						AndFilter.createAnd(
							GreaterFilter.createGreaterFilter(new ItemPath(FocusType.F_ACTIVATION), focusObjectDef, 
									ActivationType.F_VALID_TO, new PrismPropertyValue<XMLGregorianCalendar>(lastRecomputeTimestamp), false),
							LessFilter.createLessFilter(new ItemPath(FocusType.F_ACTIVATION), focusObjectDef, 
									ActivationType.F_VALID_TO, new PrismPropertyValue<XMLGregorianCalendar>(thisRecomputeTimestamp), true)));			
		}
		
		query.setFilter(filter);
		return query;
	}
	
	@Override
	protected AbstractSearchIterativeResultHandler<UserType> createHandler(TaskRunResult runResult, final Task task,
			OperationResult opResult) {
		
		AbstractSearchIterativeResultHandler<UserType> handler = new AbstractSearchIterativeResultHandler<UserType>(
				task, FocusValidityScannerTaskHandler.class.getName(), "recompute", "recompute task") {
			@Override
			protected boolean handleObject(PrismObject<UserType> user, OperationResult result) throws CommonException {
				recomputeUser(user, task, result);
				return true;
			}
		};
		
		return handler;
	}

	private void recomputeUser(PrismObject<UserType> user, Task task, OperationResult result) throws SchemaException, 
			ObjectNotFoundException, ExpressionEvaluationException, CommunicationException, ObjectAlreadyExistsException, 
			ConfigurationException, PolicyViolationException, SecurityViolationException {
		LOGGER.trace("Recomputing user {}", user);

		LensContext<UserType, ShadowType> syncContext = LensUtil.createRecomputeContext(UserType.class, user, prismContext, provisioningService);
		LOGGER.trace("Recomputing of user {}: context:\n{}", user, syncContext.dump());
		clockwork.run(syncContext, task, result);
		LOGGER.trace("Recomputing of user {}: {}", user, result.getStatus());
	}

    @Override
    public String getCategoryName(Task task) {
        return TaskCategory.USER_RECOMPUTATION;
    }

    @Override
    public List<String> getCategoryNames() {
        return null;
    }
}