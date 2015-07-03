/*
 * Copyright (c) 2015 Evolveum
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
package com.evolveum.midpoint.provisioning.test.impl;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.testng.annotations.Test;

import com.evolveum.midpoint.prism.PrismObject;
import com.evolveum.midpoint.prism.crypto.EncryptionException;
import com.evolveum.midpoint.provisioning.ucf.impl.ConnectorFactoryIcfImpl;
import com.evolveum.midpoint.schema.GetOperationOptions;
import com.evolveum.midpoint.schema.result.OperationResult;
import com.evolveum.midpoint.test.util.TestUtil;
import com.evolveum.midpoint.util.exception.SchemaException;
import com.evolveum.midpoint.xml.ns._public.common.common_3.CredentialsType;
import com.evolveum.midpoint.xml.ns._public.common.common_3.PasswordType;
import com.evolveum.midpoint.xml.ns._public.common.common_3.ShadowType;
import com.evolveum.prism.xml.ns._public.types_3.ProtectedStringType;

/**
 * Almost the same as TestDummy but with some extra things, such as:
 * readable password
 * 
 * @author Radovan Semancik
 *
 */
@ContextConfiguration(locations = "classpath:ctx-provisioning-test-main.xml")
@DirtiesContext
public class TestDummyExtra extends TestDummy {
	
	public static final String TEST_DIR = "src/test/resources/impl/dummy-extra/";
	public static final String RESOURCE_DUMMY_FILENAME = TEST_DIR + "resource-dummy.xml";

	@Override
	protected String getResourceDummyFilename() {
		return RESOURCE_DUMMY_FILENAME;
	}

	@Override
	protected void checkAccountWill(ShadowType shadow, OperationResult result) throws SchemaException, EncryptionException {
		super.checkAccountWill(shadow, result);
		assertPassword(shadow, "3lizab3th");
	}
	
	@Test
	public void testFakeToEnableDebug() {
		
	}
	
}
