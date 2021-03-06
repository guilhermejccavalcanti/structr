/**
 * Copyright (C) 2010-2014 Morgner UG (haftungsbeschränkt)
 *
 * This file is part of Structr <http://structr.org>.
 *
 * Structr is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Structr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Structr.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.structr.rest.test;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.filter.log.ResponseLoggingFilter;
import org.structr.rest.common.StructrRestTest;
import static org.hamcrest.Matchers.*;

/**
 *
 * @author Axel Morgner
 */
public class SchemaResourceTest extends StructrRestTest {

	public void testCustomSchema0() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType0\", \"_foo\": \"String\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].type", equalTo("String"))
				.body("result[-1].jsonName", equalTo("foo"))
				.body("result[-1].declaringClass", equalTo("class org.structr.dynamic.TestType0"))

			.when()
				.get("/_schema/TestType0/ui");

	}

	public void testCustomSchema1() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType1\", \"_foo\": \"fooDb|String\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].type", equalTo("String"))
				.body("result[-1].jsonName", equalTo("foo"))
				.body("result[-1].dbName", equalTo("fooDb"))
				.body("result[-1].declaringClass", equalTo("class org.structr.dynamic.TestType1"))

			.when()
				.get("/_schema/TestType1/ui");

	}

	public void testCustomSchema2() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType2\", \"_foo\": \"+String\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].type", equalTo("String"))
				.body("result[-1].dbName", equalTo("foo"))
				.body("result[-1].notNull", equalTo(true))

			.when()
				.get("/_schema/TestType2/ui");

	}

	public void testCustomSchema3() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType3\", \"_foo\": \"String!\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].dbName", equalTo("foo"))
				.body("result[-1].unique", equalTo(true))

			.when()
				.get("/_schema/TestType3/ui");

	}

	public void testCustomSchema4() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType4\", \"_foo\": \"+String!\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].dbName", equalTo("foo"))
				.body("result[-1].unique", equalTo(true))
				.body("result[-1].notNull", equalTo(true))

			.when()
				.get("/_schema/TestType4/ui");

	}

	public void testCustomSchema5() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType5\", \"_foo\": \"String(bar)\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].format", equalTo("bar"))

			.when()
				.get("/_schema/TestType5/ui");

	}

	public void testCustomSchema6() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType6\", \"_foo\": \"String!(bar)\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].dbName", equalTo("foo"))
				.body("result[-1].unique", equalTo(true))
				.body("result[-1].format", equalTo("bar"))

			.when()
				.get("/_schema/TestType6/ui");

	}

	public void testCustomSchema7() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType7\", \"_foo\": \"String[text/html]\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].dbName", equalTo("foo"))
				.body("result[-1].contentType", equalTo("text/html"))

			.when()
				.get("/_schema/TestType7/ui");

	}

	public void testCustomSchema8() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType8\", \"_foo\": \"String[text/html]!\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].dbName", equalTo("foo"))
				.body("result[-1].contentType", equalTo("text/html"))
				.body("result[-1].unique", equalTo(true))

			.when()
				.get("/_schema/TestType8/ui");

	}

	public void testCustomSchema9() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType9\", \"_foo\": \"+String[text/html]!\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].dbName", equalTo("foo"))
				.body("result[-1].contentType", equalTo("text/html"))
				.body("result[-1].notNull", equalTo(true))

			.when()
				.get("/_schema/TestType9/ui");

	}

	
	public void testCustomSchema10() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType10\", \"_foo\": \"+String[text/html]!\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].dbName", equalTo("foo"))
				.body("result[-1].contentType", equalTo("text/html"))
				.body("result[-1].notNull", equalTo(true))

			.when()
				.get("/_schema/TestType10/ui");

	}

	public void testCustomSchema11() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType11\", \"_foo\": \"+String[text/html]!([a-f0-9]{32}):xyz\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].dbName", equalTo("foo"))
				.body("result[-1].contentType", equalTo("text/html"))
				.body("result[-1].notNull", equalTo(true))
				.body("result[-1].format", equalTo("[a-f0-9]{32}"))
				.body("result[-1].defaultValue", equalTo("xyz"))

			.when()
				.get("/_schema/TestType11/ui");

	}

	public void testCustomSchema12() {
		
		createEntity("/schema_node", "{ \"name\": \"TestType12\", \"_foo\": \"+Date!(yyyy-MM-dd)\" }");

		RestAssured
		    
			.given()
				.contentType("application/json; charset=UTF-8")
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(200))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(201))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(400))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(404))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(422))
				.filter(ResponseLoggingFilter.logResponseIfStatusCodeIs(500))
			
			.expect()
				.statusCode(200)

				.body("result",	      hasSize(14))
				.body("result_count", equalTo(14))
				.body("result[-1].dbName", equalTo("foo"))
				.body("result[-1].type", equalTo("Date"))
				.body("result[-1].notNull", equalTo(true))
				.body("result[-1].format", equalTo("yyyy-MM-dd"))

			.when()
				.get("/_schema/TestType12/ui");

	}

}
