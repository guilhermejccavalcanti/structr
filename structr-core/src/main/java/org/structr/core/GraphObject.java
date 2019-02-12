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
package org.structr.core;

import java.util.Date;
import java.util.List;
import java.util.Map;
import org.neo4j.graphdb.PropertyContainer;
import org.structr.common.SecurityContext;
import org.structr.common.error.ErrorBuffer;
import org.structr.common.error.FrameworkException;
import org.structr.core.entity.AbstractNode;
import org.structr.core.entity.AbstractRelationship;
import org.structr.core.graph.NodeInterface;
import org.structr.core.graph.RelationshipInterface;
import org.structr.core.property.BooleanProperty;
import org.structr.core.property.ISO8601DateProperty;
import org.structr.core.property.Property;
import org.structr.core.property.PropertyKey;
import org.structr.core.property.PropertyMap;
import org.structr.core.property.StringProperty;
import org.structr.core.property.TypeProperty;
import org.structr.core.property.UuidProperty;
import org.structr.schema.action.ActionContext;


/**
 * A common base class for {@link AbstractNode} and {@link AbstractRelationship}.
 *
 * @author Christian Morgner
 */
public interface GraphObject {

	public static final Property<String>  base                        = new StringProperty("base");
	public static final Property<String>  type                        = new TypeProperty();
	public static final Property<String>  id                          = new UuidProperty();

	public static final Property<Date>    createdDate                 = new ISO8601DateProperty("createdDate").indexed().unvalidated().readOnly().writeOnce();
	public static final Property<Date>    lastModifiedDate            = new ISO8601DateProperty("lastModifiedDate").passivelyIndexed().unvalidated().readOnly();
	public static final Property<Boolean> visibleToPublicUsers        = new BooleanProperty("visibleToPublicUsers").passivelyIndexed();
	public static final Property<Boolean> visibleToAuthenticatedUsers = new BooleanProperty("visibleToAuthenticatedUsers").passivelyIndexed();
	public static final Property<Date>    visibilityStartDate         = new ISO8601DateProperty("visibilityStartDate");
	public static final Property<Date>    visibilityEndDate           = new ISO8601DateProperty("visibilityEndDate");

	// ----- methods common to both types -----
	/**
	 * Returns the database ID of this graph object.
	 *
	 * @return the database ID
	 */
	public long getId();

	/**
	 * Returns the UUID of this graph object.
	 *
	 * @return the UUID
	 */
	public String getUuid();

	/**
	 * Returns the type of this graph object.
	 *
	 * @return the type
	 */
	public String getType();

	/**
	 * Sets the security context to be used by this entity.
	 *
	 * @param securityContext
	 */
	public void setSecurityContext(final SecurityContext securityContext);

	/**
	 * Returns the SecurityContext associated with this instance.
	 *
	 * @return the security context
	 */
	public SecurityContext getSecurityContext();

	/**
	 * Returns the underlying property container for this graph object.
	 *
	 * @return property container
	 */
	public PropertyContainer getPropertyContainer();

	/**
	 * Returns the property set for the given view as an Iterable.
	 *
	 * @param propertyView
	 * @return the property set for the given view
	 */
	public Iterable<PropertyKey> getPropertyKeys(String propertyView);

	/**
	 * Sets the property with the given key to the given value.
	 *
	 * @param <T>
	 * @param key the property key to set
	 * @param value the value to set
	 * @throws FrameworkException
	 */
	public <T> void setProperty(final PropertyKey<T> key, T value) throws FrameworkException;

	/**
	 * Returns the (converted, validated, transformed, etc.) property for the given
	 * property key.
	 *
	 * @param <T>
	 * @param propertyKey the property key to retrieve the value for
	 * @return the converted, validated, transformed property value
	 */
	public <T> T getProperty(final PropertyKey<T> propertyKey);

	/**
	 * Returns the (converted, validated, transformed, etc.) property for the given
	 * property key with the given filter applied to it.
	 *
	 * @param <T>
	 * @param propertyKey the property key to retrieve the value for
	 * @param filter the filter to apply to all properties
	 * @return the converted, validated, transformed property value
	 */
	public <T> T getProperty(final PropertyKey<T> propertyKey, final org.neo4j.helpers.Predicate<GraphObject> filter);

	/**
	 * Returns the property value for the given key as a Comparable
	 *
	 * @param <T>
	 * @param key the property key to retrieve the value for
	 * @return the property value for the given key as a Comparable
	 */
	public <T> Comparable getComparableProperty(final PropertyKey<T> key);

	/**
	 * Returns the property value for the given key that will be used
	 * for indexing.
	 *
	 * @param key the key to index the value for
	 * @return the property value for indexing
	 */
	public Object getPropertyForIndexing(final PropertyKey key);

	/**
	 * Removes the property value for the given key from this graph object.
	 *
	 * @param key the key to remove the value for
	 * @throws FrameworkException
	 */
	public void removeProperty(final PropertyKey key) throws FrameworkException;

	/**
	 * Returns the default sort key for this entity.
	 *
	 * @return the default sort key
	 */
	public PropertyKey getDefaultSortKey();

	/**
	 * Returns the default sort order for this entity.
	 *
	 * @return the default sort order
	 */
	public String getDefaultSortOrder();

	/**
	 * Unlock all read-only properties in this entity for a single <code>setProperty</code>
	 * call.
	 */
	public void unlockReadOnlyPropertiesOnce();

	// ----- callback methods -----
	/**
	 * Called when an entity of this type is created in the database. This method can cause
	 * the underlying transaction to be rolled back in case of an error, either by throwing
	 * an exception, or by returning false.
	 *
	 * @param securityContext the context in which the creation takes place
	 * @param errorBuffer the error buffer to put error tokens into
	 * @return true if the transaction can go on, false if an error occurred
	 * @throws FrameworkException
	 */
	public boolean onCreation(final SecurityContext securityContext, final ErrorBuffer errorBuffer) throws FrameworkException;

	/**
	 * Called when an entity of this type is modified. This method can cause the underlying
	 * transaction to be rolled back in case of an error, either by throwing an exception,
	 * or by returning false.
	 *
	 * @param securityContext the context in which the modification takes place
	 * @param errorBuffer the error buffer to put error tokens into
	 * @return true if the transaction can go on, false if an error occurred
	 * @throws FrameworkException
	 */
	public boolean onModification(final SecurityContext securityContext, final ErrorBuffer errorBuffer) throws FrameworkException;

	/**
	 * Called when an entity of this type is deleted. This method can cause the underlying
	 * transaction to be rolled back in case of an error, either by throwing an exception,
	 * or by returning false.
	 *
	 * @param securityContext the context in which the deletion takes place
	 * @param errorBuffer the error buffer to put error tokens into
	 * @param properties
	 * @return true if the transaction can go on, false if an error occurred
	 * @throws FrameworkException
	 */
	public boolean onDeletion(final SecurityContext securityContext, final ErrorBuffer errorBuffer, final PropertyMap properties) throws FrameworkException;

	/**
	 * Called when an entity was successfully created. Please note that this method
	 * will need to create its own toplevel transaction and can NOT cause the creation
	 * transaction to be rolled back.
	 *
	 * @param securityContext the context in which the creation took place
	 */
	public void afterCreation(final SecurityContext securityContext);

	/**
	 * Called when an entity was successfully modified. Please note that this method
	 * will need to create its own toplevel transaction and can NOT cause the modification
	 * transaction to be rolled back.
	 *
	 * @param securityContext the context in which the modification took place
	 */
	public void afterModification(final SecurityContext securityContext);

	/**
	 * Called when an entity was successfully deleted. Please note that this method
	 * has no access to the database entity since it is called _after_ the successful
	 * deletion.
	 *
	 * @param securityContext the context in which the deletion took place
	 * @param properties
	 */
	public void afterDeletion(final SecurityContext securityContext, final PropertyMap properties);

	/**
	 * Called when the owner of this entity was successfully modified. Please note
	 * that this method will run in its own toplevel transaction and can NOT prevent
	 * the owner modification.
	 *
	 * @param securityContext the context in which the owner modification took place
	 */
	public void ownerModified(final SecurityContext securityContext);

	/**
	 * Called when the permissions of this entity were successfully modified. Please note
	 * that this method will run in its own toplevel transaction and can NOT prevent the
	 * permission modification.
	 *
	 * @param securityContext the context in which the permission modification took place
	 */
	public void securityModified(final SecurityContext securityContext);

	/**
	 * Called when the location of this entity was successfully modified. Please note
	 * that this method will run in its own toplevel transaction and can NOT prevent the
	 * permission modification.
	 *
	 * @param securityContext the context in which the location modification took place
	 */
	public void locationModified(final SecurityContext securityContext);

	/**
	 * Called when a non-local modification occurred in the neighbourhood of this node.
	 *
	 * @param securityContext
	 */
	public void propagatedModification(final SecurityContext securityContext);

	public void addToIndex();
	public void updateInIndex();
	public void removeFromIndex();
	public void indexPassiveProperties();

	public String getPropertyWithVariableReplacement(final SecurityContext securityContext, final ActionContext renderContext, final PropertyKey<String> key) throws FrameworkException;
	public Object evaluate(final SecurityContext securityContext, final String key, final String defaultValue) throws FrameworkException;
	public Object invokeMethod(final String methodName, final Map<String, Object> parameters, final boolean throwExceptionForUnknownMethods) throws FrameworkException;


	// ----- Cloud synchronization and replication -----
	public List<GraphObject> getSyncData() throws FrameworkException;

	public boolean isNode();
	public boolean isRelationship();

	public NodeInterface getSyncNode();
	public RelationshipInterface getSyncRelationship();

	public void updateFromPropertyMap(final Map<String, Object> properties) throws FrameworkException;
}
