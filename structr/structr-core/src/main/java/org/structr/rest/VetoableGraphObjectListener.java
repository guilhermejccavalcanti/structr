/*
 *  Copyright (C) 2011 Axel Morgner
 * 
 *  This file is part of structr <http://structr.org>.
 * 
 *  structr is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 * 
 *  structr is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with structr.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.structr.rest;

import javax.servlet.http.HttpServletRequest;
import org.structr.core.GraphObject;

/**
 * An interface that allows you to be notified when a
 * GraphObject is modified in the context of a REST call, with
 * the option to forbid the modification.
 * In order to use this interface, you must register your
 * implementation as an init parameter to the JsonRestServlet
 * declaration in your web.xml file.
 *
 * @author Christian Morgner
 */
public interface VetoableGraphObjectListener {

	public boolean mayDelete(GraphObject graphObject, HttpServletRequest request);
	public boolean mayModify(GraphObject graphObject, HttpServletRequest request);
}
