/**
 * Copyright (C) 2010-2015 Structr GmbH
 *
 * This file is part of Structr <http://structr.org>.
 *
 * Structr is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Structr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Structr.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.structr.files.ssh.shell;

import java.io.IOException;
import java.util.List;
import org.structr.common.Permission;
import org.structr.common.error.FrameworkException;
import org.structr.core.app.App;
import org.structr.core.app.StructrApp;
import org.structr.core.graph.Tx;
import org.structr.files.ssh.StructrShellCommand;
import org.structr.web.entity.AbstractFile;
import org.structr.web.entity.Folder;

/**
 *
 *
 */
public class LsCommand extends NonInteractiveShellCommand {

	// http://invisible-island.net/xterm/ctlseqs/ctlseqs.html

	@Override
	public void execute(final StructrShellCommand parent) throws IOException {

		final App app = StructrApp.getInstance();

		try (final Tx tx = app.tx()) {

			final Folder currentFolder = parent.getCurrentFolder();
			if (currentFolder != null) {

				listFolder(parent, currentFolder.getProperty(AbstractFile.children));

			} else {

				listFolder(parent, app.nodeQuery(AbstractFile.class).and(AbstractFile.parent, null).getAsList());
			}

			tx.success();

		} catch (FrameworkException fex) {

			fex.printStackTrace();
		}
	}

	// ----- private methods -----
	private void listFolder(final StructrShellCommand parent, final List<AbstractFile> folder) throws FrameworkException, IOException {

		for (final AbstractFile child : folder) {

			if (parent.isAllowed(child, Permission.read, false)) {

				if (child instanceof Folder) {

					term.setBold(true);
					term.setTextColor(4);
					term.print(child.getName() + "  ");
					term.setTextColor(7);
					term.setBold(false);

				} else {

					term.print(child.getName() + "  ");
				}
			}
		}

		if (!folder.isEmpty()) {
			term.println();
		}
	}
}
