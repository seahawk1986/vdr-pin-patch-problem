/*
 * vdr-menuorg - A plugin for the Linux Video Disk Recorder
 * Copyright (c) 2007 - 2008 Tobias Grimm <vdr@e-tobi.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id$
 *
 */

#ifndef __MENUORGPATCH_H
#define __MENUORGPATCH_H

#include "mainmenuitemsprovider.h"

class MenuOrgPatch
{
    private:
        static IMainMenuItemsProvider* _mainMenuItemsProvider;

    private:
        static IMainMenuItemsProvider* MainMenuItemsProvider()
        {
            if (!_mainMenuItemsProvider)
            {
                IMainMenuItemsProvider* mainMenuItemsProvider;

                if (cPluginManager::CallFirstService(MENU_ITEMS_PROVIDER_SERVICE_ID, &mainMenuItemsProvider))
                {
                    _mainMenuItemsProvider = mainMenuItemsProvider;
                }
            }
            return _mainMenuItemsProvider;
        }

    public:
        static bool IsCustomMenuAvailable()
        {
            return (MainMenuItemsProvider() != NULL) && (MainMenuItemsProvider()->IsCustomMenuAvailable());
        }

        static void EnterRootMenu()
        {
            if (MainMenuItemsProvider())
            {
                MainMenuItemsProvider()->EnterRootMenu();
            }
        }

        static bool LeaveSubMenu()
        {
            if (MainMenuItemsProvider())
            {
                return MainMenuItemsProvider()->LeaveSubMenu();
            }
            return false;
        }

        static void EnterSubMenu(cOsdItem* item)
        {
            if (MainMenuItemsProvider())
            {
                MainMenuItemsProvider()->EnterSubMenu(item);
            }
        }

        static MenuItemDefinitions* MainMenuItems()
        {
            if (MainMenuItemsProvider())
            {
                return MainMenuItemsProvider()->MainMenuItems();
            }
            return NULL;
        }

        static cOsdMenu* Execute(cOsdItem* item)
        {
            if (MainMenuItemsProvider())
            {
                return MainMenuItemsProvider()->Execute(item);
            }
            return NULL;
        }
};

IMainMenuItemsProvider* MenuOrgPatch::_mainMenuItemsProvider = NULL;

#endif //__MENUORGPATCH_H
