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

#ifndef __MAINMENUITEMSPROVIDER_H
#define __MAINMENUITEMSPROVIDER_H

#include <vector>

class cOsdItem;
class cOsdMenu;

class IMenuItemDefinition
{
    public:
        virtual ~IMenuItemDefinition() {};
        virtual bool IsCustomOsdItem() = 0;
        virtual bool IsPluginItem() = 0;
        virtual bool IsSeparatorItem() = 0;
        virtual cOsdItem* CustomOsdItem() = 0;
        virtual const char* PluginMenuEntry() = 0;
        virtual bool IsSelected() = 0;
        virtual int PluginIndex() = 0;
};

typedef std::vector<IMenuItemDefinition*> MenuItemDefinitions;

#define MENU_ITEMS_PROVIDER_SERVICE_ID "MenuOrgPatch-v0.4.2::MainMenuItemsProvider"

class IMainMenuItemsProvider
{
    public:
        virtual ~IMainMenuItemsProvider() {};
        virtual bool IsCustomMenuAvailable() = 0;
        virtual MenuItemDefinitions* MainMenuItems() = 0;
        virtual void EnterRootMenu() = 0;
        virtual void EnterSubMenu(cOsdItem* item) = 0;
        virtual bool LeaveSubMenu() = 0;
        virtual cOsdMenu* Execute(cOsdItem* item) = 0;
};

#endif //__MAINMENUITEMSPROVIDER_H
