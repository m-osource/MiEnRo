// SPDX-License-Identifier: GPL-2.0
/***************************************************************************
 *          (C) Copyright 2023 - Marco Giuseppe Spiga                      *
 ***************************************************************************
 *                                                                         *
 *  This file is part of MInimal ENterprise ROuter.                        *
 *                                                                         *
 *  MIENRO is free software: you can redistribute it and/or modify         *
 *  it under the terms of the GNU General Public License as published by   *
 *  the Free Software Foundation, either version 2 of the License, or      *
 *  any later version.                                                     *
 *                                                                         *
 *  MIENRO is distributed in the hope that it will be useful,              *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *  GNU General Public License for more details.                           *
 *                                                                         *
 *  You should have received a copy of the GNU General Public License      *
 *  along with this software. If not, see <http://www.gnu.org/licenses/>.  *
 *                                                                         *
 **************************************************************************/

// Warning: with latest versions there's no need to include this macro and use #include <catch2/catch_all.hpp> instead 
// #define CATCH_CONFIG_MAIN

#include "mcommon.h"
#include "Setup.h"
#include "Mienro.h"
#include <catch2/catch_test_macros.hpp>
// #include <catch/catch.hpp>
#include <sys/mman.h> // mmap munmap

extern const char *projectname;
extern const char *_color;
extern sig_atomic_t _signal;
extern sig_atomic_t _signal_quit;
extern program_t progid;
extern bool ischild;
extern bool disclog;
extern int map_wan_fd[MAX_MAPS];
extern int map_ctr_fd[MAX_MAPS];
extern int map_lan_fd[MAX_MAPS];
extern int map_pinned_fd[MAX_MAPS];

static int Factorial( int number ) {
   return number <= 1 ? number : Factorial( number - 1 ) * number;  // fail
// return number <= 1 ? 1      : Factorial( number - 1 ) * number;  // pass
}

bool boolean_checks( const char *bool_setup_str )
{
			if (strnlen(bool_setup_str, 3) == 2 && strncmp(bool_setup_str, "on", 2) == 0)
				return true;
			else if (strnlen(bool_setup_str, 4) == 3 && strncmp(bool_setup_str, "off", 3) == 0)
				return true;

			return false;
}

const int __argc = 3;
const char *__argv[__argc] = {"checks", "-c", "./tests/mienro.tests.conf"};

TEST_CASE("Test Setup Class") {

	//	int err;
		pid_t pid = 0;

	//	srand(time(NULL));

		// load startup configuration
		Setup *setup = new Setup ("UT");

		// load command line options and parse file configuration
		if (setup->parseconf((int)__argc, (char **)__argv) == EXIT_FAILURE)
		{
			BADINIT;
			exit(EXIT_FAILURE);
		}

		// set signals, drop admin privileges, create pid file // use whe and if needed
		if (setup->prepare(pid) == EXIT_FAILURE)
		{
			BADINIT;
			exit(EXIT_FAILURE);
		}

		REQUIRE(strncmp(setup->conf_getval(Setup::locale).strval, "en_US.UTF-8", 11) == 0);
		REQUIRE(boolean_checks(setup->conf_getval(Setup::direct).strval) == true);
		REQUIRE(boolean_checks(setup->conf_getval(Setup::skbmode).strval) == true);
		REQUIRE(strncmp(setup->conf_getval(Setup::wanifindex).strval, "waninterface0.5", 15) == 0);
		REQUIRE(strncmp(setup->conf_getval(Setup::sshifindex).strval, "vlan4094", 8) == 0);
		REQUIRE(strncmp(setup->conf_getval(Setup::dmzifindex).strval, "vlan4093", 8) == 0);
		REQUIRE(strncmp(setup->conf_getval(Setup::lanifindex).strval, "laninterface98.8.99", 19) == 0);
		REQUIRE(strncmp(setup->conf_getval(Setup::lockdir).strval, "/tmp", 4) == 0);
		REQUIRE(strncmp(setup->conf_getval(Setup::rundir).strval, "/tmp", 4) == 0);
		REQUIRE(strncmp(setup->conf_getval(Setup::logdir).strval, "/tmp", 4) == 0);
		REQUIRE(setup->conf_getval(Setup::lbhf).longval == 0x00000007);

		delete setup;
}
