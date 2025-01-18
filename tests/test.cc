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

class Data {
	using Tuple = std::tuple<std::string, // name paramenter configuration
			   std::string, // expected results
			   std::vector<std::string>, // eq patterns
			   std::vector<std::string> // values patterns
			  >;

	std::vector<Tuple> collection;

	void populate (void) {
		std::vector<std::string> test_name_eq;
		std::vector<std::string> test_groups;

		test_name_eq.emplace_back("=");
		test_name_eq.emplace_back("= ");
		test_name_eq.emplace_back("= \t");
		test_name_eq.emplace_back(" =");
		test_name_eq.emplace_back(" = ");
		test_name_eq.emplace_back(" =  ");
		test_name_eq.emplace_back("  =");
		test_name_eq.emplace_back("  = ");
		test_name_eq.emplace_back("  =  ");

		test_groups.emplace_back("[9 9 3]");
		test_groups.emplace_back("[9 9 3 ]");
		test_groups.emplace_back("[ 9 9 3]");
		test_groups.emplace_back("[ 9 9 3 ]");
		test_groups.emplace_back("[  9  9  3  ]");

		collection.emplace_back(std::make_tuple("pool_mon", "pool_mon 9 9 3", test_name_eq, test_groups));
		collection.emplace_back(std::make_tuple("pool_dns", "pool_dns 9 9 3", test_name_eq, test_groups));
	}
public:
	Data () { populate(); };

	std::vector<Tuple> get_test_collection (void) const {
		return collection;
	} 
};

//
// Name: UnrollCheck
//
// Description: C++20 concept just to be aware about the data unroll_pass_tests function can handles as return value
//
// Input:
//
// Return:
//
template <typename T>
concept UnrollCheck = std::same_as<T, std::string>;

//
// Name: unroll_pass_tests
//
// Description: Prepare valid candidate tests
//
// Input:
//   Data - The data with string to be assembled
//
// Return:
//   Coro::Geko<T> Object
//
template<UnrollCheck T> Coro::Geko<T> unroll_pass_tests(const Data &in) {
	for (const auto & test : in.get_test_collection()) {
		co_yield get<0>(test);
		co_yield get<1>(test);
		for (const auto & eq : get<2>(test)) {
			T pattern (get<0>(test));
			pattern += eq;

			for (const auto & group : get<3>(test)) {
	   			T full_pattern = pattern + group;  // Concatenate test_groups to pattern
				co_yield full_pattern;
	   		}

			pattern.erase(pattern.size() - eq.size(), eq.size());  // Remove the last appended eq
		}

		co_yield "";
	}
}

//
// Name: boolean_checks
//
// Description: Check if a string is "on" or "off" and returns a boolean true in both cases
//
// Input:
//   bool_setup_str - The string to check
//
// Return:
//   bool
//
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

		Data d;

		// Explicit Template Argument 
		Coro::Geko<std::string> sa = unroll_pass_tests<std::string>(d);

		std::string paramname;
		std::string expected;
		std::string virtual_conf;

		while (true)
		{
			if (sa.next())
			{
				paramname.assign(sa.get_yielded_value());

				if (sa.next()) expected.assign(sa.get_yielded_value());
				else break;
			}
			else break;

			std::stringstream ss;
			std::ifstream ifs;

			assert(not ifs.is_open());

			while (sa.next()) {
				std::string yielded = sa.get_yielded_value();
 
				if (yielded.empty())
				{
					auto so = setup->parser<std::string>(ifs, ss);

					while (so.next())
					{
						std::cout << so.get_yielded_value() << " -> " << expected << std::endl;
						REQUIRE(expected.compare(so.get_yielded_value()) == 0);
					}

					break;
				}

				std::string a {"  #"};
				std::random_device rd;
				std::mt19937 gen {rd()};
				std::ranges::shuffle(a, gen);

				ss << yielded << a << "comment" << std::endl;
			}
		}

		std::vector<std::pair<Setup::parname_t, std::string>> str_pnames;
		str_pnames.emplace_back(std::make_pair(Setup::locale, "en_US.UTF-8"));
		str_pnames.emplace_back(std::make_pair(Setup::direct, ""));
		str_pnames.emplace_back(std::make_pair(Setup::skbmode, ""));
		str_pnames.emplace_back(std::make_pair(Setup::wanifindex, "waninterface0.5"));
		str_pnames.emplace_back(std::make_pair(Setup::sshifindex, "vlan4094"));
		str_pnames.emplace_back(std::make_pair(Setup::dmzifindex, "vlan4093"));
		str_pnames.emplace_back(std::make_pair(Setup::lanifindex, "laninterface98.8.99"));
		str_pnames.emplace_back(std::make_pair(Setup::lockdir, "/tmp"));
		str_pnames.emplace_back(std::make_pair(Setup::rundir, "/tmp"));
		str_pnames.emplace_back(std::make_pair(Setup::logdir, "/tmp"));

		std::ranges::for_each(str_pnames, [&] (const std::pair<Setup::parname_t, std::string> & v) {
			Setup::vdata_t vdata = setup->conf_getval(v.first);
			auto *s = std::get_if<std::string>(&vdata);

			if (v.first == Setup::direct or v.first == Setup::skbmode)
			{
				if (s) REQUIRE(boolean_checks(s->c_str()) == true);
			}
			else if (s) REQUIRE(s->compare(v.second) == 0);
		});

		delete setup;
}
