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

#ifndef __CONST_INCLUDED_H
#define __CONST_INCLUDED_H

#include <algorithm>
#include <array>
#include <cassert>
#include <deque>
#include <errno.h>
#include <format>
#include <forward_list>
#include <functional>
#include <iostream>
#include <limits.h>
#include <list>
#include <locale.h>
#include <memory>
#include <optional>
#include <random>
#include <ranges>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string_view>
#include <variant>
#include <type_traits>
// #include <bitmask.h>

// Local libraries
#include "templates.h"

#define _XOPEN_SOURCE_EXTENDED 1

// for dump to log more informations than normal procedure
// WARNING: TESTING PURPOSE. DON'T CHANGE THIS VALUE ONCE INDEX IS CREATED
// #define DEBUG // enable from compiler

// Preprocessor macro (first two lines only for knowledge)
// #define GET_MACRO_OVERLOADING(_1,_2,_3,NAME,...) NAME
// #define FOO(...) GET_MACRO_OVERLOADING(__VA_ARGS__, FOO3, FOO2)(__VA_ARGS__)

// IT'S NOT ENOUGH TO MODIFY THE FOLLOWING TYPEDEFS HERE
// YOU HAVE TO MODIFY THEM ALSO IN SOME PARTS OF THE CODE
// (ie: printf "%l", atol())

// #define EOF (-1) defined in stdio.h
#define byte_t uint8_t
#define hash_t uint32_t
#define longhash_t uint64_t
#define internal_long_int_t int64_t // long int
#define internal_long_uint_t uint64_t // unsigned long int
#define internal_long_double_t long double

// WARNING:
// For technical reasons, IDs cannot have values major of (it's theoretical max value - CONF_HASH_RESERVE)
// TODO insert checks inside 'cbot-reset'

// cleartext dirname/filename size
#define ename_size_t uint8_t // unsigned 8 bits -> unsigned char

// this types MUST BE unsigned
#define bucket_t uint32_t // unsigned int
#define enameid_t uint16_t // unsigned short
#define boxid_t uint16_t // unsigned short

#define MAX_STR_LEN 256

// Loglevel constants
#define LOGLEVEL_QUIET 0
#define LOGLEVEL_NORMAL 1
#define LOGLEVEL_VERBOSE 2

// ANSI colors (for reporting)
#ifdef __linux__
#define RED "[31m"
#define LRE "[1;31m"
#define GRE "[32m"
#define LGR "[1;32m"
#define BRO "[33m"
#define LBR "[1;33m"
#define BLU "[34m"
#define LBL "[1;34m"
#define PUR "[35m"
#define LPU "[1;35m"
#define NOR "[0m"
#else
#define RED ""
#define LRE ""
#define GRE ""
#define LGR ""
#define BRO ""
#define LBR ""
#define BLU ""
#define LBL ""
#define PUR ""
#define LPU ""
#define NOR ""
#endif

// Numerical value of Non Blocking Space (multibyte char)
#define NBSP 160

// ASCII abbreviations
#define NUL 0 // Nul Character -> (semplificato per ragioni di leggibilita) dunque sostituirà: '\0'
#define ASCII_NUL 0 // NULL Char
#define ASCII_TB 9 // Orizzontal Tab
#define ASCII_NL 10 // New Line
#define ASCII_CR 13 // Carriage Return
#define ASCII_SP 32 // Space
#define ASCII_EM 33 // Exclamation mark (punto esclamativo)
#define ASCII_DQ 34 // Double quotes
#define ASCII_NU 35 // Number (cancelletto)
#define ASCII_DO 36 // Dollar
#define ASCII_PE 37 // Procenttecken (percentuale)
#define ASCII_AM 38 // Ampersand
#define ASCII_QU 39 // Quote
#define ASCII_AS 42 // Asterisk
#define ASCII_PL 43 // Plus (simbolo più)
#define ASCII_CM 44 // Comma (Virgola)
#define ASCII_HM 45 // Hyphen-minus/Score (simbolo meno)
#define ASCII_DT 46 // Dot (punto)
#define ASCII_SL 47 // Slash
#define ASCII_CO 58 // Double Point
#define ASCII_SC 59 // Semicolon (punto e virgola)
#define ASCII_MI 60 // Minor
#define ASCII_EQ 61 // Equal
#define ASCII_MA 62 // Major
#define ASCII_QM 63 // Question Mark (punto interrogativo)
#define ASCII_AT 64 // At (chiocciola)
#define ASCII_SBO 91 // Square Brakets Open (parentesi quadra aperta)
#define ASCII_BS 92 // Back slash
#define ASCII_SBC 93 // Square Brakets Close (parentesi quadra close)
#define ASCII_US 95 // UnderScore
#define ASCII_PP 124 // Pipe
#define ASCII_ST 126 // Single Tilde (comunemente chiamata tilde)

#endif // __CONST_INCLUDED_h
