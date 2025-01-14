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

#ifndef __TEMPLATES_INCLUDED_H
#define __TEMPLATES_INCLUDED_H

// System libraries
#include <openssl/objects.h>
// #include <typeinfo>
// #include <typeindex>
#include <coroutine>
#include <thread>

using namespace std;

// Local libraries
// #include "const.h"
// #include "cleanup.h"
// #include "pthread.h"
// #include "atomic"

// Preprocessor macros
#ifdef DEBUG
#define FCALLOC(type, am, size) FCloudAllocator<type>(am, size, (const char *)__FILE__, __LINE__)
#define FCREALLOC(type, type2, oldbuf, oldsize, newsize) FCloudReAllocator<type, type2>(oldbuf, oldsize, newsize, (const char *)__FILE__, __LINE__)
#else
#define FCALLOC(type, am, size) FCloudAllocator<type>(am, size)
#define FCREALLOC(type, type2, oldbuf, oldsize, newsize) FCloudReAllocator<type, type2>(oldbuf, oldsize, newsize)
#endif

//
// Name: Coro
//
// Description: Namespace for coroutines
//
// Input:
//
// Return:
//
namespace Coro {
	// A task-like object (arbitrarily called Geko (Generic Coroutine)) to simulate an async delay, but now with manual resumption using co_resume
	template<typename T> struct Geko {
		struct promise_type { // The promise_type is essential for the coroutine machinery in C++
			// get_return_object(): returns an instance of Geko, which represents the task that the coroutine is performing.
			// It initializes a coroutine handle (handle_type) from the promise object.
			Geko get_return_object() { return Geko{ handle_type::from_promise(*this)}; }

			// Required by coroutine_handle:
			// initial_suspend(): is called when the coroutine starts. The return value std::suspend_always means that the coroutine will immediately suspend its execution.
			std::suspend_always initial_suspend() {
				// std::cout << "Task starting...\n";
				return {};  // Suspend immediately when the coroutine starts
			}

			// Required by coroutine_handle:
			// final_suspend(): is called when the coroutine finishes executing its main body. It suspends the coroutine one last time and prints "Task finished!" before the coroutine exits.
			std::suspend_always final_suspend() noexcept {
				// std::cout << "Task finished!\n";
				return {};  // Suspend at the end of the coroutine
			}

			// Required by coroutine_handle:
			// unhandled_exception(): handles exceptions thrown within the coroutine. If an exception occurs, the program is terminated by calling std::terminate(). 
			void unhandled_exception() {
				std::terminate();  // If an exception occurs, terminate the program
			}

			// Required by coroutine_handle:
			// await_transform(): is called when co_await is used.
			// It receives the value passed to co_await (in this case, an integer representing seconds).
			std::suspend_always await_transform(int seconds) {
				std::cout << "Suspending for " << seconds << " seconds...\n";
				std::this_thread::sleep_for(std::chrono::seconds(seconds));  // Actual sleep for the given number of seconds
				return {};  // Continue the coroutine after the sleep
			}

			// Required by coroutine_handle:
			// yield_value(): yield a value to the caller
			std::suspend_always yield_value(T value) {
				yielded_value = value;  // Store the yielded value
				return {};  // Suspend and return the value to the caller
			}

			// get_yielded_value(): Provide a method to get the last yielded value (name of function is arbitrary)
			T get_yielded_value() const {
				 return yielded_value;
			}
 
private:
			T yielded_value;  // Store the last yielded value
		};

		// handle_type: alias defined for the type of handle that manages the coroutine. It’s a std::coroutine_handle pointing to promise_type.
		using handle_type = std::coroutine_handle<promise_type>;
		handle_type coro;

		// Constructor and Destructor:
		// The constructor takes a coroutine handle (handle_type h) and stores it in the coro member. The destructor destroys the coroutine handle when the task object is destructed.
		explicit Geko( handle_type h) : coro(h) {}
		~Geko() { coro.destroy(); }

		// Function to resume the coroutine and check if it's done
		bool next() {
			coro.resume(); // Resume the coroutine to the next suspension point
			return not coro.done(); // Return true if the coroutine isn't finished
		}

		// Add a method to retrieve the yielded value from the coroutine
		T get_yielded_value() const {
			return coro.promise().get_yielded_value();
		}

		// done(): object method that returns true if the coroutine has completed its execution, i.e., if it’s finished.
		bool done() {
			return coro.done();  // Check if the coroutine is finished
		}
	};
}

template <typename T, typename D>
std::unique_ptr<T, D> make_handle(T *handle, D deleter)
{
    return std::unique_ptr<T, D> { handle, deleter };
}

template <typename T>
uint8_t twoexp(T target)
{
    assert(target > 0);

    uint8_t exponent = 1;

    for (uint8_t c = 0; c < ((target - 1) % 8); c++)
    {
        exponent *= 2;
    }

    return exponent;
}

enum am_t
{ // alloc method enum
    NEW = 0,
    MALLOC = 1,
    CALLOC = 2
};

#ifdef DEBUG

//
// Name: FCloudAllocator
//
// Description:
//   Invoked by 'preprocessor macro FCalloc'
//   Alloc memory at pointer declared inside of function
//   N.B. i template se compilati attraverso moduli devono SEMPRE essere presenti nel file header
//
// Input:
//   method - enum 'am_t' allocation method
//   size - size of memory area
//   file - filename where function is called
//   line - line in the filename where function is called
//
// Return:
//   T *pointer
//
template <typename T>
T *FCloudAllocator(const am_t &method, const int &size, const char *file, const int &line)
{
    if (size <= 0)
    {
        fprintf(stderr, "%s %s %s %d FCALLOC: size %d of memory allocation is invalid!", __DATE__, __TIME__, file, line, size);
        return nullptr;
    }

    T *allocated = nullptr;

    bool bad_alloc_method = false;

    try
    {
        switch (method)
        {
        case (NEW):
            allocated = new T[size];
            break;
        case (MALLOC):
            allocated = (T *)malloc(size * sizeof(T));
            break;
        case (CALLOC):
            allocated = (T *)calloc(size, sizeof(T));
            break;
        default:
            bad_alloc_method = true;
            break;
        }
    }
    catch (std::bad_alloc &ba)
    {
        fprintf(stderr, "%s %s %s %d FCALLOC: bad_alloc caught %s!", __DATE__, __TIME__, file, line, ba.what());
        return nullptr;
    }

    if (bad_alloc_method == true)
    {
        fprintf(stderr, "%s %s %s %d FCALLOC: unsupported memory allocation method!", __DATE__, __TIME__, file, line);
        return nullptr;
    }

    if (allocated == nullptr)
    {
        fprintf(stderr, "%s %s %s %d FCALLOC: allocation failed!", __DATE__, __TIME__, file, line);
        return nullptr;
    }

    return allocated;
}

//
// Name: FCloudReAllocator
//
// Description:
//   Invoked by 'preprocessor macro' 'FCalloc'
//   Realloc memory for required new size
//
// Input:
//   oldbuf - the buffer to increase size
//   oldsize - the size of oldbuf
//   newsize - the needed size
//   file - filename where function is called
//   line - line in the filename where function is called
//
// Output:
//   size set to new size
//
// Return:
//   T *pointer to rellocated buffer
//
template <typename T, typename P>
T *FCloudReAllocator(T *oldbuf, const P size, const P required_size, const char *file, const int &line)
{
    if (oldbuf == nullptr)
    {
        fprintf(stderr, "%s %s FCREALLOC: memory (re)allocation is required for nullptr pointer file %s and line %d!", __DATE__, __TIME__, file, line);
        return nullptr;
    }

    T *newbuf = nullptr;

    unsigned short err_count = 0;
    const unsigned short max_realloc = 5;
    bool undefined_retries = false;

    try
    {
        if (required_size > size)
        {
            do
            {
                err_count++;
                newbuf = (T *)realloc(oldbuf, (required_size * sizeof(T)));

                if (newbuf == nullptr && err_count > max_realloc)
                    undefined_retries = true;
            } while (newbuf == nullptr); // ... fine processo assegnazione memoria puntatore 'base'
        }
    }
    catch (std::bad_alloc &ba)
    {
        fprintf(stderr, "%s %s FCREALLOC: bad_alloc caught %s at source file %s and line %d!", __DATE__, __TIME__, ba.what(), file, line);
        return nullptr;
    }

    if (undefined_retries == true)
    {
        fprintf(stderr, "%s %s FCREALLOC: Error (re)allocating memory for %u times at file %s and line %d!", __DATE__, __TIME__, err_count, file, line);
        return nullptr;
    }

    return newbuf;
}

#else

//
// Name: FCloudAllocator
//
// Description:
//   Invoked by 'preprocessor macro' 'FCalloc'
//   Alloc memory at pointer declared inside of function
//   N.B. i template se compilati attraverso moduli devono SEMPRE essere presenti nel file header
//
// Input:
//   method - enum 'am_t' allocation method
//   size - size of memory area
//
// Return:
//   T *pointer
//
template <typename T>
T *FCloudAllocator(const am_t &method, const int &size)
{
    if (size <= 0)
    {
        fprintf(stderr, "FCALLOC: size %d of memory allocation is invalid!", size);
        return nullptr;
    }

    T *allocated = nullptr;

    bool bad_alloc_method = false;

    try
    {

        switch (method)
        {
        case (NEW):
            allocated = new T[size];
            break;
        case (MALLOC):
            allocated = (T *)malloc(size * sizeof(T));
            break;
        case (CALLOC):
            allocated = (T *)calloc(size, sizeof(T));
            break;
        default:
            bad_alloc_method = true;
            break;
        }
    }
    catch (std::bad_alloc &ba)
    {
        fprintf(stderr, "FCALLOC: bad_alloc caught %s!", ba.what());
    }

    if (bad_alloc_method == true)
    {
        fprintf(stderr, "FCALLOC: unsupported memory allocation method!");
        return nullptr;
    }

    if (allocated == nullptr)
    {
        fprintf(stderr, "FCALLOC: allocation failed");
        return nullptr;
    }

    return allocated;
}

//
// Name: FCloudReAllocator
//
// Description:
//   Invoked by 'preprocessor macro' 'FCalloc'
//   Realloc memory for required new size
//
// Input:
//   oldbuf - the buffer to increase size
//   size - the size of oldbuf
//   required_size - the needed size
//   delta - the delta size used to increase size
//
// Output:
//   size set to new size
//
// Return:
//   T *pointer to rellocated buffer
//
template <typename T, typename P>
T *FCloudReAllocator(T *oldbuf, const P size, const P required_size)
{
    if (oldbuf == nullptr)
    {
        fprintf(stderr, "memory (re)allocation is required!");
        return nullptr;
    }

    T *newbuf = nullptr;

    unsigned short err_count = 0;
    const unsigned short max_realloc = 5;
    bool undefined_retries = false;

    try
    {
        if (required_size > size)
        {
            do
            {
                err_count++;
                newbuf = (T *)realloc(oldbuf, (required_size * sizeof(T)));

                if (newbuf == nullptr && err_count > max_realloc)
                    undefined_retries = true;
            } while (newbuf == nullptr); // ... fine processo assegnazione memoria puntatore 'base'
        }
    }
    catch (std::bad_alloc &ba)
    {
        fprintf(stderr, "FCREALLOC: bad_alloc caught %s!", ba.what());
        return nullptr;
    }

    if (undefined_retries == true)
    {
        fprintf(stderr, "FCREALLOC: Error (re)allocating memory for %u times!", err_count);
        return nullptr;
    }

    return newbuf;
}

#endif
#endif // __TEMPLATES_INCLUDED_H
