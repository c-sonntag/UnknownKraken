/*
 * This file is part of UnknownEchoLib.
 *
 * UnknownEchoLib is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * UnknownEchoLib is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.
 */

/*!
 *  \brief     Main file that execute all LibUnknownEcho tests
 *  \author    Swa
 *  \version   0.1
 *  \date      2017-2018
 *  \copyright GNU Public License.
 */

#include "crypto/api/encryption/test_sym_encrypter.h"
#include "crypto/api/encryption/test_asym_encrypter.h"

#include <unknownecho/init.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/*!
 *  \brief Execute all tests
 */
int main() {
	int exit_code;

	const struct CMUnitTest tests[] = {
        //cmocka_unit_test_setup_teardown(test_sym_encrypter, test_sym_encrypter_setup, test_sym_encrypter_teardown),
        cmocka_unit_test_setup_teardown(test_asym_encrypter, test_sym_encrypter_setup, test_sym_encrypter_teardown)
    };

	ue_init();

    exit_code = cmocka_run_group_tests(tests, NULL, NULL);

	ue_uninit();

    return exit_code;
}
