/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoUtilsModule.                             *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#ifndef UnknownKrakenUtils_UK_UTILS_H
#define UnknownKrakenUtils_UK_UTILS_H

#include <uk/utils/byte/byte_reader.h>
#include <uk/utils/byte/byte_stream_struct.h>
#include <uk/utils/byte/byte_stream.h>
#include <uk/utils/byte/byte_utility.h>
#include <uk/utils/byte/byte_writer.h>
#include <uk/utils/byte/hex_utility.h>

#include <uk/utils/compiler/bool.h>
#include <uk/utils/compiler/inline.h>
#include <uk/utils/compiler/likely.h>
#include <uk/utils/compiler/overflow.h>
#include <uk/utils/compiler/pragma.h>
#include <uk/utils/compiler/ssize_t.h>
#include <uk/utils/compiler/typecheck.h>
#include <uk/utils/compiler/typename.h>
#include <uk/utils/compiler/typeof.h>
#include <uk/utils/compiler/warn_unused_result.h>

#include <uk/utils/console/color.h>
#include <uk/utils/console/console.h>
#include <uk/utils/console/input.h>
#include <uk/utils/console/progress_bar.h>

#include <uk/utils/container/byte_vector.h>
#include <uk/utils/container/string_vector.h>
#include <uk/utils/container/queue.h>

#include <uk/utils/file_system/file_utility.h>
#include <uk/utils/file_system/folder_utility.h>

#include <uk/utils/process/process_utils.h>

#include <uk/utils/safe/safe_alloc.h>
#include <uk/utils/safe/safe_arithmetic.h>

#include <uk/utils/string/string_builder.h>
#include <uk/utils/string/string_split.h>
#include <uk/utils/string/string_utility.h>

#include <uk/utils/thread/thread_cond.h>
#include <uk/utils/thread/thread_id_struct.h>
#include <uk/utils/thread/thread_mutex.h>
#include <uk/utils/thread/thread_result.h>
#include <uk/utils/thread/thread.h>

#include <uk/utils/time/current_time.h>
#include <uk/utils/time/processor_timestamp.h>
#include <uk/utils/time/real_current_time.h>
#include <uk/utils/time/sleep.h>
#include <uk/utils/time/timer_measure_struct.h>
#include <uk/utils/time/timer_measure.h>
#include <uk/utils/time/timer.h>

#endif
