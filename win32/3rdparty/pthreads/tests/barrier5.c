/*
 * barrier5.c
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 * 
 *      Contact Email: rpj@callisto.canberra.edu.au
 * 
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 * 
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 * 
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 * 
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * --------------------------------------------------------------------------
 *
 * Declare a single barrier object, set up a sequence of
 * barrier points to prove lockstepness, and then destroy it.
 *
 */

#include "test.h"

enum {
  NUMTHREADS = 16,
  BARRIERS = 10000
};
 
pthread_barrier_t barrier = NULL;
pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;

int barrierReleases[BARRIERS + 1];

void *
func(void * barrierHeight)
{
  int i;
  int result;
  int serialThreads = 0;

  for (i = 1; i < BARRIERS; i++)
    {
      result = pthread_barrier_wait(&barrier);

      assert(pthread_mutex_lock(&mx) == 0);
      barrierReleases[i]++;
      assert(pthread_mutex_unlock(&mx) == 0);
      /*
       * Confirm the correct number of releases from the previous
       * barrier. We can't do the current barrier yet because there may
       * still be threads waking up.
       */
      if (result == PTHREAD_BARRIER_SERIAL_THREAD)
        {
          serialThreads++;
          assert(barrierReleases[i - 1] == (int) barrierHeight);
          barrierReleases[i + 1] = 0;
        }
      else if (result != 0)
        {
          printf("Barrier failed: result = %s\n", error_string[result]);
          fflush(stdout);
          return NULL;
        }
    }

  return (void *) serialThreads;
}

int
main()
{
  int i, j;
  int result;
  int serialThreadsTotal;
  pthread_t t[NUMTHREADS + 1];

  for (j = 1; j <= NUMTHREADS; j++)
    {
      printf("Barrier height = %d\n", j);

      barrierReleases[0] = j;
      barrierReleases[1] = 0;

      assert(pthread_barrier_init(&barrier, NULL, j) == 0);

      for (i = 1; i <= j; i++)
        {
          assert(pthread_create(&t[i], NULL, func, (void *) j) == 0);
        }

      serialThreadsTotal = 0;
      for (i = 1; i <= j; i++)
        {
          assert(pthread_join(t[i], (void **) &result) == 0);
          serialThreadsTotal += result;
        }

      assert(serialThreadsTotal == BARRIERS - 1);
      assert(barrierReleases[BARRIERS - 1] == j);
      assert(barrierReleases[BARRIERS] == 0);

      assert(pthread_barrier_destroy(&barrier) == 0);
    }

  assert(pthread_mutex_destroy(&mx) == 0);

  return 0;
}
