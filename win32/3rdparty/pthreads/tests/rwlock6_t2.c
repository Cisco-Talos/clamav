/*
 * rwlock6_t2.c
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
 * Check writer and reader timeouts.
 *
 * Depends on API functions: 
 *      pthread_rwlock_timedrdlock()
 *      pthread_rwlock_timedwrlock()
 *      pthread_rwlock_unlock()
 */

#include "test.h"
#include <sys/timeb.h>

static pthread_rwlock_t rwlock1 = PTHREAD_RWLOCK_INITIALIZER;

static int bankAccount = 0;
struct timespec abstime = { 0, 0 };

void * wrfunc(void * arg)
{
  int result;

  result = pthread_rwlock_timedwrlock(&rwlock1, &abstime);
  if ((int) arg == 1)
    {
      assert(result == 0);
      Sleep(2000);
      bankAccount += 10;
      assert(pthread_rwlock_unlock(&rwlock1) == 0);
      return ((void *) bankAccount);
    }
  else if ((int) arg == 2)
    {
      assert(result == ETIMEDOUT);
      return ((void *) 100);
    }

  return ((void *) -1);
}

void * rdfunc(void * arg)
{
  int ba = 0;

  assert(pthread_rwlock_timedrdlock(&rwlock1, &abstime) == ETIMEDOUT);

  return ((void *) ba);
}

int
main()
{
  pthread_t wrt1;
  pthread_t wrt2;
  pthread_t rdt;
  int wr1Result = 0;
  int wr2Result = 0;
  int rdResult = 0;
  struct _timeb currSysTime;
  const DWORD NANOSEC_PER_MILLISEC = 1000000;

  _ftime(&currSysTime);

  abstime.tv_sec = currSysTime.time;
  abstime.tv_nsec = NANOSEC_PER_MILLISEC * currSysTime.millitm;

  abstime.tv_sec += 1;

  bankAccount = 0;

  assert(pthread_create(&wrt1, NULL, wrfunc, (void *) 1) == 0);
  Sleep(100);
  assert(pthread_create(&rdt, NULL, rdfunc, NULL) == 0);
  Sleep(100);
  assert(pthread_create(&wrt2, NULL, wrfunc, (void *) 2) == 0);

  assert(pthread_join(wrt1, (void **) &wr1Result) == 0);
  assert(pthread_join(rdt, (void **) &rdResult) == 0);
  assert(pthread_join(wrt2, (void **) &wr2Result) == 0);

  assert(wr1Result == 10);
  assert(rdResult == 0);
  assert(wr2Result == 100);

  return 0;
}
