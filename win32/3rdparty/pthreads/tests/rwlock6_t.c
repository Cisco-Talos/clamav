/*
 * rwlock6_t.c
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
 * Check writer and reader locking with reader timeouts
 *
 * Depends on API functions: 
 *      pthread_rwlock_timedrdlock()
 *      pthread_rwlock_wrlock()
 *      pthread_rwlock_unlock()
 */

#include "test.h"
#include <sys/timeb.h>

static pthread_rwlock_t rwlock1 = PTHREAD_RWLOCK_INITIALIZER;

static int bankAccount = 0;

void * wrfunc(void * arg)
{
  assert(pthread_rwlock_wrlock(&rwlock1) == 0);
  Sleep(2000);
  bankAccount += 10;
  assert(pthread_rwlock_unlock(&rwlock1) == 0);

  return ((void *) bankAccount);
}

void * rdfunc(void * arg)
{
  int ba = -1;
  struct timespec abstime = { 0, 0 };
  struct _timeb currSysTime;
  const DWORD NANOSEC_PER_MILLISEC = 1000000;

  _ftime(&currSysTime);

  abstime.tv_sec = currSysTime.time;
  abstime.tv_nsec = NANOSEC_PER_MILLISEC * currSysTime.millitm;


  if ((int) arg == 1)
    {
      abstime.tv_sec += 1;
      assert(pthread_rwlock_timedrdlock(&rwlock1, &abstime) == ETIMEDOUT);
      ba = 0;
    }
  else if ((int) arg == 2)
    {
      abstime.tv_sec += 3;
      assert(pthread_rwlock_timedrdlock(&rwlock1, &abstime) == 0);
      ba = bankAccount;
      assert(pthread_rwlock_unlock(&rwlock1) == 0);
    }

  return ((void *) ba);
}

int
main()
{
  pthread_t wrt1;
  pthread_t wrt2;
  pthread_t rdt1;
  pthread_t rdt2;
  int wr1Result = 0;
  int wr2Result = 0;
  int rd1Result = 0;
  int rd2Result = 0;

  bankAccount = 0;

  assert(pthread_create(&wrt1, NULL, wrfunc, NULL) == 0);
  Sleep(500);
  assert(pthread_create(&rdt1, NULL, rdfunc, (void *) 1) == 0);
  Sleep(500);
  assert(pthread_create(&wrt2, NULL, wrfunc, NULL) == 0);
  Sleep(500);
  assert(pthread_create(&rdt2, NULL, rdfunc, (void *) 2) == 0);

  assert(pthread_join(wrt1, (void **) &wr1Result) == 0);
  assert(pthread_join(rdt1, (void **) &rd1Result) == 0);
  assert(pthread_join(wrt2, (void **) &wr2Result) == 0);
  assert(pthread_join(rdt2, (void **) &rd2Result) == 0);

  assert(wr1Result == 10);
  assert(rd1Result == 0);
  assert(wr2Result == 20);
  assert(rd2Result == 20);

  return 0;
}


