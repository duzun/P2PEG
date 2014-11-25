/*  GUChaos.c -- Give Us Chaos* !
    -----------------------------

    This can be used if your system don't have enought entropy for doing
    tasks such as cryptographic keys generation.  It retrieves random bytes
    from http://www.random.org, modify them on the fly with a polynumeric
    substitution cypher and finally add them to your system's random device
    until your kernel's entropy pool gets full.

      (*) Entropy can be associated with chaos, disorder, etc.

    Usage: 

       1) change the default key (KEY) bellow
       2) compile with "cc GUChaos.c -o GUChaos" or "make GUChaos"
       3) run as root: ./GUChaos

    Changelog:

       2014/08/31 - 1.2 - Bug fix: Host header is now required in the HTTP 
                          request.
       2012/04/30 - 1.1 - Exit program if random.org is unreachable.
                        - Change default KEY value.
                        - Minor output changes.
       2010/12/26 - 1.0 - Initial version.

    -----------------------------------------------------------------------

    Copyright (C) 2010,2012,2014 vladz <vladz@devzero.fr>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <linux/random.h>

#define PROGRAM_NAME      "GUChaos"
#define PROGRAM_VERSION   "1.2"

#define RANDOM_DEVICE     "/dev/random"
#define CUR_ENTROPY_FILE  "/proc/sys/kernel/random/entropy_avail"
#define MAX_ENTROPY_FILE  "/proc/sys/kernel/random/poolsize"
#define MAX_RBYTES        1024

/* this key will be used during polynumeric substitution. Content and
 * length has to be changed ! */
#define KEY               "0000000000000000"


typedef unsigned short _u16;
typedef unsigned int _u32;


/* will contain retrieved short integers */
_u16 u16_rbytes[MAX_RBYTES];
/* will contain our final real 32 bits integers */
_u32 rbytes[MAX_RBYTES / 2];


/* convert 16 bits integer table into 32 bits integer table.
*/
void convert_stoi(_u32 * dst, _u16 * src) {
  int x = 0;

  while (x != (MAX_RBYTES / 2)) {

    dst[x] = src[x * 2] << 16 | src[x * 2 + 1];
    x++;
  }
}

/* transform tab[] by using a polynumeric substitution cipher (based on
 * polyalphabetic substitution[1])
 *
 * [1] Substitution Ciphers
 *     [http://en.wikipedia.org/wiki/Substitution_cipher]
*/
void poly_substition(_u16 * tab, char *key) {
  int i = 0, ki;
  char ckey[2];
  int key_len = strlen(key);

  memset(ckey, '\0', 2);

  while (tab[i]) {
    ckey[0] = *key;
    ki = atoi(ckey);
    tab[i] = (tab[i] + ki) % 0xffff;
    i++;
    key++;
    if (*key == '\0')
      key -= key_len;
  }
}

/* add entropy to char device "/dev/random" 
*/
int add_entropy(void) {
  struct rand_pool_info *t;
  int fd, ret = 0;

  poly_substition(u16_rbytes, KEY);
  convert_stoi(rbytes, u16_rbytes);

  printf("[+] Adding 0x%-8x 0x%-8x ... 0x%-8x",
	 rbytes[1], rbytes[2], rbytes[MAX_RBYTES / 2 - 1]);

  t = (struct rand_pool_info *) malloc(sizeof(struct rand_pool_info) +
				       MAX_RBYTES / 2);
  t->entropy_count = MAX_RBYTES / 2;
  t->buf_size = MAX_RBYTES / 2;

  memcpy(&(t->buf[0]), rbytes, MAX_RBYTES / 2);

  if ((fd = open(RANDOM_DEVICE, O_WRONLY)) < 0) {
    printf("\n[-] Cannot open %s.\n", RANDOM_DEVICE);
    exit(1);
  }

  /* RANDOM_DEVICE is now opened, run ioctl() */
  if (ioctl(fd, RNDADDENTROPY, t) < 0) {
    printf("\n[-] Cannot call ioctl on %s. Are you root?!\n",
	   RANDOM_DEVICE);
    exit(1);
  }

  close(fd);

  return ret;
}

/* return fd content (entropy information's value) as an integer 
*/
int value_from_fd(int fd) {
  char buf[16];
  int read_bytes;

  memset(buf, '\0', 16);
  read_bytes = read(fd, buf, 16 - 1);
  buf[read_bytes] = '\0';

  return atoi(buf);
}

/* display current entropy's status (available/poolsize) and returns 1 if
 * more are needed or 0 if entropy's spool is full
*/
int check_entropy_status(int quiet) {
  int cur_fd, max_fd;
  int cur_val, max_val;

  if ((cur_fd = open(CUR_ENTROPY_FILE, O_RDONLY)) < 0) {
    printf("[-] Cannot open CUR_ENTROPY_FILE\n");
    exit(1);
  }

  if ((max_fd = open(MAX_ENTROPY_FILE, O_RDONLY)) < 0) {
    printf("[-] Cannot open MAX_ENTROPY_FILE\n");
    close(cur_fd);
    exit(1);
  }

  cur_val = value_from_fd(cur_fd);
  max_val = value_from_fd(max_fd);
  close(cur_fd);
  close(max_fd);

  if (cur_val == max_val) {

    if (!quiet)
      printf(" (status: %d/%d)\n", cur_val, max_val);

    printf("[+] Available entropy is set to the maximum (%d)\n", max_val);
    return 0;
  }

  if (!quiet)
    printf(" (status: %d/%d)\n", cur_val, max_val);

  return 1;
}

/* parse retrieved webpage (result) and store random digits into u16_rbytes[]
*/
int parse(unsigned char *result) {
  char *q, *p;
  int i = 0;

  p = (char *) result;

  /* we jump after the HTTP header */
  q = strstr(p, "\r\n\r\n");
  q += 4;
  p = q;

  if (!strncmp(q, "Error", 5)) {
    /* If you run this program to much, random.org will send the following
     * error message: "Error: You have used your quota of random bits for 
     * today.  See the quota page for details". So exit ! */
    printf("[-] random.org - %s", q);
    exit(1);
  }

  while (i < MAX_RBYTES) {
    if (isdigit(*q)) {
      /* maybe more digits ? */
      q++;
    } else {
      /* no more digit */
      *q = '\0';
      /* save the current number */
      u16_rbytes[i] = atoi((const char *) p);
      i++;
      q++;
      p = q;
    }
  }

  return 0;
}

/* retrieve random.org web page and parse the result
*/
int retrieve_random_bytes(void) {
  int size = 0;
  char ans[256], cmd[1024];
  unsigned char *result = NULL;
  int read_bytes = 0;

  int sock;
  struct sockaddr_in dest;
  struct hostent *he;

  char *hostname = "www.random.org";
  char *file = "/integers/?";

  /* random.org can't generate real 32 bits integers as the maximum number
   * available is 1,000,000,000. So lets retrieve 16 bits integers (maximum
   * number sets to 65535), we will concatenate into 32 bits integers later  
   */
  char *options =
      "num=1024&min=0&max=65535&col=4&base=10&format=plain&md=new";

  if ((he = gethostbyname(hostname)) == NULL) {
    printf("[-] Could not resolve %s\n", hostname);
    return 1;
  }

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "%s: socket() failed.\n", PROGRAM_NAME);
    return 1;
  }

  /* fill sockaddr_in structure */
  dest.sin_family = AF_INET;
  dest.sin_port = htons(80);
  dest.sin_addr = *((struct in_addr *) he->h_addr);

  if (connect(sock, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0) {
    printf("[-] Connect() failed.\n");
    close(sock);
    return 1;
  }

  sprintf(cmd, "GET %s%s HTTP/1.1\nHost: www.random.org\r\n\r\n", file, options);
  send(sock, cmd, strlen(cmd), 0);

  while ((read_bytes = read(sock, ans, 256 - 1))) {

    ans[read_bytes] = '\0';
    size += read_bytes;
    result = realloc(result, size);
    strcat((char *) result, ans);
  }

  parse(result);
  close(sock);

  return 0;
}

int main(int argc, char *argv[]) {

  printf("[+] %s version %s\n", PROGRAM_NAME, PROGRAM_VERSION);

  if (!check_entropy_status(1))
    return 0;

  printf("[+] Retrieve random bytes from http://random.org\n");

  do {
    if (retrieve_random_bytes() != 0)
      return 1;

    add_entropy();
  } while (check_entropy_status(0));

  return (0);
}
