#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/fail.h>

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


/* Convert a 'struct in_addr' to an Ocaml string */
value inaddr2string(struct in_addr addr_in)
{
  CAMLlocal1(address_binary);

  /* Prepare the ocaml string */
  address_binary = caml_alloc_string(4);
  char *p_str = String_val(address_binary); /* Retrieve the pointer to address_binary. */

  p_str[0] = (ntohl(addr_in.s_addr) >> 24) & 0xFF;
  p_str[1] = (ntohl(addr_in.s_addr) >> 16) & 0xFF;
  p_str[2] = (ntohl(addr_in.s_addr) >> 8) & 0xFF;
  p_str[3] = ntohl(addr_in.s_addr) & 0xFF;

  return address_binary;
}


/* Convert an Ocaml string (on 4 bytes) to a 'struct in_addr */
struct in_addr string2inaddr(value address_binary)
{
  CAMLparam1(address_binary);

  /* Prepare the in_addr structure */
  struct in_addr addr_in;
  char *a_ptr = String_val(address_binary);

  addr_in.s_addr  =  a_ptr[0] << 24;
  addr_in.s_addr +=  a_ptr[1] << 16;
  addr_in.s_addr +=  a_ptr[2] << 8;
  addr_in.s_addr +=  a_ptr[3] & 0xFF;
  addr_in.s_addr = htonl(addr_in.s_addr);

  return addr_in;
}


/* inet_aton for ocaml */
value ocaml_inet_aton(value address)
{
  CAMLparam1(address);

  int ret_code;
  struct in_addr addr_in;

  /* Call inet_aton */
  char *address_C = String_val(address);
  ret_code = inet_aton(address_C, &addr_in);
  if (ret_code == 0)
    caml_failwith("Invalid IPv4 address !");

  CAMLreturn(inaddr2string(addr_in));
}


/* inet_ntoa for ocaml */
value ocaml_inet_ntoa(value address_binary)
{
  CAMLparam1(address_binary);

  if (caml_string_length(address_binary) != 4)
    caml_failwith("Invalid binary IPv4 address !");

  char *ret_addr = inet_ntoa(string2inaddr(address_binary));
  if (ret_addr == NULL)
    caml_failwith("Invalid binary IPv4 address !");

  CAMLreturn(caml_copy_string(ret_addr));
}


/* inet_pton for ocaml */
value ocaml_inet_pton(value af, value address)
{
  CAMLparam2(af, address);

  int ret_code, i;
  struct in_addr addr_in;
  struct in6_addr addr_in6;
  char *address_C = String_val(address);

  /* Identify the address family and call inet_pton */
  if (af == Val_int(0))
  {
    // IPv4
    ret_code = inet_pton(AF_INET, address_C, &addr_in);
    if (ret_code != 1)
      caml_failwith("Invalid IPv4 address !");

    CAMLreturn(inaddr2string(addr_in));
  }

  else if (af == Val_int(1))
  {
    // IPv6
    ret_code = inet_pton(AF_INET6, address_C, &addr_in6);
    if (ret_code != 1)
      caml_failwith("Invalid IPv6 address !");

    CAMLlocal1(address_binary6);
    address_binary6 = caml_alloc_string(16);
    char *p_str = String_val(address_binary6); /* Retrieve the pointer to address_binary. */
    for (i=0; i <= 15; i++)
      p_str[i] = addr_in6.s6_addr[i];

    CAMLreturn(address_binary6);
  }

  else
    caml_failwith("Unknown address family  !");
}


/* inet_ntop for ocaml */
value ocaml_inet_ntop(value af, value address_binary)
{
  CAMLparam2(af, address_binary);

  const char* ret_ptr;
  char address[INET6_ADDRSTRLEN];

  char *a_ptr = String_val(address_binary);

  if (af == Val_int(0))
  {
    // IPv4
    ret_ptr = inet_ntop(AF_INET, a_ptr, (char*) &address, INET_ADDRSTRLEN);
    if (ret_ptr == NULL)
      caml_failwith("Invalid binary IPv4 address !");

    CAMLreturn(caml_copy_string(ret_ptr));
  }

  if (af == Val_int(1))
  {
    // IPv6
    ret_ptr = inet_ntop(AF_INET6, a_ptr, (char*) &address, INET6_ADDRSTRLEN);
    if (ret_ptr == NULL)
      caml_failwith("Invalid binary IPv6 address !");

    CAMLreturn(caml_copy_string(ret_ptr));
  }

  else
    caml_failwith("Unknown address family  !");
}
