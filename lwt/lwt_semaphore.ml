(* Lightweight thread library for OCaml
 * http://www.ocsigen.org/lwt
 * Module Lwt_semaphore
 * Copyright (C) 2005-2008 Jérôme Vouillon
 * Laboratoire PPS - CNRS Université Paris Diderot
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, with linking exceptions;
 * either version 2.1 of the License, or (at your option) any later
 * version. See COPYING file for details.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *)

let (>>=) = Lwt.(>>=)

type t = { mutable resources_available : int; mutable waiters : unit Lwt.u Lwt_sequence.t  }

let create n = { resources_available = n; waiters = Lwt_sequence.create () }

let wait s =
  if s.resources_available <= 0 then
    Lwt.add_task_r s.waiters
  else begin
    s.resources_available <- s.resources_available - 1;
    Lwt.return_unit
  end

let post s =
  if Lwt_sequence.is_empty s.waiters then
    s.resources_available <- s.resources_available + 1
  else
    (* We do not use [Lwt.wakeup] here to avoid a stack overflow
       when unlocking a lot of threads. *)
    Lwt.wakeup_later (Lwt_sequence.take_l s.waiters) ()

let with_semaphore s f =
  wait s >>= fun () ->
  Lwt.finalize f (fun () -> post s; Lwt.return_unit)

let resources_available s = s.resources_available
let is_empty s = Lwt_sequence.is_empty s.waiters
