open Lwt

module Authlet = struct
  type t = [
    | `None
    | `Logger of string
    | `Remote of (string * int) * Certificate.certificate option
  ]

  let null = `None
  let logger logfile = `Logger logfile
  let remote ?cert:cert ?port:port host = 
    let port_v = match port with
      | None -> 443
      | Some p -> p
    in
    
    `Remote ((host, port_v), cert) 
end

module Authenticator = struct
  
  let logger path (r_host, r_port) = 
    lwt oc = Lwt_io.open_file ~mode:Lwt_io.Output path in
    return begin
      fun ?host:host (c, stack) ->
        let hst = match host with
          | None -> "UNKNOWN"
          | Some (`Wildcard s) -> s
	  | Some (`Strict s) -> s
        in
        let c_str = Cstruct.to_string (Certificate.cs_of_cert c) in
        Lwt_io.(write_line oc ("\nConnecting to '" ^ r_host ^ ":" ^ (string_of_int r_port) ^ "' (" ^ hst ^ ") with certificate:")
             >> write_line oc c_str) >> return (`Ok c)
    end

  let remote (ts_host, ts_port) ts_c (r_host, r_port) =
    return begin
      fun ?host:host (c, stack) ->
        (* TODO: how best to authenticate here? *)
        (* TODO: pass cert file as argument to authlet *)
        lwt auth = X509_lwt.authenticator (`Ca_file "/home/jocbe/sdev/ConsT/certs/demoCA.crt") in
        lwt (ic, oc) = Tls_lwt.connect auth (ts_host, ts_port) in
        Lwt_io.write_value oc ((r_host, r_port), ((c, stack), host));
	lwt resp = Lwt_io.read_value ic in
        let res = match resp with
	  | `Ok _ -> "Trusted."
          | `Fail _ -> "NOT trusted!"
          | _ -> "ERROR: unexpected response."
	in
        Lwt_io.printf "GOT: %s\n" res;
        return resp
      end
end

module Comp = struct
  type mode = [ `Strict | `Allow_failures ] 
  (* (number of authenticators to execute * number of authenticators that need to return `Ok) * ((authlet * priority (lower = higher priority)) list)  *)
  type t = [ `Comp of (int * int * mode) * ((Authlet.t * int) list) | `Single of Authlet.t ]

  let single authlet = `Single authlet
  let comp (num_execute, num_ok, mode) (authlet, priority) = `Comp ((num_execute, num_ok, mode), [(authlet, priority)])
  let add comp p_authlet = 
    match comp with
    | `Comp (c_data, aas) -> `Comp (c_data, p_authlet :: aas)
    | _ -> raise (Invalid_argument "Expected `Comp composition")
  let update_comp_data comp new_data = 
    match comp with
    | `Comp (c_data, aas) -> `Comp (new_data, aas)
    | _ -> raise (Invalid_argument "Expected `Comp composition")

end

module Conf = struct
  type t = Comp.t list

  let new_conf = []
  let from_authlet authlet = [`Single authlet]
  let from_comp comp = [comp]
  let add_authlet conf authlet = (`Single authlet) :: conf
  let add conf comp = comp :: conf
  
  let conf_to_string conf =
    "NOT YET IMPLEMENTED" 
  let string_to_conf str =
    [`Single `None]

  let build conf (r_host, r_port) =
    (* WARNING: does not preserve order of items in first half returned *)
    let split_list xxs i =
      let rec sl_worker acc xxs num =
	if List.length xxs <= num then
          (xxs, [])
	else if num <= 0 then
	  (acc, xxs)
	else
	  let x::xs = xxs in 
	  sl_worker (x::acc) xs (num - 1)
      in sl_worker [] xxs i
    in
    let authenticate ?host:host (c, stack) auth = auth ?host:host (c, stack) in
    let filterp = fun v -> 
      let ret = match v with
        | `Ok _ -> false
        | _ -> true
      in
      return ret
    in
    let compile_authlet authlet host_info =
      match authlet with
      | `None -> return X509.Authenticator.null
      | `Logger log -> Authenticator.logger log host_info
      | `Remote ((ts_host, ts_port), ts_cert) -> Authenticator.remote (ts_host, ts_port) ts_cert host_info
    in
    let compile_p_authlet (authlet, _) = compile_authlet authlet in
    let compile_comp ((max_queries, num_ok, mode), auths) host_info = 
      let sorted = List.sort (fun (_, p1) (_, p2) -> p1 - p2) auths in
      lwt compiled = Lwt_list.map_p (fun (authlet, _) -> compile_authlet authlet host_info) sorted in
      (* TODO: take care of case where num_ok > max_query *)
      return begin 
	fun ?host:host (c, stack) -> begin
          let rec count_results resl num_ok num_fail num_err = 
            match resl with
	    | [] -> (num_ok, num_fail, num_err)
	    | x :: xs -> 
	      match x with
	      | `Ok _ -> count_results xs (num_ok + 1) num_fail num_err
	      | `Fail _ -> count_results xs num_ok (num_fail + 1) num_err
	      | _ -> count_results xs num_ok num_fail (num_err + 1)
            (* num_ok = number of `Ok still required to pass *)
          in
          let rec eval_auth auths num_ok max mode = 
	    if num_ok > max || num_ok <= 0 then
	      return (`Fail Certificate.InvalidCertificate)
	    else
	      let (next_candidates, rest) = split_list auths num_ok in
	      lwt resl = Lwt_list.map_p (authenticate ?host:host (c, stack)) next_candidates in
	      let (n_o, n_f, n_e) = count_results resl 0 0 0 in
              if n_o = num_ok then
		return (List.nth resl 0)
	      else if mode = `Strict && n_f > 0 then
		lwt errl = Lwt_list.filter_p filterp resl in
	        return (List.nth errl 0)
              else
                eval_auth rest (num_ok - n_o) (max - num_ok) mode
          in 
          eval_auth compiled num_ok max_queries mode
        end
      end
    in 
    let compile host_info comp = 
      match comp with
      | `Single a -> compile_authlet a host_info
      | `Comp c -> compile_comp c host_info
    in
    (* Compare the returned certs to each other? *)
    lwt authl = Lwt_list.map_p (compile (r_host, r_port)) conf  in
    return begin
      fun ?host:host (c, stack) -> 
        lwt resl = Lwt_list.map_p (authenticate ?host:host (c, stack)) authl in
        lwt errl = Lwt_list.filter_p filterp resl in
        if List.length errl > 0 then
          return (List.nth errl 0)
        else 
  	  return (List.nth resl 0)
    end
end


