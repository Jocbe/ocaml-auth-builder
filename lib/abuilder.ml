open Lwt

let _LOGLEVEL = 6
let d l m =
  if l <= _LOGLEVEL then
    Lwt_io.printf "level %i: %s" l m
  else
    return ()

module Authlet = struct
  type with_depend = [
    | `Ca_file of string
    | `Ca_dir of string
    | `Remote_ca_file of (string * int) * string
  ]
  
  type self_contained = [
    | `None
    | `Logger of string
    | `Remote of (string * int) * X509.Cert.t list option
    | `Ca_list of X509.Cert.t list
  ]

  type t = [ self_contained | with_depend ]

  let null = `None
  let logger logfile = `Logger logfile
  let remote ?cert:cert ?port:port host = 
    let port_v = match port with
      | None -> 443
      | Some p -> p
    in
    `Remote ((host, port_v), cert)
  let remote_ca_file c_path ?port:port host = 
    let port_v = match port with
      | None -> 443
      | Some p -> p
    in
    `Remote_ca_file ((host, port_v), c_path)
  let ca_file path = `Ca_file path
  let ca_dir path = `Ca_dir path
  let ca_list cas = `Ca_list cas
  
  let contain authlet = 
    match authlet with
    | `Ca_file path -> 
      lwt cert_list = X509_lwt.certs_of_pem path in
      return (`Ca_list cert_list)
    | `Ca_dir path ->
      lwt cert_list = X509_lwt.certs_of_pem_dir path in
      return (`Ca_list cert_list)
    | `Remote_ca_file (host, c_path) -> 
      lwt cert_list = X509_lwt.certs_of_pem c_path in
      return (`Remote (host, Some cert_list))
    | `None -> return `None
    | `Logger l -> return (`Logger l)
    | `Remote r -> return (`Remote r)
    | `Ca_list l -> return (`Ca_list l)
end

module Cache = struct
  type t = [ `Simple of float ]
  type auth_res = [ `Ok of Certificate.certificate | `Fail of Certificate.certificate_failure ]
  type res = [ `Res of auth_res | `Not_found ]
  type compiled = < 
    get_res : ( string * int ) -> ?host:Certificate.host -> Certificate.stack -> res ;
    get_cert : ( string * int ) -> Certificate.certificate ;
    set : ( string * int ) -> ?ttl:float -> Certificate.certificate -> auth_res -> unit ;
    remove_stale_entries : unit
  >
  module CertSet = Set.Make (
    struct 
      type t = ( (string * int) * ((float * Certificate.certificate * auth_res) option) )
      let compare = fun ((host1, port1), _) ((host2, port2), _) -> 
	let host_comp_res = Pervasives.compare host1 host2 in
	if host_comp_res != 0 then
	  host_comp_res
	else
	  Pervasives.compare port1 port2
    end
  )

  let simple ttl = 
    `Simple ttl

  let c_simple default_ttl = object
    val mutable certs = CertSet.empty
    
    method get_res (r_host, r_port) ?host:host (c, stack) =
      try
	let (expiry_time, ccert, cres) =
	  match CertSet.find ((r_host, r_port), None) certs with
	  | (_, None) ->
	    certs <- CertSet.remove ((r_host, r_port), None) certs;
	    raise Not_found
	  | (_, Some (t, c, r)) -> (t, c, r)
	in
	let now = Unix.gettimeofday () in
	if now > expiry_time then
	  begin
	    certs <- CertSet.remove ((r_host, r_port), None) certs;
	    `Not_found
	  end
	else if Pervasives.compare c ccert != 0 then
	  `Not_found
	else
	  `Res cres
      with Not_found -> `Not_found

    method get_cert (r_host, r_port) =
      let (time, cert, res) = match CertSet.find ((r_host, r_port), None) certs with
	| (_, None) ->
	  certs <- CertSet.remove ((r_host, r_port), None) certs;
	  raise Not_found
	| (_, Some (t, c, r)) -> (t, c, r)
      in
      let now = Unix.gettimeofday () in
      if now > time then
	begin
	  certs <- CertSet.remove ((r_host, r_port), None) certs;
	  raise Not_found
	end
      else
	match res with
	| `Ok _ -> cert
	| _ -> raise Not_found

    method set (r_host, r_port) ?ttl cert res =
      let tmp_certs = CertSet.remove ((r_host, r_port), None) certs in
      let now = Unix.gettimeofday () in
      let expiry_time = match ttl with
	| None -> now +. default_ttl
	| Some n -> now +. n
      in
      let entry = ((r_host, r_port), Some (expiry_time, cert, res)) in
      certs <- CertSet.add entry tmp_certs

    method remove_stale_entries =
      let now = Unix.gettimeofday () in
      let filter_fun = fun (_, data) -> 
	match data with
	| None -> false
	| Some (t, _, _) -> t > now
      in
      certs <- CertSet.filter filter_fun certs
  end

  let compile cache = 
    match cache with
    | `Simple ttl -> return (c_simple ttl)
end

module Authenticator = struct
  exception Unexpected_response of string

  let logger path (r_host, r_port) = 
    lwt oc = Lwt_io.open_file ~flags:[Unix.O_APPEND; Unix.O_CREAT; Unix.O_WRONLY] ~mode:Lwt_io.Output path in
    return begin
      fun ?host:host (c, stack) ->
        let hst = match host with
          | None -> "UNKNOWN"
          | Some (`Wildcard s) -> s
	  | Some (`Strict s) -> s
        in
        let c_str = Cstruct.to_string (Nocrypto.Base64.encode (Certificate.cs_of_cert c)) in
	let t = Unix.localtime (Unix.time ()) in
        let soi = fun i -> 
	  let s = string_of_int i in
	  if i > 9 then
	    s
	  else
	    "0" ^ s
	in
	let open Unix in
	let msg = String.concat "\n" [
	  "[" ^ soi (t.tm_year + 1900) ^ "-" ^ soi t.tm_mon ^ "-" ^ soi t.tm_mday ^ "_" ^ soi t.tm_hour ^ ":" ^ soi t.tm_min ^ ":" ^ soi t.tm_sec ^ "] "
	    ^ "Connecting to '" ^ r_host ^ ":" ^ soi r_port ^ "' (" ^ hst ^ ") with cert:" ;
	  "-----BEGIN CERTIFICATE-----" ; c_str ; "-----END CERTIFICATE-----"
	] in
        Lwt_io.(write_line oc msg >> close oc) >> return (`Ok c)
    end

  let remote (ts_host, ts_port) ts_c (r_host, r_port) =
    return begin
      fun ?host:host (c, stack) ->
        let now = Unix.gettimeofday () in
	let auth = match ts_c with
	| Some c -> X509.Authenticator.chain_of_trust ~time:now c
	| None -> X509.Authenticator.null
	in
	(*lwt auth = X509_lwt.authenticator (`Ca_file "/home/jocbe/sdev/ConsT/certs/demoCA.crt") in*)
        lwt (ic, oc) = Tls_lwt.connect auth (ts_host, ts_port) in
        lwt () = Lwt_io.write_value oc (`Single ((r_host, r_port), ((c, stack), host))) in
	lwt resp = Lwt_io.read_value ic in
        let msg = match resp with
	  | `Unsupported -> "Server does not support single requests!"
          | `Single `Ok _ -> "Trusted."
          | `Single `Fail _ -> "NOT trusted!"
	  | `Policy _ -> "Expected `Single, got `Policy"
          | _ -> "ERROR: unexpected response."
	in
	let res = match resp with
	  | `Single r -> r
	  | `Policy _ -> raise (Unexpected_response "Expected a `Single response, got a `Policy")
	  | `Unsupported -> raise (Unexpected_response "Server does not support `Single requests")
	  | _ -> raise (Unexpected_response "Got an unexpected response from server")
	in
        lwt () = d 4 ("GOT: " ^  msg ^ "\n") in
        return res
      end 

  let remote_ca_file ts_info c_path r_info =
    lwt cert_list = X509_lwt.certs_of_pem c_path in
    remote ts_info (Some cert_list) r_info
  
  let ca_list cas =
    let now = Unix.gettimeofday () in
    return (X509.Authenticator.chain_of_trust ~time:now cas)
  let ca_file path =
    lwt cert_list = X509_lwt.certs_of_pem path in
    ca_list cert_list
  let ca_dir path =
    lwt cert_list = X509_lwt.certs_of_pem_dir path in
    ca_list cert_list
end

module Comp = struct
  type mode = [ `Strict | `Allow_failures ] 
  (* (number of authenticators to execute * number of authenticators that need to return `Ok) * ((authlet * priority (lower = higher priority)) list)  *)
  type t = [ `Comp of (int * int * mode) * ((Authlet.t * int) list) | `Single of Authlet.t ]

  let single ?priority authlet = 
    let p = match priority with
      | None -> 0
      | Some p -> p
    in (`Single authlet, p)
  let comp ?priority (num_execute, num_ok, mode) authlet = 
    let p = match priority with
      | None -> 0
      | Some p -> p
    in
    (`Comp ((num_execute, num_ok, mode), [authlet]), p)
  let add comp authlet = 
    match comp with
    | `Comp (c_data, aas) -> `Comp (c_data, authlet :: aas)
    | _ -> raise (Invalid_argument "Expected `Comp composition")
  let update_comp_data comp new_data = 
    match comp with
    | `Comp (c_data, aas) -> `Comp (new_data, aas)
    | _ -> raise (Invalid_argument "Expected `Comp composition")

  let contain comp =
    let contain_pair (authlet, priority) = 
      lwt contained = Authlet.contain authlet in
      return (contained, priority)
    in
    match comp with
    | `Single a -> 
      lwt new_a = Authlet.contain a in
      return (`Single new_a)
    | `Comp (c_data, aas) -> 
      lwt new_aas = Lwt_list.map_p contain_pair aas in
      return (`Comp (c_data, new_aas))
end

module Conf = struct
  type conf_item = Comp.t * int
  type cache_item = Cache.t * int
  type t = { auths  : conf_item list ; 
	     cache_specs : cache_item list;
	     caches : ( Cache.compiled * int ) list }

  let extract n = 
    match n with
    | None -> 0
    | Some n -> n
  	
  let empty_conf = { auths = []; cache_specs = []; caches = [] }
  let new_conf auths cache_specs = { auths = auths; cache_specs = cache_specs; caches = [] }
  let of_authlet ?priority authlet = 
    { auths = [(`Single authlet, extract priority)]; cache_specs = []; caches = [] }
  let of_comp ?priority comp = 
    { auths = [(comp, extract priority)]; cache_specs = []; caches = [] }
  let of_a_list ?priority list = 
    lwt a = Lwt_list.map_p (fun authlet -> return (`Single authlet, extract priority)) list in
    return { auths = a; cache_specs = []; caches = [] }
  let of_a_plist list = 
    lwt a = Lwt_list.map_p (fun (authlet, p) -> return (`Single authlet, p)) list in
    return { auths = a; cache_specs = []; caches = [] }
  let add_authlet conf ?priority authlet = { 
    auths = (`Single authlet, extract priority) :: conf.auths;
    cache_specs = conf.cache_specs; 
    caches = conf.caches
  }
  let add conf ?priority comp = {
    auths = (comp, extract priority) :: conf.auths;
    cache_specs = conf.cache_specs;
    caches = conf.caches
  }
  let add_cache conf ?priority cache = { 
    auths = conf.auths;
    cache_specs = (cache, extract priority) :: conf.cache_specs;
    caches = conf.caches
  }
  (*let add_caches conf caches = {
    auths = conf.auths;
    cache_specs = *)
  
  let conf_to_string conf =
    "NOT YET IMPLEMENTED" 
  let string_to_conf str =
    { auths = [(`Single `None, 0)]; cache_specs = []; caches = [] }

  let prepare conf = 
    let compile_cache = fun (c, p) -> 
      lwt compiled = Cache.compile c in
      return (compiled, p)
    in
    lwt compiled = Lwt_list.map_p compile_cache conf.cache_specs in
    return { auths = conf.auths; cache_specs = []; caches = compiled }
    
    
      
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
      | `Remote (ts_info, ts_cert) -> Authenticator.remote ts_info ts_cert host_info
      | `Remote_ca_file (ts_info, path) -> Authenticator.remote_ca_file ts_info path host_info
      | `Ca_file path -> Authenticator.ca_file path
      | `Ca_dir path -> Authenticator.ca_dir path
      | `Ca_list certs -> Authenticator.ca_list certs
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
      | (`Single a, p) -> 
	lwt auth = compile_authlet a host_info in
        return (auth, p)
      | (`Comp c, p) -> 
	lwt comp = compile_comp c host_info in
        return (comp, p)
    in
    let extract_errs_pred = fun v -> 
      let ret = match v with
        | (_, Some (`Fail _)) -> true
        | _ -> false
      in
      return ret
    in
    (* Make sure we don't have any cache_specs that haven't been precompiled ('prepared') yet *)
    if List.length conf.cache_specs > 0 then
      raise (Invalid_argument "Caches must be compiled before the conf can be built (hint: use 'prepare conf')")
    else

      (* Compare the returned certs to each other? *)
      let comp = fun x -> 
	lwt compiled = compile (r_host, r_port) x in
        return (compiled, None)
      in
      lwt authl = Lwt_list.map_p comp conf.auths  in
      let cachl = List.sort (fun (_, p1) (_, p2) -> p1 - p2) conf.caches in
      return begin
	fun ?host:host (c, stack) -> 
        
	  let rec calc_result authl cachl = 
	    let calc ?priority ((a, p), prev_res) =
	      let eval = match priority with
		| None -> prev_res = None
		| Some n -> (prev_res = None) && p <= n
	      in
	      lwt () = d 7 ("priority is: " ^ (match priority with | None -> "NONE" | Some x -> string_of_int x) ^ "\n") in
	      if eval then
		lwt res = authenticate ?host:host (c, stack) a in
		return ((a, p), Some res)
	      else
	        return ((a, p), prev_res)
	    in
            let rec get_first_res authl =
	      match authl with
	      | [] -> raise (Invalid_argument "No `Ok result found")
	      | (_, None) :: tail -> get_first_res tail
	      | (_, Some res) :: _ -> res
	    in
	    match cachl with
	      | [] -> begin
		lwt resl = Lwt_list.map_p calc authl in
                lwt errl = Lwt_list.filter_p extract_errs_pred resl in                
                if List.length errl > 0 then
		  return (get_first_res errl)
		else
		  return (get_first_res resl)
		end
              | (cache, priority) :: caches -> 
		let res = cache#get_res (r_host, r_port) ?host:host (c, stack) in
		match res with
		| `Not_found ->
		  lwt () = d 6 "Cache miss\n" in
		  calc_result authl caches
		| `Res (`Fail f) ->
		  lwt () = d 6 "Cache fail\n" in
		  return (`Fail f)
		| `Res (`Ok c) ->
		  lwt () = d 6 "Cache ok\n" in
		  lwt resl = Lwt_list.map_p (calc ~priority:priority) authl in
                  lwt errl = Lwt_list.filter_p extract_errs_pred resl in
                  if List.length errl > 0 then
		    return (get_first_res errl)
		  else
		    try
		      let auth_res = get_first_res resl in
		      return auth_res
		    with
		      Invalid_argument _ -> return (`Ok c)
	  in
  
	  (*lwt resl = Lwt_list.map_p (authenticate ?host:host (c, stack)) authl in
          lwt errl = Lwt_list.filter_p filterp resl in
          if List.length errl > 0 then
            return (List.nth errl 0)
          else 
  	    return (List.nth resl 0)*)
          lwt res = calc_result authl cachl in
	  lwt () = Lwt_list.iter_p (fun (cache, _) -> cache#set (r_host, r_port) ?ttl:None c res; return ()) cachl in
	  return res
      end 
    
  let contain conf = 
    let contain_pair = fun (c, p) ->
      lwt contained = Comp.contain c in
      return (contained, p)
    in
    lwt contained = Lwt_list.map_p contain_pair conf.auths in
    return { auths = contained; cache_specs = conf.cache_specs; caches = conf.caches }
end


