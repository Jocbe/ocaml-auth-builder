open Lwt

type client_policy = { conf : Abuilder.Conf.t ; 
		       version : int option ; 
		       use_until : float ; 
		       new_conf : ( ( string * int ) * Abuilder.Conf.t ) option
		     }
type t = < connect : string * int -> (Tls_lwt.ic * Tls_lwt.oc) Lwt.t ;
	   force_update : unit ;
	   get_policy : client_policy ;
	   set_policy : client_policy -> unit
	 >

let replace_field ?conf ?ver ?use_time ?new_c client_p =
  let c = match conf with
    | None -> client_p.conf
    | Some c -> c
  in
  let v = match ver with
    | None -> client_p.version
    | Some v -> v
  in 
  let ut = match use_time with
    | None -> client_p.use_until
    | Some t -> t
  in
  let nc = match new_c with
    | None -> client_p.new_conf
    | Some c -> c
  in
  { conf = c ; version = v ; use_until = ut ; new_conf = nc }

let client_policy ?ver ?use_time ?new_c conf =
  let time = match use_time with
    | Some t -> t
    | None -> -1.0
  in
  { conf = conf ; version = ver ; use_until = time ; new_conf = new_c }

let rec update_policy ?force policy attempts =
  let f = match force with
    | None -> false
    | Some b -> b
  in
  let now = Unix.gettimeofday () in
  if not f && (policy.use_until > now || policy.use_until < 0.0) then
    return policy
  else
    let ((host, port), conf) = match policy.new_conf with
      | None -> raise (Failure "No data to retrieve new policy available")
      | Some nc -> nc
    in
    lwt auth = Abuilder.Conf.build conf (host, port) in
    lwt (ic, oc) = Tls_lwt.connect auth (host, port) in
    lwt resp = Lwt_io.(write_value oc `Policy >> read_value ic) in
    lwt () = Lwt_io.(close oc >> close ic) in
    match resp with
    | `Policy p ->
       let now = Unix.gettimeofday () in
       if p.use_until < now && p.use_until >= 0.0 then
	 if attempts > 0 then
	   update_policy p (attempts - 1)
	 else
	   raise (Failure "Max attempts exceeded")
       else
	 lwt prep_caches = Abuilder.Conf.prepare p.conf in
         let poly = replace_field ~conf:prep_caches p in
	 return poly
    | _ -> raise (Abuilder.Authenticator.Unexpected_response "Expected `Policy")

let new_client_object policy =
  object
    val mutable policy = policy
    method connect (host, port) = begin
      let now = Unix.gettimeofday () in
      lwt poly = update_policy policy 10 in
      policy <- poly;
      (*let () = if p.use_until < now && p.use_until >= 0.0 then
        lwt poly = update_policy !policy 10 in
        return (policy := poly)
      in*)
		  
      lwt auth = Abuilder.Conf.build policy.conf (host, port) in
      Tls_lwt.connect auth (host, port)
    end
    method force_update = Printf.printf "Not yet implemented"
    method get_policy = policy
    method set_policy p = policy <- p
  end

let of_policy policy = 
  lwt contained_conf = Abuilder.Conf.contain policy.conf in
  lwt cont_prep_conf = Abuilder.Conf.prepare contained_conf in
  return (new_client_object (replace_field ~conf:cont_prep_conf policy))

let of_ts_info ((host, port), conf) =
  lwt auth = Abuilder.Conf.build conf (host, port) in
  lwt (ic, oc) = Tls_lwt.connect auth (host, port) in
  lwt resp = Lwt_io.(write_value oc `Policy >> read_value ic) in
  lwt () = Lwt_io.(close oc >> close ic) in
  let policy = match resp with
    | `Policy p -> p
    | _ -> raise (Failure "Couldn't retrieve policy")
  in
  of_policy policy
