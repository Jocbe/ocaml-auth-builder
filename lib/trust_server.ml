open Lwt

type client_policy = Trust_client.client_policy
(*type server_policy = Abuilder.Conf.t*)
type response = [ `Policy of client_policy | `Single of X509.Authenticator.res | `Unsupported ]

type t = < run : unit Lwt.t ;
           get_policy : client_policy option ;
	   set_policy : client_policy -> unit ;
	   rm_policy : unit ;
	   get_conf : Abuilder.Conf.t option ;
	   set_conf : Abuilder.Conf.t -> unit ;
	   rm_conf : unit ;
	   set_auto_update : ( client_policy -> client_policy option ) -> int -> float -> unit ;
	   auto_update_mode : [ `Off | `Active | `Lazy ] -> unit ;
	   start_auto_update : unit ;
	   stop_auto_update : unit ;
         >

let create ?server_conf ?client_policy sock_addr max_con cert_key_pair =
  object
    val mutable policy = client_policy
    val mutable conf = server_conf
    val mutable updater = None
    val mutable auto_update = false
    val mutable auto_update_mode = `Off
    val mutable update_poll_time = 0
    val mutable update_rest_time = 0.0
    method run =
      let check_for_updates () =
	match policy with
	| Some p -> begin
	  let now = Unix.gettimeofday () in
	  if auto_update_mode = `Lazy && p.Trust_client.use_until < now +. update_rest_time then
	    match updater with
	    | Some f -> policy <- f p
	    | None -> ()
	end
	| None -> ()	    
      in
      let worker ic oc sockaddr () =
        lwt req = Lwt_io.read_value ic in
        let str = ref "" in
        lwt resp =
          match req with
          | `Policy -> begin
            match policy with
            | Some p ->
	      check_for_updates ();
	      str := "Returning client policy.";
	      return (`Policy p)
            | None -> str := "Client policy is NOT SUPPORTED!"; return `Unsupported
          end
          | `Single ((r_host, r_port), ((c, stack), host)) -> begin
            match conf with
            | Some cnf -> begin
                lwt authenticator = Abuilder.Conf.build cnf (r_host, r_port) in
                lwt result = X509.Authenticator.authenticate authenticator ?host:host (c, stack) in
                str := "Returning result for host '" ^ r_host ^ "', Port " ^ string_of_int r_port ^ ".";
                return (`Single result)
              end  
            | None -> str := "Single requests are NOT SUPPORTED!"; return `Unsupported
          end
          | _ -> str := "Unsupported request."; return `Unsupported
        in
        lwt () = Lwt_io.(write_value oc resp >> printf "%s\n" !str >> close oc >> close ic) in
        return ()
      
    (*lwt authenticator = Abuilder.Conf.build auth_policy (r_host, r_port) in
    lwt result = X509.Authenticator.authenticate authenticator ?host:host (c, stack) in
      lwt () = Lwt_io.(write_value oc result >> printf "Host '%s', Port %i\n" r_host r_port >> close oc >> close ic) in
      return ()*)
      in
      let rec listener server_socket =
        try_lwt
          lwt ((ic, oc), sockaddr) = Tls_lwt.accept cert_key_pair server_socket in
          Lwt.async (worker ic oc sockaddr); return ();
          listener server_socket
        with
          Tls_lwt.Tls_failure _ -> begin
            Lwt_io.print "TLS failure when client connecting\n";
          end;
        listener server_socket
      in
      let server_socket = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
      Lwt_unix.bind server_socket sock_addr;
      Lwt_unix.listen server_socket max_con;
      listener server_socket

    method get_policy = policy
    method set_policy p = policy <- Some p
    method rm_policy = policy <- None
    method get_conf = conf
    method set_conf c = conf <- Some c
    method rm_conf = conf <- None
    method set_auto_update f poll_time rest_time =
      updater <- Some f;
      update_poll_time <- poll_time;
      update_rest_time <- rest_time
    method auto_update_mode m = auto_update_mode <- m
    method start_auto_update = 
      match updater with
      | None -> ()
      | Some f ->
	match policy with
	| None -> ()
	| Some p ->
	  auto_update <- true;
	  while auto_update do
	    let now = Unix.gettimeofday () in
	    if (now +. update_rest_time) > p.Trust_client.use_until && p.Trust_client.use_until > 0.0 then
	      policy <- f p;
	    Unix.sleep update_poll_time
	  done
    method stop_auto_update = auto_update <- false
  end


(*let run_server ?server_conf ?client_policy sock_addr max_con cert_key_pair = 
  lwt () = Tls_lwt.rng_init () in
  
  lwt client_policy =
    match client_policy with
    | None -> return None
    | Some p -> 
      lwt new_c = Abuilder.Conf.contain p.Trust_client.conf in
      return (Some (Trust_client.replace_field ~conf:new_c p))
  in
      
  
*)

