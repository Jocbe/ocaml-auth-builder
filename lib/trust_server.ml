open Lwt

type client_policy = Trust_client.client_policy
(*type server_policy = Abuilder.Conf.t*)
type response = [ `Policy of client_policy | `Single of X509.Authenticator.res | `Unsupported ]



    


let run_server ?server_conf ?client_policy sock_addr max_con cert_key_pair = 
  lwt () = Tls_lwt.rng_init () in
  
  lwt client_policy =
    match client_policy with
    | None -> return None
    | Some p -> 
      lwt new_c = Abuilder.Conf.contain p.Trust_client.conf in
      return (Some (Trust_client.replace_field ~conf:new_c p))
  in
      
  let worker ic oc sockaddr () =
    (*lwt ((ic, oc), sockaddr) = con in*)
    lwt req = Lwt_io.read_value ic in
    let str = ref "" in
    lwt resp =
      match req with
      | `Policy -> begin
	match client_policy with
	| Some p -> str := "Returning client policy."; return (`Policy p)
	| None -> str := "Client policy is NOT SUPPORTED!"; return `Unsupported
      end
      | `Single ((r_host, r_port), ((c, stack), host)) -> begin
	match server_conf with
	| Some p -> begin
	  lwt authenticator = Abuilder.Conf.build p (r_host, r_port) in
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


