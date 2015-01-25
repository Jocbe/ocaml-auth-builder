open Lwt

type auth_policy = Abuilder.Conf.t

let worker ic oc sockaddr auth_policy () =
  lwt req = Lwt_io.read_value ic in
  match req with
  | `Policy -> return ()
  | `Single ((r_host, r_port), ((c, stack), host)) -> 
    lwt authenticator = Abuilder.Conf.build auth_policy (r_host, r_port) in
    lwt result = X509.Authenticator.authenticate authenticator ?host:host (c, stack) in
    lwt () = Lwt_io.(write_value oc result >> printf "Host '%s', Port %i\n" r_host r_port >> close oc >> close ic) in
    return ()
    

let rec listener cert_key_pair server_socket auth_policy =
  lwt ((ic, oc), sockaddr) = Tls_lwt.accept cert_key_pair server_socket in
  Lwt.async (worker ic oc sockaddr auth_policy);
  listener cert_key_pair server_socket auth_policy

let run_server sock_addr max_con cert_key_pair auth_policy = 
  lwt () = Tls_lwt.rng_init () in
  let server_socket = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
  Lwt_unix.bind server_socket sock_addr;
  Lwt_unix.listen server_socket max_con;
  listener cert_key_pair server_socket auth_policy
