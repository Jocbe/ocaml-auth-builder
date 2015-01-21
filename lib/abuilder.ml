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
  
  let logger path = 
    lwt oc = Lwt_io.open_file ~mode:Lwt_io.Output path in
    return begin
      fun ?host:host (c, stack) ->
        let hst = match host with
          | None -> "UNKNOWN"
          | Some (`Wildcard s) -> s
	  | Some (`Strict s) -> s
        in
        let c_str = Cstruct.to_string (Certificate.cs_of_cert c) in
        Lwt_io.(write_line oc ("\nConnecting to '" ^ hst ^ "' with certificate:")
             >> write_line oc c_str) >> return (`Ok c)
    end

  let remote (ts_host, ts_port) ts_c =
    return begin
      fun ?host:host (c, stack) ->
        (* TODO: how best to authenticate here? *)
        (* TODO: pass cert file as argument to authlet *)
        lwt auth = X509_lwt.authenticator (`Ca_file "/home/jocbe/sdev/ConsT/certs/demoCA.crt") in
        lwt (ic, oc) = Tls_lwt.connect auth (ts_host, ts_port) in
        Lwt_io.write_value oc ((c, stack), host);
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

module Conf = struct
  type t = Authlet.t list

  let newc = []
  let from_authlet authlet = [authlet]

  let add conf authlet =
    authlet :: conf
  
  let conf_to_string conf =
    "NOT YET IMPLEMENTED"
  
  let string_to_conf str =
    [`None]

  let build conf =
    let compile = fun authlet ->
      match authlet with
      | `None -> return X509.Authenticator.null
      | `Logger log -> Authenticator.logger log
      | `Remote ((host, port), cert) -> Authenticator.remote (host, port) cert
    in
    let authenticate ?host:host (c, stack) auth =
      auth ?host:host (c, stack)
    in
    (* Compare the returned certs to each other? *)
    let filterp = fun v -> 
      let ret = match v with
        | `Ok _ -> false
        | _ -> true
      in
      return ret
    in
   
    lwt authl = Lwt_list.map_p compile conf in
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


