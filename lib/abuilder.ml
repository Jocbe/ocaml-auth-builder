open Lwt

module Authlet = struct
  type t = [ `None | `Logger of string ]

  let null = `None
  let logger logfile = `Logger logfile
    
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
      | `Logger log -> return X509.Authenticator.null
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
    return (
      fun ?host:host (c, stack) -> 
        lwt resl = Lwt_list.map_p (authenticate ?host:host (c, stack)) authl in
        lwt errl = Lwt_list.filter_p filterp resl in
        if List.length errl > 0 then
          return (List.nth errl 0)
        else 
  	  return (List.nth resl 0)
    )
end


