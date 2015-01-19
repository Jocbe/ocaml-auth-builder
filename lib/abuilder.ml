open Lwt

type authlet = [ `None | `Logger ]
type conf = authlet list

let build conf = 
  X509.Authenticator.null

let add conf authlet =
  conf

let conf_to_string conf =
  "NOT YET IMPLEMENTED"

let string_to_conf str =
  [`None]

