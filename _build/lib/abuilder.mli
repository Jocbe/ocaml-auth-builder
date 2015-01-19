type authlet = [ `None | `Logger ]
  
type conf = authlet list

val build : conf -> X509.Authenticator.t
val add : conf -> authlet -> conf
val conf_to_string : conf -> string
val string_to_conf : string -> conf
