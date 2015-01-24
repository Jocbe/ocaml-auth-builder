
module Authlet : sig
  type t = [ 
    | `None 
    | `Logger of string 
    | `Remote of (string * int) * Certificate.certificate option
  ]
  
  val null : t
  val logger : string -> t
  val remote : ?cert:Certificate.certificate -> ?port:int -> string -> t
end

module Conf : sig
  type c_mode = [ `Strict | `Allow_failures ] 
  type composition = [ `Comp of (int * int * c_mode) * ((Authlet.t * int) list) | `Single of Authlet.t ]
  type t = composition list
  
  val new_conf : t
  val from_authlet : Authlet.t -> t

  val add_comp : t -> composition -> t
  val conf_to_string : t -> string
  val string_to_conf : string -> t
  val build : t -> (string * int) -> X509.Authenticator.t Lwt.t
end

