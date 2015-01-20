
module Authlet : sig
  type t = [ `None | `Logger of string ]
  
  val null : t
  val logger : string -> t
end

module Conf : sig
  type t = Authlet.t list
  
  val newc : t
  val from_authlet : Authlet.t -> t

  val add : t -> Authlet.t -> t
  val conf_to_string : t -> string
  val string_to_conf : string -> t
  val build : t -> X509.Authenticator.t Lwt.t
end

