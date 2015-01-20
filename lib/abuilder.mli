
module Authlet : sig
  type t = [ `None | `Logger of string ]
end

module Conf : sig
  type t = Authlet.t list
  
  val add : t -> Authlet.t -> t
  val conf_to_string : t -> string
  val string_to_conf : string -> t
  val build : t -> X509.Authenticator.t
end

