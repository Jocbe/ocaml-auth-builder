
module Authlet : sig
  type t = [ 
    | `None 
    | `Logger of string 
    | `Remote of (string * int) * Certificate.certificate option
  ]
  
  type self_contained = [
    | `None
    | `Logger of string
    | `Remote of (string * int) * Certificate.certificate option
  ]

  type gen = [ t | self_contained ]

  val null : t
  val logger : string -> t
  val remote : ?cert:Certificate.certificate -> ?port:int -> string -> t

  val contain : t -> self_contained
end

module Comp : sig
  type mode = [ `Strict | `Allow_failures ] 
  type t = [ `Comp of ( int * int * mode ) * (( Authlet.gen * int ) list ) | `Single of Authlet.gen ]

  val single : Authlet.gen -> t
  val comp : ( int * int * mode ) -> ( Authlet.gen * int ) -> t
  val add : t -> ( Authlet.gen * int) -> t
  val update_comp_data : t -> ( int * int * mode) -> t

end

module Conf : sig
  type t = Comp.t list
  
  val new_conf : t
  val from_authlet : Authlet.gen -> t
  val from_comp : Comp.t -> t
  val add_authlet : t -> Authlet.gen -> t
  val add : t -> Comp.t -> t
  
  val conf_to_string : t -> string
  val string_to_conf : string -> t
  val build : t -> (string * int) -> X509.Authenticator.t Lwt.t
end
