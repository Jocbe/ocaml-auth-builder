
module Authlet : sig
  type with_depend = [ 
    | `Ca_file of string
    | `Ca_dir of string
  ]
  
  type self_contained = [
    | `None
    | `Logger of string
    | `Remote of (string * int) * Certificate.certificate option
    | `Ca_list of X509.Cert.t list
  ]

  type t = [ self_contained | with_depend ]

  val null : t
  val logger : string -> t
  val remote : ?cert:Certificate.certificate -> ?port:int -> string -> t

  val contain : t -> self_contained Lwt.t
end

module Comp : sig
  type mode = [ `Strict | `Allow_failures ] 
  type t = [ `Comp of ( int * int * mode ) * (( Authlet.t * int ) list ) | `Single of Authlet.t ]

  val single : Authlet.t -> t
  val comp : ( int * int * mode ) -> ( Authlet.t * int ) -> t
  val add : t -> ( Authlet.t * int) -> t
  val update_comp_data : t -> ( int * int * mode) -> t

end

module Conf : sig
  type t = Comp.t list
  
  val new_conf : t
  val from_authlet : Authlet.t -> t
  val from_comp : Comp.t -> t
  val add_authlet : t -> Authlet.t -> t
  val add : t -> Comp.t -> t
  
  val conf_to_string : t -> string
  val string_to_conf : string -> t
  val build : t -> (string * int) -> X509.Authenticator.t Lwt.t
end
