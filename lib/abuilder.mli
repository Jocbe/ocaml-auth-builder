
module Authlet : sig
  type with_depend = [ 
    | `Ca_file of string
    | `Ca_dir of string
    | `Remote_ca_file of (string * int) * string
  ]
  
  type self_contained = [
    | `None
    | `Logger of string
    | `Remote of (string * int) * X509.Cert.t list option
    | `Ca_list of X509.Cert.t list
  ]

  type t = [ self_contained | with_depend ]

  val null : t
  val logger : string -> t
  val remote : ?cert:X509.Cert.t list -> ?port:int -> string -> t
  val remote_ca_file : string -> ?port:int -> string -> t
  val ca_file : string -> t
  val ca_dir : string -> t
  val ca_list : X509.Cert.t list -> t

  val contain : t -> self_contained Lwt.t
end

module Cache : sig
  type t = [ `Simple of float ]
  (* TODO: improve type declaration for res *)
  type auth_res = [ `Ok of Certificate.certificate | `Fail of Certificate.certificate_failure ]
  type res = [ `Res of auth_res | `Not_found ]
  type compiled = < 
    get_res : ( string * int ) -> ?host:Certificate.host -> Certificate.stack -> res ;
    get_cert : ( string * int ) -> Certificate.certificate ;
    set : ( string * int ) -> ?ttl:float -> Certificate.certificate -> auth_res -> unit ;
    remove_stale_entries : unit
  >
  
  val simple : float -> t
  
  (*val compile : t -> compiled Lwt.t*)
end

module Authenticator : sig
  exception Unexpected_response of string
end

module Comp : sig
  type mode = [ `Strict | `Allow_failures ] 
  type t = [ `Comp of ( int * int * mode ) * (( Authlet.t * int ) list ) | `Single of Authlet.t ]

  val single : ?priority:int -> Authlet.t -> ( t * int )
  val comp : ?priority:int -> ( int * int * mode ) -> ( Authlet.t * int ) -> ( t * int)
  val add : t -> ( Authlet.t * int) -> t
  val update_comp_data : t -> ( int * int * mode) -> t

  val contain : t -> t Lwt.t
end

module Conf : sig
  type conf_item = Comp.t * int
  type cache_item = Cache.t * int
  type t = { auths  : conf_item list ;
	     cache_specs : cache_item list ;
	     caches : ( Cache.compiled * int ) list }
  
  val empty_conf : t
  val new_conf : conf_item list -> cache_item list -> t
  val of_authlet : ?priority:int -> Authlet.t -> t
  val of_comp : ?priority:int -> Comp.t -> t
  val of_a_list : ?priority:int -> Authlet.t list -> t Lwt.t
  val of_a_plist : ( Authlet.t * int ) list -> t Lwt.t
  val add_authlet : t -> ?priority:int -> Authlet.t -> t
  val add : t -> ?priority:int -> Comp.t -> t
  val add_cache : t -> ?priority:int -> Cache.t -> t
  
  (*val conf_to_string : t -> string
  val string_to_conf : string -> t*)
  val prepare : t -> t Lwt.t
  val build : t -> (string * int) -> X509.Authenticator.t Lwt.t

  val contain : t -> t Lwt.t
end
