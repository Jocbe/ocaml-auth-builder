
module Authlet : sig

  (* The following authlets refer to external resources (e.g. a file on disk).
     These should not be used in policies that are being sent to other devices.
     Use the 'contain' function to convert them to self-contained authlts. *)
  type with_depend = [ 
    | `Ca_file of string
    | `Ca_dir of string
    | `Remote_ca_file of (string * int) * string
    | `Certs of string
  ]
  
  (* The following authlets are self-contained and hence can safely be passed
     to other devices *)
  type self_contained = [
    | `None
    | `Logger of string
    | `Remote of (string * int) * X509.Cert.t list option
    | `Ca_list of X509.Cert.t list
    | `Cert_list of X509.Cert.t list
    | `Notary
  ]

  type t = [ self_contained | with_depend ]

  (* Use the following functions to obtain authlets *)
  val null : t
  val logger : string -> t
  val remote : ?cert:X509.Cert.t list -> ?port:int -> string -> t
  val remote_ca_file : string -> ?port:int -> string -> t
  val ca_file : string -> t
  val ca_dir : string -> t
  val ca_list : X509.Cert.t list -> t
  val notary : t
  val certs : string -> t
  val cert_list : string -> t Lwt.t

  (* Use to return a self-contained authlet from any other *)
  val contain : t -> self_contained Lwt.t

end

module Cache : sig
  
  type t = [ `Simple of float ]
  
  type auth_res = [ `Ok of Certificate.certificate | `Fail of Certificate.certificate_failure ]
  type res = [ `Res of auth_res | `Not_found ]
  
  type compiled = < 
    get_res : ( string * int ) -> ?host:Certificate.host -> Certificate.stack -> res ;
    get_cert : ( string * int ) -> Certificate.certificate ;
    set : ( string * int ) -> ?ttl:float -> Certificate.certificate -> auth_res -> unit ;
    remove_stale_entries : unit
  >
  
  (* Use this to obtain a 'cachlet' that contains the parameters for a simple cache *)
  val simple : float -> t
  
  (* compile is currently not exposed *)
  (*val compile : t -> compiled Lwt.t*)
end

module Authenticator : sig
  exception Unexpected_response of string
end

(* Use compositions to create more complex policies/configurations *)
module Comp : sig
  type mode = [ `Strict | `Allow_failures ] 
  type t = [ `Comp of ( int * int * mode ) * (( Authlet.t * int ) list ) | `Single of Authlet.t ]

  (* Contains only a single authlet. *)
  val single : ?priority:int -> Authlet.t -> ( t * int )

  (* A combination of various authlets *)
  val comp : ?priority:int -> ( int * int * mode ) -> ( Authlet.t * int ) -> ( t * int)
  
  (* Add an authlet to a composition *)
  val add : t -> ( Authlet.t * int) -> t

  val update_comp_data : t -> ( int * int * mode) -> t
  
  (* Use to create a self-contained composition *)
  val contain : t -> t Lwt.t
end

module Conf : sig
  type conf_item = Comp.t * int
  type cache_item = Cache.t * int
  type t = { auths  : conf_item list ;
	     cache_specs : cache_item list ;
	     caches : ( Cache.compiled * int ) list }

  (* Use one of the following function to create a new configuration *)
  val empty_conf : t
  val new_conf : conf_item list -> cache_item list -> t
  val of_authlet : ?priority:int -> Authlet.t -> t
  val of_comp : ?priority:int -> Comp.t -> t
  val of_a_list : ?priority:int -> Authlet.t list -> t Lwt.t
  val of_a_plist : ( Authlet.t * int ) list -> t Lwt.t

  (* Use one of the following function to add elements to a configuration *)
  val add_authlet : t -> ?priority:int -> Authlet.t -> t
  val add : t -> ?priority:int -> Comp.t -> t
  val add_cache : t -> ?priority:int -> Cache.t -> t
  
  (* The human-readable to policy conversion functions are not yet implemented *)
  (*val conf_to_string : t -> string
  val string_to_conf : string -> t*)

  (* Prepare configurations such that caches are ready to cache responses *)
  val prepare : t -> t Lwt.t

  (* Build a configuration to obtain an authenticator that can be used for
     connecting to remote hosts *)
  val build : t -> (string * int) -> X509.Authenticator.t Lwt.t

  (* Use to create a self-contained configuration *)
  val contain : t -> t Lwt.t
end
