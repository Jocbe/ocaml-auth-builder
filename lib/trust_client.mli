(* The client policy includes a couple of fields beyond the conf in order
   to be able to update it. new_conf indicates where the trust server is
   located, which will provide a policy update *)
type client_policy = { conf : Abuilder.Conf.t ; 
		       version : int option ; 
		       use_until : float ; 
		       new_conf : ( ( string * int ) * Abuilder.Conf.t ) option
		     }

type t = < (* Use 'connect' to connect to a remote host via TLS *)
           connect : string * int -> (Tls_lwt.ic * Tls_lwt.oc) Lwt.t ;
           
	   (* Do not use force_ubdate at this point. It is not necessary
	      as updates are performed automatically. If a use case does
	      crop up in which force_update makes sense, it still needs
	      to be implemented *)
           force_update : unit ;

	   get_policy : client_policy ;
	   set_policy : client_policy -> unit >

(* Any field in a trust client's policy can be replaced individually and
   conveniently using replace_field *)
val replace_field : ?conf:Abuilder.Conf.t -> ?ver:int option -> ?use_time:float -> ?new_c:((string * int) * Abuilder.Conf.t) option -> client_policy -> client_policy

(* Create a new client policy by providing at least an authlet configuration *)
val client_policy : ?ver:int -> ?use_time:float -> ?new_c:((string * int) * Abuilder.Conf.t) -> Abuilder.Conf.t -> client_policy

(* Instantiate a client by providing a policy that contains an authlet
   configuration *)
val of_policy : client_policy -> t Lwt.t

(* Instantiate a client by providing only the address and port of the
   trust server from which a policy can be downloaded. *)
val of_ts_info : ((string * int) * Abuilder.Conf.t) -> t Lwt.t
