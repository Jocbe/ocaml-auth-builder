type client_policy = { conf : Abuilder.Conf.t ; 
		       version : int option ; 
		       use_until : float ; 
		       new_conf : ( ( string * int ) * Abuilder.Conf.t ) option
		     }
type t = < connect : string * int -> (Tls_lwt.ic * Tls_lwt.oc) Lwt.t ;
           force_update : unit ;
	   get_policy : client_policy ;
	   set_policy : client_policy -> unit >
val replace_field : ?conf:Abuilder.Conf.t -> ?ver:int option -> ?use_time:float -> ?new_c:((string * int) * Abuilder.Conf.t) option -> client_policy -> client_policy
val client_policy : ?ver:int -> ?use_time:float -> ?new_c:((string * int) * Abuilder.Conf.t) -> Abuilder.Conf.t -> client_policy
val from_policy : client_policy -> t Lwt.t
val from_ts_info : ((string * int) * Abuilder.Conf.t) -> t Lwt.t
