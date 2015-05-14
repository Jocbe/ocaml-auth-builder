type client_policy = Trust_client.client_policy

(* The client policy includes an authlet configuration that the
   client uses to authenticate certificates. The server authenticates
   certificates using the server authlet configuration *)

type t = < (* Starts the server *)
           run : unit Lwt.t ;
           
	   (* Get, set and remove the client policy *)
           get_policy : client_policy option ;
	   set_policy : client_policy -> unit ;
	   rm_policy : unit ;
	   
	   (* Get, set and remove the server authlet configuration *)
	   get_conf : Abuilder.Conf.t option ;
	   set_conf : Abuilder.Conf.t -> unit ;
	   rm_conf : unit ;
	   
	   (* Update settings *)
	   set_auto_update : ( client_policy -> client_policy option ) -> float -> float -> unit ;
	   auto_update_mode : [ `Off | `Active | `Lazy ] -> unit ;
	   start_auto_update : unit Lwt.t ;
	   stop_auto_update : unit ;
	 >

(* Instantiate a new trust server. The server_conf is the authlet
   configuration used to authenticate certificates on the trust sever.
   The client_policy is the policy sent to any clients that request it.
   Clients will use the configuration contained in the policy to
   authenticate certificates. *)
val create : ?server_conf:Abuilder.Conf.t -> ?client_policy:client_policy -> Lwt_unix.sockaddr -> int -> X509_lwt.priv -> t
