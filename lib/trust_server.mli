type client_policy = Trust_client.client_policy
(*type server_policy = Abuilder.Conf.t*)

(*val run_server : ?server_conf:Abuilder.Conf.t -> ?client_policy:client_policy -> Lwt_unix.sockaddr -> int -> X509_lwt.priv -> unit Lwt.t*)

type t = < run : unit Lwt.t ;
           get_policy : client_policy option ;
	   set_policy : client_policy -> unit ;
	   rm_policy : unit ;
	   get_conf : Abuilder.Conf.t option ;
	   set_conf : Abuilder.Conf.t -> unit ;
	   rm_conf : unit ;
	   set_auto_update : ( client_policy -> client_policy option ) -> int -> float -> unit ;
	   start_auto_update : unit ;
	   stop_auto_update : unit ;
	 >

val create : ?server_conf:Abuilder.Conf.t -> ?client_policy:client_policy -> Lwt_unix.sockaddr -> int -> X509_lwt.priv -> t
