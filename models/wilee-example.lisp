;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Defining the enterprise and its capability map
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; We'll regard anything not within the 192.168 class B as the rest of the world

;;; The outside world is anything outside our Class B address space
(defexternal-internet outside ("192.168.0.0" "255.255.0.0"))

;;; Our attacker lives somewhere out there
(define-attacker attacker 
    :location outside
    :download-servers attacker-download-server
    :adware-servers attacker-adware-server)

;;; This is the name of our enterprise
(define-enterprise victim)

;;; An authorization pool is a group of identities and privileges
;;; managed in a unified way.
;;; For the moment we're going to assume that all privileges
;;; are manaaged in an enterprise-wide manner
(defauthorization-pool victim-authorization-pool)

;;; There is a capability called sysadmin, they can do anything
;;; as the rest will make clear
(defcapability sysadmin victim-authorization-pool)

;;; Vanilla ability to read any user file
;;; "Greater" Means that Sysadmin has this privilege
(defcapability user-read victim-authorization-pool
  :greater (sysadmin))

;;; Vanilla ability to write any user file
(defcapability user-write victim-authorization-pool
  :lesser (user-read)
  :greater (sysadmin))

;;; Ability to read the "low" data on the database servers
;;; Anybody with vanilla user read privileges can get to this data
(defcapability data-low-read victim-authorization-pool
  :greater (user-read))

;;; Ability to write the "low" data on the database servers
;;; Anybody with vanilla user write privileges can get to this data
(defcapability data-low-write victim-authorization-pool
  :lesser (user-read)
  :greater (user-write))

;;; Ability to read the "high" data on the database servers
;;; Sysadmins have this capability
(defcapability data-high-read victim-authorization-pool
  :greater (sysadmin))

;;; Ability to write the "high" data on the database servers
;;; Sysadmins have this capability
(defcapability data-high-write victim-authorization-pool
  :lesser (data-high-read)
  :greater (sysadmin))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 
;;; The networking environment of our Enterprise
;;; There are 3 enclaves (called "sites" here)
;;; The worker enclave
;;; The sysadmin enclave
;;; and the server enclave
;;; They are on separate subnets:
;;; 192.168.0.x, 192.168.10.x, 192.168.20.x
;;; 
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The worker enclave
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defsite worker-enclave ("192.168.0.0" "255.255.255.0")
	 :enterprise victim)

(defsubnet worker-subnet switched-subnet ("192.168.0.0" "255.255.255.0"))

;;; An esemble is a group of computers that are essentially identical from
;;; our point of view
(defensemble worker-computers
    :enterprise victim
    :size 40
    :address-range ("192.168.0.0" "255.255.255.0")
    )

;;; The typical worker computer is a "windows" computer
;;; It is a typical meember of the worker-computers ensemble
(defcomputer typical-worker-computer windows-computer
  :ip-address-string "192.168.0.3"
  :typical t
  :authorization-pool victim-authorization-pool
  :ensemble worker-computers
  :superuser ()
  ) 

;;; Typical worker bee is a typical user of a typical
;;; computer in the worker-computers ensemble
;;; This user has "user-write" capabilities
;;; meaning they can read-or-write any resource that
;;; requires read or write capability
(defuser typical-worker-bee
    :user-type normal-user
    :ensemble worker-computers
    :computers (typical-worker-computer)
    :typical t
    :capabilities (user-write)
    :authorization-pools (victim-authorization-pool)
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The sysadmin enclave
;;; Similar to the user enclave
;;; except that the typical user here has sysadmin privileges
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defsite admin-enclave ("192.168.10.0" "255.255.255.0")
	 :enterprise victim)

(defsubnet admin-subnet switched-subnet ("192.168.10.0" "255.255.255.0"))

(defensemble admin-computers
    :enterprise victim
    :size 5
    :address-range ("192.168.10.0" "255.255.255.0")
    )

(defcomputer typical-admin-computer unix-computer
  :ip-address-string "192.168.10.3"
  :typical t
  :authorization-pool victim-authorization-pool
  :ensemble admin-computers
  )

(defuser typical-sysadmin
  :user-type admin-user
  :ensemble admin-computers
  :computers (typical-admin-computer typical-worker-computer)
  :typical t
  :authorization-pools (victim-authorization-pool)
  :capabilities (sysadmin)
  :superuser-for (typical-worker-computer typical-admin-computer)
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The server enclave
;;; There are no typical users here, because nobody is supposed to be logged
;;; onto a server, just use its services
;;; There are two servers, one carrying "low" data and the other "high" data
;;; The data resources are defined further down
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defsite server-enclave ("192.168.20.0" "255.255.255.0")
	 :enterprise victim)

(defsubnet server-subnet switched-subnet ("192.168.20.0" "255.255.255.0"))

(defensemble server-computers
  :enterprise victim
  :size 2
  :address-range ("192.168.20.0" "255.255.255.0")
  )

(defcomputer email-server unix-computer
  :ip-address-string "192.168.20.5"
  :typical nil
  :authorization-pool victim-authorization-pool
  :ensemble server-computers)

;;; Note, check blacklist for email protocol
;;; also should really be smtp not email
(defprocess email-server-process
    :process-type email-server-process
    :computer email-server
    )

(def-email-clients email-server-process typical-worker-bee typical-sysadmin)

(defcomputer low-data-server unix-computer
  :ip-address-string "192.168.20.3"
  :typical nil
  :authorization-pool victim-authorization-pool
  :ensemble server-computers)

(defcomputer high-data-server unix-computer
  :ip-address-string "192.168.20.4"
  :typical nil
  :authorization-pool victim-authorization-pool
  :ensemble server-computers)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The router, switches and "firewall" rules
;;; The router is addressable at the 1 position in each subnet
;;; The switch is addressable at the 2 position in its subnet
;;; Vanilla computers start at 3 within their subnet
;;; Anybody coming in would have to pass through the router
;;; and through one switch for the subnet they want to penetrate
;;; Also each router or switch defines a set of rules for what traffic they will forward
;;; These are specified by whitelists and blacklists
;;; The planner's view is that routers and switches will forward any traffic that isn't
;;; blacklisted
;;; Because routers and switches are also hosts, we need to specify not only
;;; what traffic they pass but also what connections they will accept (any host can do this)
;;; If a blacklist (or whitelist) specifies :for-host t, then that is specifying what
;;; connection they will accept.  If not, then it specifies what traffic it will pass
;;; 
;;; Normally a blacklist will specify a range of addresses that are blocked as an ip-address and mask
;;; (specified in the ":block" field.
;;; But there can be holes in this range, specified in the :exceptions field
;;; (similary for white lists, but I didn't use whitelists because the default
;;; is to pass everything not blocked).
;;;
;;; There is a shorthand: "everywhere" means the entire internet (i.e. 0.0.0.0 0.0.0.0)
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; the Main Router
;;; Note that routers and switches are both network "bridges" and computers.
;;; 
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrouter victim-router ("192.168.0.1"  "192.168.10.1" "192.168.20.1")
  :authorization-pool victim-authorization-pool
  :superuser typical-sysadmin
  :external-networks (outside))

;;; These whitelist and blacklist descriptions are supposed to say
;;; what traffic will be allowed to pass in from the outside
;;; However, note that all inter-enclave traffic will go through this router as well
;;; So we have to be careful about allowing those

;;; The router will reject TELNET packets from anywhere (including the 192.168.x.x range)
(defblacklist (telnet victim-router)
    :block everywhere
    )

;;; The router is itself a computer and will not accept telnet or email
;;; connections even if they get through the routing infrastructure
(defblacklist (email victim-router)
    :for-host t
    :block everywhere
    )

(defblacklist (telnet victim-router)
    :for-host t
    :block everywhere
    )

;;; The router as a computer will only accept ssh and http connections
;;; from the administrative subnet
(defblacklist (ssh victim-router)
    :for-host t
    :block everywhere
    :exceptions (("192.168.10.0"  "255.255.0.0"))
    )

(defblacklist (http victim-router)
    :for-host t
    :block everywhere
    :exceptions (("192.168.10.0"  "255.255.0.0"))
    )

;;; The router will reject any attempt to access a database from outside 192.168.x.x
(defblacklist (database-protocol victim-router)
    :block everywhere
    :exceptions (("192.168.0.0"  "255.255.0.0"))
    )

;;; but will allow internal traffic to get to the database
;;; this is redudant with the "permissive" policy
;;;(defwhitelist (database-protocol victim-router)
;;;    :pass ("192.168.0.0"  "255.255.0.0")
;;;    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The worker net switch
;;; The worker switch imposes no more restrictions that the router/firewall
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defswitch worker-net-switch wired-switch "192.168.0.2"
	   :authorization-pool victim-authorization-pool
	   :superuser typical-sysadmin
	   )


;;; sort of redundant since the main router blocks it
(defblacklist (telnet worker-net-switch)
    :block everywhere
    )

;;; The switch as a computer will not 
;;; accept telnet or email connections from anywhere
(defblacklist (telnet worker-net-switch)
    :for-host t
    :block everywhere
    )

(defblacklist (email worker-net-switch)
    :for-host t
    :block everywhere
    )

;;; the switch will not accept http or ssh connections as a computer
;;; accept from the administrative subnet
(defblacklist (ssh worker-net-switch)
    :for-host t
    :block everywhere
    :exceptions (("192.168.10.0" "255.255.0.0"))
    )

(defblacklist (http worker-net-switch)
    :for-host t
    :block everywhere
    :exceptions (("192.168.10.0" "255.255.0.0"))
    )

;;; We'll block database protocol requests from outside
;;; Redudant with the main router
(defblacklist (database-protocol worker-net-switch)
    :block everywhere
    :exceptions (("192.168.0.0"  "255.255.0.0"))
    )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The admin net switch and its blacklists
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;



;;; the Admin switch will block ssh attempts from anywhere outside the 192.168.x.x range
(defswitch admin-net-switch wired-switch "192.168.10.2"
	   :authorization-pool victim-authorization-pool
	   :superuser typical-sysadmin
	   )

(defblacklist (telnet admin-net-switch)
    :block everywhere
    )

;;; block telnet or email connections from anywhere
(defblacklist (telnet admin-net-switch)
    :for-host t
    :block everywhere
    )

(defblacklist (email admin-net-switch)
    :for-host t
    :block everywhere
    )

;;; the switch will not accept http or ssh connections as a computer
;;; accept from the administrative subnet
(defblacklist (ssh admin-net-switch)
    :for-host t
    :block everywhere
    :exceptions (("192.168.10.0" "255.255.0.0"))
    )

(defblacklist (http admin-net-switch)
    :for-host t
    :block everywhere
    :exceptions (("192.168.10.0" "255.255.0.0"))
    )

;;; For admin net we'll only accept SSH from within
;;; the enclave
;;; this is redudant with the "permissive" policy
;;;(defwhitelist (ssh admin-net-switch)
;;;    :pass ("192.168.0.0"  "255.255.0.0")
;;;    )

(defblacklist (ssh admin-net-switch)
    :block everywhere
    ;; :exceptions (("192.168.0.0"  "255.255.0.0"))
    )

(defblacklist (http admin-net-switch)
    :block everywhere
    :exceptions (("192.168.0.0"  "255.255.0.0"))
    )

(defblacklist (email admin-net-switch)
    :block everywhere
    :exceptions (("192.168.0.0"  "255.255.0.0"))
    )

;;; Redudant with the main router
(defblacklist (database-protocol admin-net-switch)
    :block everywhere
    :exceptions (("192.168.0.0"  "255.255.0.0"))
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The server net
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; The server switch won't allow ssh from outside the admin area
(defswitch server-net-switch wired-switch "192.168.20.2"
	   :authorization-pool victim-authorization-pool
	   :superuser typical-sysadmin
	   )

;;; Redundant with the main router, but no telnet from anywhere
(defblacklist (telnet server-net-switch)
    :block everywhere
    )

;;; block telnet or email connections from anywhere
(defblacklist (telnet server-net-switch)
    :for-host t
    :block everywhere
    )

(defblacklist (email server-net-switch)
    :for-host t
    :block everywhere
    )

;;; the switch will not accept http or ssh connections as a computer
;;; accept from the administrative subnet
(defblacklist (ssh server-net-switch)
    :for-host t
    :block everywhere
    :exceptions (("192.168.10.0" "255.255.0.0"))
    )

(defblacklist (http server-net-switch)
    :for-host t
    :block everywhere
    :exceptions (("192.168.10.0" "255.255.0.0"))
    )

;;; The server won't accept ssh from anywhere
(defblacklist (ssh server-net-switch)
    :block everywhere
    )

;;; also no email traffic coming into here
;;;(defblacklist (smtp server-net-switch)
;;;  :block everywhere
;;;  )
;;;
;;;
;;;(defblacklist (email server-net-switch)
;;;    :block everywhere
;;;    )

(defblacklist (http server-net-switch)
    :block everywhere
    )

;;; The worker-net-switch
(defblacklist (database-protocol server-net-switch)
    :block ("192.168.10.2" "255.255.255.255")
    )

;;; The server-net-switch
(defblacklist (database-protocol server-net-switch)
    :block ("192.168.10.2" "255.255.255.255")
    )

;;; The server-net-switch, probably irrelevent
(defblacklist (database-protocol server-net-switch)
    :block ("192.168.20.2" "255.255.255.255")
    )

;;; the router's server-net port
(defblacklist (database-protocol server-net-switch)
    :block ("192.168.20.1" "255.255.255.255")
    )

;;; the router's admin-net port
(defblacklist (database-protocol server-net-switch)
  :block ("192.168.10.1" "255.255.255.255")
  )

;;; the router's worker-net port
(defblacklist (database-protocol server-net-switch)
    :block ("192.168.0.1" "255.255.255.255")
    )



;;; The server enclave will accept database queries from anybody in our enterprise
;;; this is redudant with the "permissive" policy
;;;(defwhitelist (database-protocol server-net-switch)
;;;    :pass ("192.168.0.0"  "255.255.0.0")
;;;    )


;;; but not from anybody outside our enterprise
(defblacklist (database-protocol server-net-switch)
    :block everywhere
    :exceptions (("192.168.0.0"  "255.255.0.0"))
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The resources and their required capabilities
;;; Here we say what resources (in this case database resources) are available
;;; and what capabilities a user will need to access these resources
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; The high database lives on the high-data-server
;;; To write it requires data-high-write capability (which isn't the same a normal write capability)
;;; similarly for reading.  Sysadmins have this capability
(defresource high-database database
  :computers (high-data-server)
  :capability-requirements ((write data-high-write) (read data-high-read))
  )

;;; The low database lives on a separate server and requires a different set of capabilities
;;; Normal users have these capabilities (as do sysadmins)
(defresource low-database database
  :computers (low-data-server)
  :capability-requirements ((write data-low-write) (read data-low-read))
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Typical query is high-datavase-server data-integrity high-database
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; This is strictly for debugging purposes
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun get-variables ()
  (declare (special worker-computer worker-bee attacker 
		    low-server low-server-os 
		    admin-computer victim-router attacker-computer outside
		    low-database high-database sysadmin high-server high-server-os
		    download-server))
  (setq worker-computer (object-named 'typical-worker-computer)
	worker-bee (object-named 'typical-worker-bee)
	attacker (object-named 'attacker)
	attacker-computer (object-named 'attacker-computer)
	victim-router (object-named 'victim-router)
	low-server (object-named 'low-data-server)
	low-server-os (follow-path `(,low-server os))
	low-database (object-named 'low-database)
	high-database (object-named 'high-database)
	high-server (object-named 'high-data-server)
	high-server-os (follow-path `(,high-server os))
	admin-computer (object-named 'typical-admin-computer)
	outside (object-named 'outside)
	sysadmin (object-named 'typical-sysadmin)
	download-server (follow-path '(attacker-download-server))
	))

(defun test-wilee ()
  (do-it :attacker (follow-path '(attacker))
	 :property 'data-integrity
	 :computer (follow-path '(high-server))
	 :resource (follow-path '(high-database))))

#|
;; TODO: Bug with generic keyword not having methods applicable
(defprogram ie-explorer :generic ie-explorer)

;; pidl-url-attack process solely for internet explorer
(defprocess pidl-url-attack :process-type ie-process :computer high-data-server :program ie-explorer)

|#