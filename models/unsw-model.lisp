;;; -*- Mode:common-lisp; package: aplan; readtable: joshua; -*-

(In-package :aplan)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The UNSW Data
;;; 
;;; The ATTACKER computers:  175.45.176.0 - 175.45.176.3
;;;
;;; I.e these are the computers that are in the source field of 
;;; records that are marked at attacks
;;;
;;; The VICTIME computers:   149.171.126.10 - 149.171.126.19
;;;
;;; The SERVER computers: 59.166.0.0 - 59.166.0.9
;;;
;;; There's nothing in the UNSW data that indicates that these are server
;;; computers, I'm just making that up.
;;;
;;; I.e. these are the computers that are in the detination fields of 
;;; records that are marked as attacks
;;; There are other computers in the range 149.171.126.0 = 149.171.126.9
;;; that aren't targets
;;;
;;; And all of the ips are as follows 
;;; Leadering 3 octets            All values that appear
;;; 10,40.85                     (1 30)
;;; 10.40.170                    (2)
;;; 10.40.182                    (1 3)
;;; 10.40.198                    (10)
;;; 32.50.32                     (66)
;;; 59.166.0                     (0 1 2 3 4 5 6 7 8 9)
;;; 127.0.0                      (1)
;;; 149.171.126                  (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19)
;;; 175.45.176                   (0 1 2 3)
;;; 192.168.241                  (243)
;;; 224.0.0                      (1 5)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The external world in which the attacker lives
;;;
;;; In previous models we always modeled the attacker as being anywhere
;;; other than the enterprise (using defexternal-internet)
;;; In this case, we're assuming we know more and have localized the attacker
;;; to a very specific area.  So we use defsubnet.
;;; Hopefully none of the reaosning is dependent on the use of external-internet
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; Note that these addresses are the things not in "the-wild"
;;; namely the stuff that belongs to the victim

(defexternal-internet the-wild "149.171.126.0/27" "59.166.0.0/29")


;;; This defines an "enterprise" representing the
;;; attacker's organization
(define-enterprise attacker-world
    )

;;; This site is the attacker's small group
(defsite attacker-site "175.45.176.0/30")

;;; This defines the subnet for that site
;;; A bit redundant but a site can have multiple subnets
(defsubnet attacker-subnet shared-media-subnet "175.45.176.0/30")

;;; An ensemble of machines believed to 
;;; belong to the attacker
(defensemble attacker-computers
    :enterprise attacker-world
    :size 4
    :address-range "175.45.176.0/30"
    )

;;; Here's a typical member of that ensemble
(defcomputer typical-attacker-computer linux-computer
    :ip-address-string "175.45.176.0"
    :typical t
    :ensemble attacker-computers
    :superuser ()
    )
    
;;; And a spefic one
(defcomputer attacker-main-computer linux-computer
  :ip-address-string "175.45.176.1"
  :typical nil
  :ensemble attacker-computers
  :superuser ()
  )

;;; This represents the attacker as a user
(define-attacker attacker
    :location attacker-subnet 
    :computer attacker-main-computer
    :other-computers (typical-attacker-computer)
    :download-servers (typical-attacker-computer))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The enterprise 
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; Similar to the attacker we define an enterprise
;;; For the victim
(define-enterprise Victim-Inc
    )

;;; An authorization pool is an abstraction
;;; for defining permissions (called capabilities)
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
;;; The worker computers
;;;
;;; This is modeled as a switched subnet because that's the easiest
;;; way I have to specify "firewall" rules that apply to these computers
;;; specifically
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; This contains computers from 0 - 31
(defsite worker-enclave "149.171.126.0/27"
  :enterprise Victim-Inc
  )

(defsubnet worker-subnet switched-subnet "149.171.126.0/27")

(defensemble worker-computers
    :enterprise victim
    :size 40
    :address-range ("192.168.0.0" "255.255.255.0")
    )

(defcomputer typical-worker-computer windows-computer
  :ip-address-string "149.171.126.3"
  :typical t
  :authorization-pool victim-authorization-pool
  :ensemble worker-computers
  :superuser ()
  ) 

;;; This defines a process that runs on
;;; all worker computers (it says that the typical one has it)
(defprocess worker-web-server-process
    :process-type web-server-process
    :computer typical-worker-computer
    )

;;; The typical workstation user
(defuser typical-worker
    :user-type user
    :ensemble worker-computers
    :computers (typical-worker-computer)
    :typical t
    :capabilities (user-write)
    :authorization-pools (victim-authorization-pool)
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The server computers
;;;
;;; This is modeled as a switched subnet because that's the easiest
;;; way I have to specify "firewall" rules that apply to these computers
;;; specifically
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defsite server-enclave "59.166.0.0/29"
  :enterprise Victim-Inc)

(defsubnet server-subnet switched-subnet "59.166.0.0/29")

(defensemble server-computers
  :enterprise victim
  :size 20
  :address-range "59.166.0.0/29" 
  )

(defcomputer typical-server-computer linux-computer
  :ip-address-string "59.166.0.3"
  :typical t
  :authorization-pool victim-authorization-pool
  :ensemble server-computers
  :superuser ()
  )

(defuser typical-sysadmin
  :user-type user
  :ensemble server-computers
  :computers (typical-server-computer typical-worker-computer)
  :typical t
  :authorization-pools (victim-authorization-pool)
  :capabilities (sysadmin)
  :superuser-for (typical-worker-computer typical-server-computer)
  )

(defcomputer email-server unix-computer
  :ip-address-string "59.166.0.4"
  :typical nil
  :authorization-pool victim-authorization-pool
  :ensemble server-computers)

;;; Note, check blacklist for email protocol
;;; also should really be smtp not email
(defprocess email-server-process
    :process-type email-server-process
    :computer email-server
    )

;;; Define who this email server receives email for
;;; In this case both all the workstation users and
;;; all the sysadmins
(def-email-clients email-server-process typical-worker typical-sysadmin)

(defcomputer database-server unix-computer
  :ip-address-string "59.166.0.5"
  :typical nil
  :authorization-pool victim-authorization-pool
  :ensemble server-computers)

;;; Define a computer resource, In this case the database
;;; It exists on the database server
;;; And requires data-high-write permission to write it
;;; and data-high-read to read it.
;;; Sysadmins have these capabilities
(defresource database database
  :computers (database-server)
  :capability-requirements ((write data-high-write) (read data-high-read))
  )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The Routers and switches
;;;
;;; (these come after typical-sysadmin is specified because
;;; typical-sysadmin is the superuser for them)
;;; 
;;; "Firewall" rules for the main router apply to everything 
;;; in the enterprise
;;; 
;;; Firewall rules for the switches apply only to the subnet that the switch
;;; is on
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; The router that connects the two subnets and the outside world
(defrouter victim-router ("149.171.126.1" "59.166.0.1")
  :authorization-pool victim-authorization-pool
  :superuser typical-sysadmin
  :external-networks (the-wild attacker-subnet))

;;; The switch for the workstation subnet
(defswitch worker-net-switch wired-switch "149.171.126.2"
  :authorization-pool victim-authorization-pool
  :superuser typical-sysadmin)

;;; The switch for the server subnet
(defswitch server-net-switch wired-switch "59.166.0.2"
  :authorization-pool victim-authorization-pool
  :superuser typical-sysadmin)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Firewall Rules
;;; We assume that any traffic can pass through any router or switch
;;; Unless there's a specific blacklist for it
;;; Each rule specifies a service, which router or switch
;;; and what IP addresses it blocks traffic from
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; TELNET: blocked eerywhere at the router
;;; so nobody can receive a telnet connection

(defblacklist (telnet victim-router)
    :block everywhere
    )

;;; block telnet connections to the router itself (:for-host t)
(defblacklist (telnet victim-router)
    :for-host t
    :block everywhere
    )
;;;
;;; SSH: allowed to workers but not the routers
;;; switches or server computers
;;; 

(defblacklist (ssh victim-router)
    ;; for-host means that the traffic is aimed at the switch or
    ;; or router, as opposed to the computers on the subnet
    ;; this guy controls.  So this router won't accept an
    ;; SSH connection to itself from anywhere
    :for-host t
    :block everywhere
    )

(defblacklist (ssh worker-net-switch)
    :for-host t
    :block everywhere
    )

(defblacklist (ssh server-net-switch)
    :for-host t
    :block everywhere
    )

(defblacklist (ssh server-net-switch)
  :for-host nil
  :block everywhere
  )

;;;
;;; Email traffic
;;; Can't go to the router or the switches
;;; Is allowed in the server enclave from anywhere
;;; But isn't allowed into the worker enclave

(defblacklist (email victim-router)
    :for-host t
    :block everywhere
    )

(defblacklist (email worker-net-switch)
    :for-host t
    :block everywhere
    )

(defblacklist (email worker-net-switch)
    :for-host nil
    :block everywhere
    )

(defblacklist (email server-net-switch)
    :for-host t
    :block everywhere
    )

;;;
;;; HTTP: Can't go to any router or switch
;;; Or to the server enclave but can to the 
;;; worker enclave

(defblacklist (http victim-router)
    :for-host t
    :block everywhere
    )

(defblacklist (http worker-net-switch)
    :for-host t
    :block everywhere
    )

(defblacklist (http server-net-switch)
    :for-host t
    :block everywhere
    )

(defblacklist (http server-net-switch)
    :for-host nil
    :block everywhere
    )

;;;
;;; Database Protocol
;;; Routers and Switches block it
;;; Stuff in the Server enclave only accpets it from the worker enclave

(defblacklist (database-protocol victim-router)
    :for-host t
    :block everywhere
    )

(defblacklist (database-protocol worker-net-switch)
    :for-host t
    :block everywhere
    )

(defblacklist (database-protocol server-net-switch)
    :for-host t
    :block everywhere
    )

(defblacklist (database-protocol server-net-switch)
    :for-host nil
    :block everywhere
    :exceptions ("149.171.126.0/27")
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; This is not part of the environment description
;;; it's a procedure that runs the attack planner
;;; on this environment
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun test-unsw ()
  (do-it :attacker (Follow-path '(attacker))
	 :property 'data-integrity
	 :computer (Follow-path '(database-server))
	 :resource (Follow-path '(database))))


