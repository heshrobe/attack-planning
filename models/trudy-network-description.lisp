;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*- 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; First attempt at trudy network description
;;;
;;;
;;; First we define a site which should be a network range (192.0.0.0 255.255.255.0)
;;;  Defsite should allow us to pick a range with holes in it (but doesn't yet)
;;;
;;; Then we define particular subnets within that site
;;; (192.10.0.0 255.255.0.0 and 192.20.0.0 255.255)
;;; 
;;; Then we define the routers that connect the subnets (not yet updated).
;;; 
;;; For these we specify what protocols that pass and which protocols are blocked
;;; and from what network ranges
;;;
;;; Then we define machines and state what subnets those machines are on
;;;
;;; This information allows us to compute which machines an outside user can 
;;; connect to using which protocols
;;; 
;;;
;;;
;;;  To test this in the interface, use auto-pilot, accuracy, auto-pilot-process
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(in-package :aplan)


(defsite trudy "192.0.0.0/16")

(defsubnet it-network switched-subnet "192.10.0.0/16")
(defsubnet voyage-network switched-subnet "192.20.0.0/16")

(defexternal-internet outside ("192.0.0.0" "255.0.0.0"))
;;; how to handle the engineering network?
;;; also should we have a subnet, the cctv example has one but never uses it...

(define-attacker typical-attacker 
    :location 'outside)



;;;;;;;;
;; Communication pool
;; (routers and switches in our network model)
;;;;;;;;

(defauthorization-pool communication-pool)

(defcapability communication-super-user communication-pool)

(defcapability communication-user-write communication-pool
  :greater (communication-super-user))

(defcapability communication-user-read communication-pool
  :greater (communication-user-write)) 

;; Define users in communication pool
;; do we need to have different communication pools
;; for different networks? or do we have one admin that can access all of the networks

(defuser router-administrator
  :capabilities (communication-super-user)
  :authorization-pools (communication-pool))

(defuser switch-administrator
  :capabilities (communication-super-user)
  :authorization-pools (communication-pool))

;;; The IP-Address-Strings field is a list of every IP address that this guy is reachable
;;; at.  The code in threading-objects.lisp will then decide to put this guy on every subnet
;;; that those addresses lie on.  So if the router has address 192.168.10.1 and there's a subnet
;;; called foobar with range (192.168.10.0 255.255.255.0), then the router will automatically have foobar
;;; as one of its subnets and foobar will have the router as one of its computers.
;;; The external networks keyword argument is a list of NAMES of external networks, e.g. outside
(defrouter cradlepoint-router ("192.10.0.1" "192.20.0.1")
  :authorization-pool communication-pool
  :superuser router-administrator
  :external-networks (outside))

;; the specs don't list an ip for the furuno hub so i dont know what to put here
(defswitch furuno-switch switch "192.10.0.2" 
	   :authorization-pool communication-pool 
	   :superuser switch-administrator)

;; Define resources in communication pool
(defresource router-password-file password-file
    :capability-requirements ((write communication-super-user) (read communication-user-read))
    :machines (cradlepoint-router))

(defresource router-configuration-file configuration-file
    :capability-requirements ((write communication-super-user) (read communication-user-read))
    :machines (cradlepoint-router))

(defresource switch-configuration-file configuration-file
    :capability-requirements ((write communication-super-user) (read communication-user-read))
    :machines (furuno-switch))


;;;;;;;;;;;;;;;;;;;;;;;
;; "IT Network" pool
;; Just what they define in the specs
;; includes email server, 
;; 
;;;;;;;;;;;;;;;;;;;;;;;


;; Define router access policies 

;;; The router will reject TELNET packets from anywhere outside the 192.x.x.x range
(defblacklist (telnet cradlepoint-router)
    :block everywhere
    :exceptions ()
    )

(defwhitelist (ssh cradlepoint-router)
    :pass everywhere
    :exceptions (("192.0.0.0"  "255.0.0.0"))
    )

;; first argument is allowed range, the second argument is the blacklisted range
;; can take more arugments? 
;;; It can take an arbitary number of blacklisted ranges

(defwhitelist (ssh cradlepoint-router)
    :pass everywhere
    :exceptions (("192.0.0.0"  "255.0.0.0"))
    )

(defwhitelist (email cradlepoint-router)
    :pass everywhere
    :exceptions (("192.0.0.0"  "255.0.0.0")))

;; Define switch access policies
;;; The switch will forward TELNET packets only from within its subnet
(defblacklist (telnet furuno-switch)
    :block everywhere
    :exceptions ()
    )

;;; The switch will pass SSH packets originating anywhere
(defwhitelist (ssh furuno-switch)
    :pass everywhere
    )

;;; anybody anywhere can send email packets through this switch
(defwhitelist (email furuno-switch)
    :pass everywhere
    )




;;;;
;;;;;;;;;;;;;;;;;;;
;; "IT Network" pooltell
;; Just what they define in the specs
;; includes email server, 
;; 
;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Server pool 
;;
;; encompasses Storage Server, Display Server, 
;; and Video Processing Server
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defauthorization-pool server-pool)

;; Capabilities for server pool 
(defcapability server-super-user server-pool)

(defcapability server-user-write server-pool
  :greater (server-super-user))

(defcapability server-user-read server-pool
  :greater (server-user-write)) 

;; Define users for server pool
(defuser server-administrator
  :capabilities (server-super-user)
  :authorization-pools (server-pool))

(defuser server-user
    :typical t
    :capabilities (server-user-write)
    :authorization-pools (server-pool))

(defcomputer host-laptop linux-computer 
  :ip-address-string "192.1.1.2"
  :authorization-pool server-pool
  :superuser server-administrator)

(defcomputer windows-email-vm windows-7-computer 
  :ip-address-string "192.10.0.3"
  :authorization-pool server-pool
  :superuser server-administrator)

(defcomputer navnet windows-7-computer 
  :ip-address-string "192.10.0.4"
  :authorization-pool server-pool
  :superuser server-administrator
  :interfaces (serial)
  )

(defresource typical-chart file
	     :capability-requirements ((write server-super-user) (read server-user-read))
	     :machines (navnet))

(defresource waypoint-sequence data-resource
	     :capability-requirements ((write server-super-user) (read server-user-read))
	     :machines (navnet))
  
  
(defwhitelist (email windows-email-vm)
    :pass everywhere)

(defwhitelist (ssh windows-email-vm)
    :pass everywhere
    )

;; Define resources in server pool
(defresource emails file
    :capability-requirements ((write server-super-user) (read server-user-read))
    :machines (windows-email-vm))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Navigation Network -- Canbus
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defbus navigation-bus 
    :bus-type canbus
    :slots (0 1 2 3 4 5 6)
    )

(define-peripheral auto-pilot
    :peripheral-type auto-pilot
    :interfaces (serial)
    :commands (update-setpoint)
    )

(defprocess auto-pilot-process
    :process-type control-system-process
    :machine auto-pilot
    )

(define-peripheral gps
    :peripheral-type gps
    :interfaces (serial)
    :commands ()
    )

(defprocess gps-process
    :process-type embedded-sensor-process
    :machine gps)

(defresource gps-position sensor-signal
	     :machines (GPS))


(define-connection auto-pilot serial navigation-bus 3)
(define-connection gps serial navigation-bus 2)
(define-connection navnet serial navigation-bus 0)



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The Navaigation System
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(define-system navigation-system
    :components (navigation-bus auto-pilot )
    :roles ((controller auto-pilot)
	    (sensor gps))
    )


;; TODO: need to define new data types for a VM (since we 
;; running a windows VM on the linux machine)

;; TODO: we need to find a way to describe the cell tower connection
;; in our system model 

;; Question: is there just one user w/ superuser privilege in both
;; the engineering and other (forget the name) networks
;; these are just the manager device and it does everything under the hood
;; can't run commands in a terminal, so could you technically have root privilege?


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Processes and attackers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Instantiate server processes
;;(instantiate-a-process 'storage-server-process '(storage))
;;(instantiate-a-process 'display-server-process '(display))

;; Instantiate manager processes
;; (instantiate-a-process 'server-process '(host-laptop))

(defprocess email-server
    :process-type email-server-process
    :machine windows-email-vm
    )

(defprocess navigation-process
    :process-type control-system-process
    :machine navnet
    )

(defprocess web-server-process
    :Process-type apache-web-server-process
    :machine navnet
    )

(define-input navigation-process typical-chart)
(define-output navigation-process waypoint-sequence)
(define-input auto-pilot-process waypoint-sequence)
(define-output gps gps-position)
(define-input auto-pilot-process gps-position)
(define-impact data-integrity waypoint-sequence accuracy auto-pilot-process)
(define-impact data-integrity typical-chart data-integrity waypoint-sequence)
(define-impact data-integrity gps-position accuracy auto-pilot-process)

;;; Need to say that the super-user is an email client of the email-server process
(def-email-clients email-server server-administrator)
