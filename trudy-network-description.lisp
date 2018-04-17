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
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(in-package :aplan)


(defsite trudy "192.0.0.0" "255.0.0.0")

(defsubnet it-network switched-subnet "192.10.0.0" "255.255.0.0")
(defsubnet voyage-network switched-subnet "192.20.0.0" "255.255.0.0")

(defexternal-internet outside ("192.0.0.0" "255.0.0.0"))
;;; how to handle the engineering network?
;;; also should we have a subnet, the cctv example has one but never uses it...

;;;;;;;;
;; Communication pool
;; (routers and switches in our network model)
;;;;;;;;

(make-object 'authorization-pool :name 'communication-pool)

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

;;; dont know what second field should be here
(defrouter cradlepoint-router ("192.0.0.0" "10.0.0.0")
  :authorization-pool communication-pool
  :superuser router-administrator
  :external-networks (outside))

;; the specs don't list an ip for the furuno hub so i dont know what to put here
(defswitch furuno-switch switch "192.1.1.1" :authorization-pool communication-pool :superuser switch-administrator)

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


(tell-negative-policy cradlepoint-router telnet ("192.0.0.0"  "255.0.0.0"))

;; first argument is allowed range, the second argument is the blacklisted range
;; can take more arugments?
(tell-positive-policy cradlepoint-router ssh ("0.0.0.0"  "0.0.0.0") ("192.0.0.0"  "255.0.0.0"))

(tell-positive-policy cradlepoint-router email ("0.0.0.0"  "0.0.0.0") ("192.0.0.0"  "255.0.0.0"))

;; Define switch access policies
(tell-negative-policy furuno-switch telnet ("192.1.0.0" "255.255.0.0"))

;; why do we have this? it doesn't seem to be defining any range...
(tell-positive-policy furuno-switch ssh  ("0.0.0.0"  "0.0.0.0"))

(tell-positive-policy furuno-switch email  ("0.0.0.0"  "0.0.0.0"))

;;;;;;;;;;;;;;;;;;;;;;;
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

(make-object 'authorization-pool :name 'server-pool)

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
  :capabilities (server-user-write)
  :authorization-pools (server-pool))

;; Ok, what are the different types of "computers"
;; that we input to this function, are they defined somewhere
;; or are just strings that we define, where are they stored??
;; Note -- I think that these are in object-defs.lisp
;; how would we handle 10.*.*.* ip addresses, should we
;; make our valid ip range really wide or what?
(defcomputer host-laptop linux-computer "192.1.1.2"
	     :authorization-pool server-pool
	     :superuser server-administrator)

(defcomputer windows-email-vm windows-7-computer "192.1.1.3"
	     :authorization-pool server-pool
	     :superuser server-administrator)

(tell-positive-policy cradlepoint-router ssh ("0.0.0.0"  "0.0.0.0") ("192.0.0.0"  "255.0.0.0"))


(defcomputer navnet windows-7-computer "192.1.1.4"
	     :authorization-pool server-pool
	     :superuser server-administrator)

;; Define resources in server pool
(defresource emails data-resource
    :capability-requirements ((write server-super-user) (read server-user-read))
    :machines (windows-email-vm))

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
(instantiate-a-process 'server-process '(host-laptop))
(instantiate-a-process 'server-process '(windows-email-vm) :role-name 'email-server)

;; Instantiate device processes
;;(instantiate-a-process 'typical-user-process '(typical-camera) :role-name 'typical-camera-process)

;; Instantiate attacker
;;; A lot of this is a complete hack.  What we'd like to say is that the attacker is 
;;; somewhere that can contact the router of the victim.
;;; So we're should specify his machine, what network he lives on (the-wild)
;;; and then we need to update all the stuff about the connect, reachable etc
;;; predicates.

(create-attacker 'typical-attacker :world-name 'outside)

;;;(defsubnet attacker-subnet switched-subnet "10.0.0.0" "255.0.0.0")
;;;
;;;(defswitch attacker-switch switch "10.1.1.1" )
;;;(tell-policy attacker-switch ssh :positive-location-mask "0.0.0.0" :positive-location-address "0.0.0.0")

