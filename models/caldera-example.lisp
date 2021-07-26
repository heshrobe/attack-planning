;;; -*- Mode: Common-lisp; Package: Aplan; Readtable: Joshua -*-


(in-package :aplan)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Defining the enterprise and its capability map
;;;
;;;
;;;Environment Description (4 machines, 2 networks)
;;;	Networks:
;;;		- Local Network (172.16.202.0/24)
;;;		- World Network (172.16.200.0/24)
;;;
;;;	Machines:
;;;		- CALDERA Server (172.16.200.10)
;;;		- Hashcat Machine (172.16.200.9)
;;;		- Gateway Machine (on both networks, two IPs: 172.16.202.11, 172.16.200.11)
;;;		- Secure Enclave (172.16.202.12)
;;;
;;;     Users:  - Sam access to Gateway machine as normal user
;;;             - Howie super-user on Gateway normal user on Secure
;;;             - Admin super-user on Secure
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; Topology

(defexternal-internet outside "172.16.200.0/16")

;;; Our attacker lives somewhere out there
(define-attacker attacker 
    :computer (caldera-server "172.16.200.10")
    :location outside
    :servers ((hashcat-server hashcat-server "172.16.200.8")))

;;; This is the name of our enterprise
(define-enterprise victim)

(defauthorization-pool victim-authorization-pool)

(defsite victim-enclave "172.16.202.0/24"
  :enterprise victim)

(defsubnet local-subnet switched-subnet "172.16.202.0/24")

(defswitch local-subnet-switch wired-switch "172.16.202.2"
           :authorization-pool victim-authorization-pool)

(defsubnet world-subnet switched-subnet "172.16.200.0/24")
(defswitch world-subnet-switch wired-switch "172.16.200.2"
           :authorization-pool victim-authorization-pool)

(defcomputer gateway-computer linux-computer
  :ip-address-string ("172.16.202.11," "172.16.200.11")
  )

(defcomputer secure linux-computer
  :ip-address-string "172.16.202.12")

;;; at this point we know that the attacker's caldera machne can reach the bridge
;;; and that the bridge can reach the victim (secure) but caldera can't directly reach the victim

;;; We need the router here to connect Outside to the world-subnet which is where the 
;;; gateway computer lives.
(defrouter victim-router ("172.16.200.1")
  :authorization-pool victim-authorization-pool
  :external-networks (outside))

(defblacklist (telnet victim-router)
    :block everywhere
    )

(defblacklist (telnet victim-router)
    :for-host t
    :block everywhere
    )

(defblacklist (telnet world-subnet-switch)
    :block everywhere)

(defblacklist (telnet world-subnet-switch)
    :block everywhere
    :for-host t)

(defblacklist (telnet local-subnet-switch)
    :block everywhere)

(defblacklist (telnet local-subnet-switch)
    :block everywhere
    :for-host t)




;;; Permissions

(defcapability gateway-user-read victim-authorization-pool
  :greater ())

;;; "Lesser" Means that user-write has user-read as well
(defcapability gateway-user-write victim-authorization-pool
  :lesser (gateway-user-read)
  :greater ())

(defcapability gateway-super-user victim-authorization-pool
  :lesser (gateway-user-write)
  :greater ())

(defcapability secure-user-read victim-authorization-pool
  :greater ())

;;; "Lesser" Means that user-write has user-read as well
(defcapability secure-user-write victim-authorization-pool
  :lesser (secure-user-read)
  :greater ())

(defcapability secure-super-user victim-authorization-pool
  :lesser (secure-user-write)
  :greater ())

(defuser sam 
    :user-type user
    :computers (gateway-computer)
    :capabilities (gateway-user-write)
    :authorization-pools (victim-authorization-pool)
    :has-weak-password 'yes
    )

(defuser howie
    :user-type user
    :computers (gateway-computer secure)
    :capabilities (gateway-super-user secure-user-write)
    :authorization-pools (victim-authorization-pool))

(defuser admin
    :user-type admin-user
    :computers (secure)
    :capabilities (secure-super-user))



;;; Resources on victims

(defresource password-file (password-file :filename "/etc/passwd")
             :computers (gateway-computer)
             :capability-requirements ((read gateway-user-read) (write gateway-super-user))
             :authorization-pool (victim-authorization-pool))

(defresource shadow-file (password-file :filename "/etc/shadow")
             :computers (gateway-computer)
             :capability-requirements ((read gateway-user-read) (write gateway-super-user))
             :authorization-pool (victim-authorization-pool))

(defresource sensitive-file file
             :computers (secure)
             :capability-requirements ((read secure-user-read) (write secure-super-user))
             :authorization-pool (victim-authorization-pool))

(defresource admin-script admin-script-file
             :computers (secure)
             :capability-requirements ((read secure-user-read) (write secure-super-user))
             :authorization-pool (victim-authorization-pool))
             
;;; resources on atacker machine

(defprogram hashcat-program
    )

(defprocess hashcat-process 
    :process-type password-cracker-process
    :computer hashcat-server
    :program hashcat-program)
    

(defun caldera-test ()
  (clear)
  (load "aplan:models;caldera-example.lisp")
  (do-it :property 'data-integrity
         :computer (follow-path '(secure))
         :resource (Follow-path '(sensitive-file))))