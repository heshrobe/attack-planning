;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The real example has the attacker at a specific suspicious location
;;;  I'm working without that for the moment
;;;
;;; Similarly I don't yet have the addresses for the enclave
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; We'll regard anything not within the 192.168 class B as the rest of the world

;;; The outside world is anything outside our Class B address space
(defexternal-internet outside "192.168.0.0/24")

;;; Mirai has 3 servers:
;;; 1) Command and Control: Only involved with infected bots, issues attack command
;;; 2) Report: Gets info from bots about newly discovered vulnerable targets
;;; 3) Loader: Logs into newly discovered vulnerable tagets, logs in and downloads the malware
;;;            Loads the malware and the deletes the malware file

(define-attacker attacker 
    :location outside
    :command-and-control-servers attacker-c&c-server
    :servers ((report-server attacker-report-server)
              (loader attacker-loader)                             
              ))


;;; This is the name of our enterprise
(define-enterprise victim)

;;; An authorization pool is a group of identities and privileges
;;; managed in a unified way.
;;; For the moment we're going to assume that all privileges
;;; are manaaged in an enterprise-wide manner
(defauthorization-pool victim-authorization-pool)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The worker enclave
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defsite worker-enclave "192.168.0.0/16"
	 :enterprise victim)

(defsubnet worker-subnet switched-subnet "192.168.0.0/16")

;;; Vanilla ability to read any user file

(defcapability user-read victim-authorization-pool
  :greater ())

;;; "Lesser" Means that user-write has user-read as well
(defcapability user-write victim-authorization-pool
  :lesser (user-read)
  :greater ())


;;; An esemble is a group of machines that are essentially identical from
;;; our point of view
(defensemble worker-machines
    :enterprise victim
    :address-range "192.168.0.0/24"
    :size 40)

;;; The typical worker computer is a "windows" computer
;;; It is a typical meember of the worker-machines ensemble
(defcomputer typical-worker-computer windows-computer
  :ip-address-string "192.168.0.3"
  :typical t
  :authorization-pool victim-authorization-pool
  :ensemble worker-machines
  :superuser ()
  )

(defensemble other-worker-machines
    :enterprise victim
    :address-range "192.168.1.0/24"
    :size 40)

(defcomputer other-typical-worker-computer windows-computer
  :ip-address-string "192.168.1.3"
  :typical t
  :authorization-pool victim-authorization-pool
  :ensemble other-worker-machines
  :superuser ()
  )  

;;; Typical worker bee is a typical user of a typical
;;; machine in the worker-machines ensemble
;;; This user has "user-write" capabilities
;;; meaning they can read-or-write any resource that
;;; requires read or write capability
(defuser typical-worker-bee
    :user-type user
    :ensemble worker-machines
    :machines (typical-worker-computer)
    :typical t
    :capabilities (user-write)
    :authorization-pools (victim-authorization-pool)
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; the Main Router
;;; Note that routers and switches are both network "bridges" and computers.
;;; 
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrouter victim-router ("192.168.0.1")
  :authorization-pool victim-authorization-pool
  :external-networks (outside))

(defswitch worker-net-switch wired-switch "192.168.0.2"
	   :authorization-pool victim-authorization-pool
	   :superuser ())
    

;;; These whitelist and blacklist descriptions are supposed to say
;;; what traffic will be allowed to pass in from the outside
;;; However, note that all inter-enclave traffic will go through this router as well
;;; So we have to be careful about allowing those
;;; But for this example nothing is black-listed


