;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*- 

;;; Persistence Model
;;; Starting with DLL Dropping

(in-package :aplan)

;;; Assume inital access already
;;; Can have the attacker be an arbitrary 192.168.0.0

(defexternal-internet outside ("192.168.0.0"))

;;; The attacker is currently there
(define-attacker attacker
  :location outside
  :download-servers attacker-download-server)

;;; Name of enterprise
(define-enterprise victim)

;;; Authorization pool, all priveleges are managed in enterprise manner
;;; The attacker already has access to these identities and privileges
(defauthorization-pool victim-authorization-pool)

;;; Should we define the different user capabilities the attacker can have?

(defcapability sysadmin victim-authorization-pool)

(defcapability user-read victim-authorization-pool
  :greater(sysadmin))

(defcapability user-write victim-authorization-pool
  :lesser(user-read)
  :greater(sysadmin))

(defcapability user-download victim-authorization-pool)

;;; Define attacker capabilities

(defauthorization-pool attacker-authorization-pool)

;; Add a malicious file to it?
;; add a write email maybe? write as in attach the malicious document to it?
(defcapability send-email attacker-authorization-pool)

;; Define user in the victim-authorization pool
(defuser victim
  :capabilities (user-download)
  :authorization-pools
  (victim-authorization-pool))

;; Define resources in the victim-authorization pool
;; Where are resource-types defined
(defresource malicious-dll-attachment malicious-file)

;; Windows only 
(defwhitelist (email windows-email-vm)
  :pass everywhere)

(defprocess email-server
  :process-type email-server-process
  :machine windows-email-vm)

(defprocess dll-hijack
  :process-type persistence
  :machine windows-computer)
