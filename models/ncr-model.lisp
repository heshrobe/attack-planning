;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Defining the enterprise and its capability map
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; We'll regard anything not within the 142.20.xxx.xxx class B as the rest of the world

;;; The outside world is anything outside our Class B address space
(defexternal-internet outside ("192.168.0.0" "255.255.0.0"))

;;; Our attacker lives somewhere out there
(define-attacker attacker 
    :location outside
    ;; :download-servers attacker-download-server
    ;; :adware-servers attacker-adware-server
    )

(define-enterprise systemia)


;;; An authorization pool is a group of identities and privileges
;;; managed in a unified way.  In Windows this is via a domain 
;;; controller.

(defauthorization-pool systemia-domain-controller-pool
    :type domain)

;;; There is a capability called admin.
;;; In Windows with UAC, this is split into levels that
;;; we'll call normal and high (there are a actually more than this)

(defcapability domain-admin systemia-domain-controller-pool
  :role domain-admin-capability)

(defcapability sysadmin-high systemia-domain-controller-pool
  :greater (domain-admin))
(defcapability sysadmin-normal systemia-domain-controller-pool
  :greater (sysadmin-high))

;;; Vanilla ability to read any user file
;;; "Greater" Means that Sysadmin has this privilege
(defcapability user-read systemia-domain-controller-pool
  :greater (sysadmin-normal))

;;; Vanilla ability to write any user file
(defcapability user-write systemia-domain-controller-pool
  :lesser (user-read)
  :greater (sysadmin-normal))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 
;;; The networking environment of our Enterprise
;;;
;;;
;;; All the computers we know about including 4 worker subnets
;;; and the Domain Controller subnet
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defsite systemia-main-site "142.20.56.0/21"
	 :enterprise systemia)

(defsubnet worker-subnet-1 switched-subnet "142.20.56.0/24")
(defsubnet worker-subnet-2 switched-subnet "142.20.57.0/24")
(defsubnet worker-subnet-3 switched-subnet "142.20.58.0/24")
(defsubnet worker-subnet-4 switched-subnet "142.20.59.0/24")
(defsubnet domain-controller-subnet switched-subnet "142.20.61.0/24")

;;; This includes the 4 worker subnets but not the domain
;;; controller.
(defensemble systemia-worker-computers
    :enterprise systemia
    :size 40
    :address-range "142.20.56.0/22"
    :member-type windows-computer)

(defcomputer systemia-typical-worker-computer windows-computer
  :ip-address-string "142.20.56.3"
  :typical t
  :authorization-pool systemia-domain-controller-pool
  :ensemble systemia-worker-computers
  :superuser ()
  )

(defuser systemia-typical-user
    :user-type normal-user
    :ensemble systemia-worker-computers
    :computers (systemia-typical-worker-computer)
    :typical t
    :capabilities (user-write)
    :authorization-pools (systemia-domain-controller-pool)
    )

;;; The domain controller
(defcomputer DC1-systemia-com windows-computer
  :ip-address-string "142.20.61.130"
  :typical nil
  :authorization-pool systemia-domain-controller-pool
  :role (domain-controller systemia-domain-controller-pool)
  )

(defuser domain-administrator
    :user-type domain-admin
    :typical nil
    :authorization-pools (systemia-domain-controller-pool)
    :computers (DC1-systemia-com)
    :capabilities (domain-admin)
    :superuser-for (DC1-systemia-com)
    :role (domain-administrator systemia-domain-controller-pool)
    )
    


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The networking infrastrurture
;;;
;;; There don't appear to be any "firewall" restrictions
;;;
;;; the Main Router and subnet switches
;;;
;;; Note that routers and switches are both network "bridges" and computers.
;;; 
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrouter victim-router ("142.20.56.1" "142.20.57.1" "142.20.58.1" "142.20.59.1" "142.20.61.1")
  :authorization-pool systemia-domain-controller-pool
  :external-networks (outside))

(defswitch worker-subnet-1-switch wired-switch "142.20.56.2"
	   :authorization-pool systemia-domain-controller-pool
	   )

(defswitch worker-subnet-2-switch wired-switch "142.20.57.2"
	   :authorization-pool systemia-domain-controller-pool
	   )

(defswitch worker-subnet-3-switch wired-switch "142.20.58.2"
	   :authorization-pool systemia-domain-controller-pool
	   )

(defswitch worker-subnet-4-switch wired-switch "142.20.59.2"
	   :authorization-pool systemia-domain-controller-pool
	   )

(defswitch worker-domain-controller-subnet-switch wired-switch "142.20.61.2"
	   :authorization-pool systemia-domain-controller-pool
	   )

(defblacklist (telnet worker-domain-controller-subnet-switch)
    :for-host t
    :block everywhere)

(defblacklist (telnet worker-domain-controller-subnet-switch)
    :for-host nil
    :block everywhere)
  
(defblacklist (ssh worker-domain-controller-subnet-switch)
    :for-host t
    :block everywhere)

(defblacklist (ssh worker-domain-controller-subnet-switch)
    :for-host nil
    :block everywhere)

(defcomputer email-server windows-computer
  :ip-address-string "142.20.61.3"
  :typical nil
  :authorization-pool systemia-domain-controller-pool)


(defprocess email-server-process
    :process-type email-server-process
    :computer email-server
    )

(def-email-clients email-server-process systemia-typical-user)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The resources and their required capabilities
;;; Here we say what resources are available
;;; and what capabilities a user will need to access these resources
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

#|
Here the resources of ultimate concern are the colection of sensitive files
and they live on an ensemble of computers
There may also be a "domain controller" resource of some kind 


|#



(defresource sensitive-files (file-collection :owner systemia-domain-controller-pool)
             :computers (systemia-domain-controller-pool)
             :primary-computer dc1-systemia-com
             :authorization-pool systemia-domain-controller-pool
             :capability-requirements ((read domain-admin))
             )

(defresource sysvol (directory :owner systemia-domain-controller-pool)
             :computers (dc1-systemia-com)
             :primary-computer dc1-systemia-com
             :authorization-pool systemia-domain-controller-pool
             :capability-requirements ((read user-read)
                                       (write domain-admin))
             :role (system-volume systemia-domain-controller-pool))

(defresource the-domain-admin-password (password :owner systemia-domain-controller-pool)
             :authorization-pool systemia-domain-controller-pool
             :role (domain-admin-password systemia-domain-controller-pool))

(defresource the-domain-admin-password-key (encryption-key :owner systemia-domain-controller-pool)
             :role (domain-admin-password-key systemia-domain-controller-pool))

;;; hack hack
(defrule password-key-role (:forward)
  :if [and [system-role ?system domain-admin-password ?password]
           [system-role ?system domain-admin-password-key ?key]]
  :then [system-role ?password key-for ?key])