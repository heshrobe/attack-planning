;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*- 

;;; Example CCTV Network

(in-package :aplan)

;; We're assuming that entire network is internal (LAN)
(defsite cctv-network "192.0.0.0" "255.0.0.0")

;;; The rest of the world which is where the bad guy is assumed to live
(defexternal-internet the-wild ("192.0.0.0" "255.0.0.0"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Communication pool 
;;
;; encompasses Routers and Switches
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(make-object 'authorization-pool :name 'communication-pool)

;; Capabilities for communication pool 
(defcapability communication-super-user communication-pool)

(defcapability communication-user-write communication-pool
  :greater (communication-super-user))

(defcapability communication-user-read communication-pool
  :greater (communication-user-write)) 

;; Define users in communication pool
(defuser router-administrator
  :capabilities (communication-super-user)
  :authorization-pools (communication-pool))

(defuser switch-administrator
  :capabilities (communication-super-user)
  :authorization-pools (communication-pool))

;; Define machines in communication pool
(defrouter cctv-router ("192.0.0.0" "10.0.0.0") 
  :authorization-pool communication-pool
  :superuser router-administrator
  :external-networks (the-wild)
  )

(defswitch cctv-switch switch "192.1.1.1" :authorization-pool communication-pool :superuser switch-administrator)

;; Define resources in communication pool
(defresource router-password-file password-file
    :capability-requirements ((write communication-super-user) (read communication-user-read))
    :machines (cctv-router))

(defresource router-configuration-file configuration-file
    :capability-requirements ((write communication-super-user) (read communication-user-read))
    :machines (cctv-router))

(defresource switch-configuration-file configuration-file
    :capability-requirements ((write communication-super-user) (read communication-user-read))
    :machines (cctv-switch))

;; Define subnet
(defsubnet backbone switched-subnet "192.0.0.0" "255.0.0.0")

;; Define router access policies 

(tell-negative-policy cctv-router telnet ("192.0.0.0"  "255.0.0.0"))

(tell-positive-policy cctv-router ssh ("0.0.0.0"  "0.0.0.0") ("192.0.0.0"  "255.0.0.0"))

(tell-positive-policy cctv-router email ("0.0.0.0"  "0.0.0.0") ("192.0.0.0"  "255.0.0.0"))

;; Define switch access policies
(tell-negative-policy cctv-switch telnet ("192.1.0.0" "255.255.0.0"))

(tell-positive-policy cctv-switch ssh  ("0.0.0.0"  "0.0.0.0"))

(tell-positive-policy cctv-switch email  ("0.0.0.0"  "0.0.0.0"))

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

;; Define machines/computers for server pool
(defcomputer storage linux-computer "192.1.1.2"
  :authorization-pool server-pool
  :superuser server-administrator)

(defcomputer display linux-computer "192.1.1.3"
  :authorization-pool server-pool
  :superuser server-administrator)

(defcomputer video-processing linux-computer "192.1.1.4"
  :authorization-pool server-pool
  :superuser server-administrator)

;; Define resources in server pool
(defresource video-database database
    :capability-requirements ((write server-super-user) (read server-user-read))
    :machines (storage))

;; Note: need to make object definitions for computations 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Manager pool 
;;
;; encompasses Main Operator Console Server, and  Video Surveillance Manager
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(make-object 'authorization-pool :name 'manager-pool)

;; Capabilities for manager pool 
(defcapability manager-super-user manager-pool)

(defcapability manager-user-write manager-pool
  :greater (manager-super-user))

(defcapability manager-user-read manager-pool
  :greater (manager-user-write)) 

;; Define users for manager pool
(defuser manager-administrator
  :capabilities (manager-super-user)
  :authorization-pools (manager-pool))

(defuser manager-user
  :capabilities (manager-user-write)
  :authorization-pools (manager-pool))

;; Define machines/computers for manager pool
(defcomputer main-operator-console windows-7-computer "192.1.1.5"
  :authorization-pool manager-pool
  :superuser manager-administrator)

(defcomputer typical-video-surveillance-manager windows-7-computer "192.1.1.6"
  :authorization-pool manager-pool
  :superuser manager-administrator)

;; Define resources in server pool

;; Master password file contains login info for all servers/devices on the network
(defresource master-password-file password-file
    :capability-requirements ((write manager-super-user) (read manager-user-read))
    :machines (main-operator-console))

;; Local password file contains login info for the (camera) devices that fall under the video-surveillance-manager
(defresource local-password-file password-file
    :capability-requirements ((write manager-user-write) (read manager-user-read))
    :machines (typical-video-surveillance-manager))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Device pool 
;;
;; encompasses Video Surveillance Manager, and IoT Camera
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(make-object 'authorization-pool :name 'device-pool)

;; Capabilities for device pool 
(defcapability device-super-user device-pool)

(defcapability device-user-write device-pool
  :greater (device-super-user))

(defcapability device-user-read device-pool
  :greater (device-user-write))

;; Define users for device pool
(defuser device-administrator
  :capabilities (device-super-user)
  :authorization-pools (device-pool))

;; Define machines/computers for device pool
(defcomputer typical-camera embedded-linux-computer "192.1.1.7"
  :authorization-pool device-pool
  :superuser device-administrator)

;; define video-machine-policy
(tell-negative-policy typical-camera telnet ("192.0.0.0" "255.0.0.0"))

(tell-positive-policy typical-camera ssh ("0.0.0.0" "0.0.0.0"))

;;; must follow the previous guy
;;; since it refers to it
(defuser device-user
  :user-type typical-user
  :capabilities (device-user-write)
  :authorization-pools (device-pool)
  :machines (typical-camera))

;; Define resources for device pool
(defresource devices-scheduler-policy scheduler-policy-file
  :capability-requirements ((write device-super-user) (read device-user-read))
  :machines (typical-camera))

(defresource devices-password-file password-file
  :capability-requirements ((write device-super-user) (read device-user-read))
  :machines (typical-camera))

(defresource device-video-file graphic-video-file 
  :capability-requirements ((write device-user-write) (read device-user-read))
  :machines (typical-camera))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Processes and attackers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Instantiate server processes
(instantiate-a-process 'storage-server-process '(storage))
(instantiate-a-process 'display-server-process '(display))
(instantiate-a-process 'video-processing-server-process '(video-processing))

;; Instantiate manager processes
(instantiate-a-process 'operator-console-server-process '(main-operator-console))
(instantiate-a-process 'video-surveillance-manager-process '(typical-video-surveillance-manager))

;; Instantiate device processes
(instantiate-a-process 'typical-user-process '(typical-camera) :role-name 'typical-camera-process)

;; Instantiate attacker
;;; A lot of this is a complete hack.  What we'd like to say is that the attacker is 
;;; somewhere that can contact the router of the victim.
;;; So we're should specify his machine, what network he lives on (the-wild)
;;; and then we need to update all the stuff about the connect, reachable etc
;;; predicates.

(create-attacker 'typical-attacker :world-name 'the-wild)

;;;(defsubnet attacker-subnet switched-subnet "10.0.0.0" "255.0.0.0")
;;;
;;;(defswitch attacker-switch switch "10.1.1.1" )
;;;(tell-policy attacker-switch ssh :positive-location-mask "0.0.0.0" :positive-location-address "0.0.0.0")