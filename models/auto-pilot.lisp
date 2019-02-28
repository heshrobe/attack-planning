;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*- 

;; DISTRIBUTION STATEMENT C: U.S. Government agencies and their contractors.
;; Other requests shall be referred to DARPA’s Public Release Center via email at prc@darpa.mil.

;;; DCRYPPS AutoPilot model - hand-generated network description for the attack-planner
;;;
;;; QUESTIONS:
;;; Do we need a defprocess auto-pilot-process?

(in-package :aplan)

(defsite autopilot "192.0.0.0" "255.0.0.0")

(defsubnet autopilot-lan switched-subnet "192.10.0.0" "255.255.0.0")
(defsubnet extenal-lan  switched-subnet  "192.20.0.0" "255.255.0.0")

(defexternal-internet outside ("192.0.0.0" "255.0.0.0"))  ;;Is this IP range correct?  **********

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

(defuser switch-administrator
  :capabilities (communication-super-user)
  :authorization-pools (communication-pool))

;; The Pamela Autopilot model doesn't have a router **********
;; However, the Controller Board has two interfaces, one for the LAN and another for the Cellnet
;; (defrouter cradlepoint-router ("192.10.0.1" "192.20.0.1")
;;   :authorization-pool communication-pool
;;   :superuser router-administrator
;;   :external-networks (outside))

;; We need a way to get in from "outside"
(defrouter placeholder-router ("192.10.0.1" "192.20.0.1")
  :authorization-pool communication-pool
  :superuser switch-administrator
  :external-networks (outside))


;; Let's assume that this is a managed switch
(defswitch APNetworkSwitch switch "192.10.0.2"
	   :ports (0 1 2 3 4 5 6)
	   :authorization-pool communication-pool
	   :superuser switch-administrator)

(defresource switch-configuration-file configuration-file
    :capability-requirements ((write communication-super-user) (read communication-user-read))
    :machines (APNetworkSwitch))


;; Define router access policies
;; Should we assume that our APNetworkSwitch acts like a router??? **********

;;; The router will reject TELNET packets from anywhere outside the 192.x.x.x range
(tell-negative-policy placeholder-router telnet ("192.0.0.0"  "255.0.0.0"))

;; first argument is allowed range, the second argument is the blacklisted range
;; can take more arugments?
;;; It can take an arbitary number of blacklisted ranges

;; ********************
;; These are incorrect, since the only ssh & email activities won't be happening
;; over the LAN (i.e., between Ground Station and ControllerBoard via APCellularNetwork)
(tell-positive-policy placeholder-router ssh ("0.0.0.0"  "0.0.0.0") ("192.0.0.0"  "255.0.0.0"))

(tell-positive-policy placeholder-router email ("0.0.0.0"  "0.0.0.0") ("192.0.0.0"  "255.0.0.0"))

(tell-positive-policy placeholder-router http ("0.0.0.0"  "0.0.0.0") ("192.0.0.0"  "255.0.0.0"))

;; Define switch access policies
;;; The switch will forward TELNET packets only from within its subnet
(tell-negative-policy APNetworkSwitch telnet ("192.10.0.0" "255.255.0.0"))

;; why do we have this? it doesn't seem to be defining any range...
;;; Location masks have two paths:
;;; 1) An 4 place IP address
;;; 2) A mask where a 1 in that bit position means you have to match
;;;    and a zero in the mask says "don't care"
;;; So the mask below matches everything.
;;; In fact anything with a mask of "0.0.0.0" will match anything

;;; The switch will pass SSH packets originating anywhere
;; (tell-positive-policy APNetworkSwitch ssh  ("0.0.0.0"  "0.0.0.0"))

;; ;;; anybody anywhere can send email packets through this switch
;; (tell-positive-policy APNetworkSwitch email  ("0.0.0.0"  "0.0.0.0"))


(defauthorization-pool sensor-pool)

;; Capabilities for sensor pool
(defcapability sensor-super-user sensor-pool)

(defcapability sensor-user-write sensor-pool
  :greater (sensor-super-user))

(defcapability sensor-user-read sensor-pool
  :greater (sensor-user-write))

;; Define users for sensor pool
(defuser sensor-administrator
  :capabilities (sensor-super-user)
  :authorization-pools (sensor-pool))

(defuser sensor-user
  :capabilities (sensor-user-write)
  :authorization-pools (sensor-pool))

(defauthorization-pool controller-pool)

;; Capabilities for controller pool
(defcapability controller-super-user controller-pool)

(defcapability controller-user-write controller-pool
  :greater (controller-super-user))

(defcapability controller-user-read controller-pool
  :greater (controller-user-write))

;; Define users for controller pool
(defuser controller-administrator
  :capabilities (controller-super-user)
  :authorization-pools (controller-pool))

(defuser controller-user
  :capabilities (controller-user-write)
  :authorization-pools (controller-pool))

(defcomputer GPS embedded-linux-computer 
  :ip-address-string "192.10.1.2"
  :authorization-pool sensor-pool
  :superuser sensor-administrator
  :interfaces (ethernet)
  )

(defprocess gps-process
    :process-type embedded-sensor-process
    :machine gps)

(defcomputer VOR embedded-linux-computer 
  :ip-address-string "192.10.1.3"
  :authorization-pool sensor-pool
  :superuser sensor-administrator
  :interfaces (ethernet)
  )

(defprocess VOR-process
    :process-type embedded-sensor-process
    :machine VOR)

(defcomputer INS embedded-linux-computer 
  :ip-address-string "192.10.1.7"
  :authorization-pool sensor-pool
  :superuser sensor-administrator
  :interfaces (ethernet))

(defprocess INS-process
    :process-type embedded-sensor-process
    :machine INS)

(defcomputer FlightControls embedded-linux-computer 
  :ip-address-string "192.10.1.4"
  :authorization-pool sensor-pool
  :superuser sensor-administrator
  :interfaces (ethernet))

;; The controller has 2 network interfaces.  How do you specify that?  **********
(defcomputer ControllerBoard linux-computer 
  :ip-address-string ("192.20.1.3" "192.10.1.5")
  :authorization-pool controller-pool
  :superuser controller-administrator
  :interfaces (ethernet-1 ethernet-2)
  )

(defcomputer Camera embedded-linux-computer 
  :ip-address-string "192.10.1.6"
  :authorization-pool sensor-pool
  :superuser sensor-administrator
  :interfaces (ethernet))

(define-connection ControllerBoard ethernet-1 APNetworkSwitch 0)
(define-connection Camera ethernet APNetworkSwitch 1)
(define-connection FlightControls ethernet APNetworkSwitch 2)
(define-connection INS ethernet APNetworkSwitch 3)
(define-connection VOR ethernet APNetworkSwitch 4)
(define-connection GPS ethernet APNetworkSwitch 5)



(defauthorization-pool groundstation-pool)

;; Capabilities for groundstation pool
(defcapability groundstation-super-user groundstation-pool)

(defcapability groundstation-user-write groundstation-pool
  :greater (groundstation-super-user))

(defcapability groundstation-user-read groundstation-pool
  :greater (groundstation-user-write))

;; Define users for groundstation pool
(defuser groundstation-administrator
  :capabilities (groundstation-super-user)
  :authorization-pools (groundstation-pool))

(defuser groundstation-user
  :capabilities (groundstation-user-write)
  :authorization-pools (groundstation-pool))

(defcomputer groundstation linux-computer 
  :ip-address-string "192.1.1.2"
  :authorization-pool groundstation-pool
  :superuser groundstation-administrator)

(defprocess auto-pilot-process
    :process-type control-system-process
    :machine ControllerBoard
    )

(defprocess ControllerBoardWebServer
    :process-type apache-web-server-process
    :machine ControllerBoard
    )

(defprocess navigation-process
    :process-type control-system-process
    :machine groundstation
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The Navigation System
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(define-system navigation-system
    :components (autopilot-lan GPS VOR FlightControls ControllerBoard Camera INS)
    :roles ((controller ControllerBoard)
	    (sensor GPS)
	    (sensor VOR)
	    (sensor INS)
	    (sensor camera)
	    (actuator FlightControls)
	    (network autopilot-lan))
    )

(defresource waypoint-sequence data-resource
	     :capability-requirements ((write controller-super-user) (read controller-user-read))
	     :machines (ControllerBoard))

;; There's a redundancy between the :machines in the defresource and the
;; :machine in the process referred to by define-input/define-output

(define-impact data-integrity waypoint-sequence accuracy auto-pilot-process)

;; Should the :machines below include BOTH the ControllerBoard and the sensor? **********
(defresource gps-position sensor-signal
	     :capability-requirements ((write sensor-super-user) (read sensor-user-read))
	     :machines (GPS ControllerBoard))

(defresource vor-position sensor-signal
	     :capability-requirements ((write sensor-super-user) (read sensor-user-read))
	     :machines (vor ControllerBoard))

(defresource ins-position sensor-signal
	     :capability-requirements ((write sensor-super-user) (read sensor-user-read))
	     :machines (ins ControllerBoard))

(define-output gps gps-position)
(define-output vor vor-position)
(define-output ins ins-position)
(define-output navigation-process waypoint-sequence)

(define-input auto-pilot-process gps-position)
(define-input auto-pilot-process vor-position)
(define-input auto-pilot-process ins-position)
(define-input auto-pilot-process waypoint-sequence)

(define-impact data-integrity gps-position accuracy auto-pilot-process)
(define-impact data-integrity vor-position accuracy auto-pilot-process)
(define-impact data-integrity ins-position accuracy auto-pilot-process)

(create-attacker 'typical-attacker :world-name 'outside)

(define-proximity typical-attacker gps radio)
(define-proximity typical-attacker vor radio)
(define-proximity typical-attacker ins radio)