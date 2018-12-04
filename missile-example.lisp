;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*- 

;; DISTRIBUTION STATEMENT C: U.S. Government agencies and their contractors.
;; Other requests shall be referred to DARPA’s Public Release Center via email at prc@darpa.mil.

(in-package :aplan)

;;; The outside world is anything outside our Class B address space
(defexternal-internet outside ("192.168.0.0" "255.255.0.0"))

;;; Our attacker lives somewhere out there
(create-attacker 'typical-attacker :world-name 'outside)

;;; This is the name of our enterprise
(define-enterprise victim)

;;; There are two enclaves: the missile's network itself and the basestation network
;;; The Basestation's network is a class C at 192.168.0.0
;;; The missile's network is a class C at 192.168.1.0

(defsite basestation-enclave "192.168.0.0" "255.255.255.0" :enterprise victim)
(defsubnet external-lan switched-subnet "192.169.0.0" "255.255.255.0")

(defsite missile-enclave "192.168.1.0" "255.255.255.0"
	 :enterprise victim)
(defsubnet missile-subnet switched-subnet "192.168.1.0" "255.255.255.0")


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Missile Authorization Pool
;;; and the Routing Structure
;;;
;;; The router connects the outside world two the two 
;;; enclaves (the base-station and the missile)
;;; The router is at location 0 on each sub-network
;;; Each subnet has a switch (the cellular-modem for the missile)
;;; Each switch is at location 1 on its subnet
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defauthorization-pool missile-pool)

(defcapability missile-super-user missile-pool)

(defcapability missile-user-write missile-pool
  :greater (missile-super-user))

(defcapability missile-user-read missile-pool
  :greater (missile-user-write))

;; Define users in communication pool
;; do we need to have different communication pools
;; for different networks? or do we have one admin that can access all of the networks

(defuser router-administrator
  :capabilities (missile-super-user)
  :authorization-pools (missile-pool))

;; We need a way to get in from "outside"
(defrouter missile-router ("192.168.0.0" "192.168.1.0")
  :authorization-pool missile-pool
  :superuser router-administrator
  :external-networks (outside))

(defswitch missile-switch cellular-modem "192.168.1.1"
	   :authorization-pool missile-pool
	   :superuser router-administrator
	   )

(defswitch base-station-swith wired-switch "192.168.0.1"
	   :authorization-pool missile-pool 
	   :superuser router-administrator
	   )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Routing Access Rules
;;;  The planner treats anything that's not forbidden as permitted
;;;  So I think we only need to say that ssh & telnet are forbidden
;;;  We might have to move these to the switches or add more specific things
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defblacklist (telnet missile-router)
    :block everywhere
    )

(defblacklist (ssh missile-router)
  :block everywhere
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Base Station Network
;;;   Not much here, just the basestation computer
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defcomputer BaseStation Linux-computer
  :ip-address-string "192.168.0.2"
  :superuser router-administrator
  :authorization-pool missile-pool
  :interfaces (serial)
  :ensemble missile-enclave
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Navigation Network -- MissileBus
;;;
;;; This is the internal bus of the Missile
;;;  sort of like CANBUS, because we don't actually know anything
;;; On this are:
;;;  The controller board -- essentially a computer
;;;    It is connected to the ground station via cellular network
;;;     which means there needs to be a router to the cellular and the controller
;;;    It runs 2 processes: Missile-Guidance and Web-Server
;;;
;;;  Sensors: GPS, Inertial-Gyro, Seeker-Tracker, 
;;;  Actuators: Fin-control
;;;  
;;;  The seeker-tracker provides a vector from the missiles's current position
;;;   to the (future?) location of the target
;;;
;;;  Fin-control sets the fin to whatever position the Missile-Guidance process decides
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defbus missile-bus 
    :bus-type canbus
    :slots (0 1 2 3 4 5 6)
    )

(defcomputer Controller Linux-computer
  :ip-address-string "192.168.1.2"
  :superuser router-administrator
  :authorization-pool missile-pool
  :interfaces (serial)
  :ensemble missile-enclave
  )
    
(defprocess missile-guidance-process
    :process-type control-system-process
    :machine controller
    )

(define-object-type missile-diagnostic-process
    :tms t
  :included-object-types (web-server-process))

(defprocess controller-diagnostic-process
    :process-type missile-diagnostic-process
    :machine controller
    )

;;; GPS
(define-peripheral gps
    :peripheral-type gps
    :interfaces (serial)
    :commands ()
    )

(defprocess gps-process
    :process-type embedded-sensor-process
    :machine gps)

;;; INS/GYRO
(define-peripheral ins-gyro
    :peripheral-type inertial-gyro
    :interfaces (serial)
    :commands ()
    )

(defprocess ins-gyro-process
    :process-type embedded-sensor-process
    :machine ins-gyro)

;;; Seeker-Tracker
(define-peripheral seeker-tracker
  :peripheral-type seeker-tracker
  :interfaces (serial)
  :commands ()
  )

(defprocess seeker-tracker-process
  :process-type embedded-sensor-process
  :machine seeker-tracker)

;;; Fin Control

(define-peripheral fin-control
  :peripheral-type fin-control
  :interfaces (serial)
  :commands ()
  )

(defprocess fin-control-process
  :process-type embedded-actuator-process
  :machine fin-control)

;;; Wiring

(define-connection controller serial missile-bus 0)
(define-connection gps serial missile-bus 1)
(define-connection ins-gyro serial missile-bus 2)
(define-connection seeker-tracker serial missile-bus 3)
(define-connection fin-control serial missile-bus 4)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The Navaigation System and its dependencies
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(define-system navigation-system
    :components (missile-bus controller gps ins-gyro seeker-tracker fin-control)
    :roles ((controller controller)
	    (sensor gps)
	    (sensor ins-gyro)
	    (sensor seeker-tracker)
	    (actuator fin-control)
	    )
    )

;; Should the :machines below include BOTH the ControllerBoard and the sensor? **********

(defresource gps-position sensor-signal
	     :capability-requirements ((write missile-super-user) (read missile-user-read))
	     :machines (GPS Controller))

(defresource ins-gyro-position sensor-signal
	     :capability-requirements ((write missile-super-user) (read missile-user-read))
	     :machines (ins-gyro controller)
	     )

(defresource seeker-tracker-vector sensor-signal
	     :capability-requirements ((write missile-super-user) (read missile-user-read))
	     :machines (ins-gyro controller)
	     )

(defresource fin-control-command actuator-command
	     :capability-requirements ((write missile-super-user) (read missile-user-read))
	     :machines (fin-control controller)
	     )

(define-output gps-process gps-position)
(define-output ins-gyro-process ins-gyro-position)
(define-output seeker-tracker-process seeker-tracker-vector)
(define-output missile-guidance-process fin-control-command)

(define-input missile-guidance-process gps-position)
(define-input missile-guidance-process ins-gyro-position)
(define-input missile-guidance-process seeker-tracker-vector)

(define-impact data-integrity gps-position accuracy missile-guidance-process)
(define-impact data-integrity ins-gyro-position accuracy missile-guidance-process)
(define-impact data-integrity seeker-tracker-vector accuracy missile-guidance-process)
(define-impact data-integrity fin-control-command accuracy missile-guidance-process)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Promimity defines the ability to corrupt a signal
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-proximity typical-attacker gps radio)
(define-proximity typical-attacker seeker-tracker electronic-counter-measures)


 