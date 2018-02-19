;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)

;;; Notes: virtual machines


(define-object-type print-nicely-mixin)

(defvar *print-object-nicely* nil)

(defmethod print-object :around ((thing print-nicely-mixin) stream)
  (cond (*print-object-nicely*
         (let ((path (path-name thing)))
           (format stream "~{~a~^.~}" path)))
        (t (call-next-method))))

(define-object-type typical-object-mixin)

(define-object-type computer-resource
  :included-object-types (print-nicely-mixin)
  :slots ((machines :set-valued t)
          (capability-requirements :set-valued t)))

(define-object-type code-in-memory
    :included-object-types (computer-resource)
    :slots (load-image)
    )

(define-object-type data-resource
    :included-object-types (computer-resource)
    )

(define-object-type data-set
    :included-object-types (data-resource)
    )

(define-object-type file
  :included-object-types (data-resource)
  :slots ((directories :set-valued t)))

(define-object-type typical-file
    :included-object-types (file typical-object-mixin)
    )

(define-object-type dynamically-loadable-code-file
    :included-object-types (file))

(define-object-type class-file
    :included-object-types (dynamically-loadable-code-file)
    :slots (source-file 
	    (programs :set-valued t))
    )

(define-object-type typical-class-file
    :included-object-types (class-file typical-object-mixin))

(define-object-type source-file
    :included-object-types (file)
    :slots (object-file)
    )

(define-object-type java-file
    :included-object-types (source-file)
    )

(define-object-type typical-java-file
    :included-object-types (java-file typical-object-mixin)
    )

(define-object-type complex-encoded-data-file
    :included-object-types (file))

(define-object-type graphic-image-file
    :included-object-types (complex-encoded-data-file))

(define-object-type typical-graphics-image-file
    :included-object-types (graphic-image-file typical-object-mixin)
    )

(define-object-type jpeg-file
    :included-object-types (graphic-image-file))

(define-object-type png-file
    :included-object-types (graphic-image-file))

(define-object-type graphic-video-file
    :included-object-types (complex-encoded-data-file))

(define-object-type typical-graphics-video-file
    :included-object-types (graphic-video-file typical-object-mixin)
    )

(define-object-type wmv-file
    :included-object-types (graphic-video-file))

(define-object-type flv-file
    :included-object-types (graphic-video-file))

(define-object-type avi-file
    :included-object-types (graphic-video-file))

(define-object-type mp4-file
    :included-object-types (graphic-video-file))

(define-object-type database
    :included-object-types (data-resource)
    :slots ((schema) 
	    ;; Note, shouldn't there also be (servers :set-valued t)
	    (tables :set-valued t)))

;;; Note: need a notion of a web-site
;;;  this has several parts
;;; The web server program and its processes
;;; the home URL 
;;;  and the data store

(define-object-type password-file
  :included-object-types (file))

(define-object-type configuration-file
  :included-object-types (file))

(define-object-type scheduler-policy-file
  :included-object-types (file))

(define-object-type directory
  :included-object-types (computer-resource)
  :slots ((files :set-valued t)))

(define-object-type process
    :slots (host-os program code-image)
    :included-object-types (computer-resource))

;;; presumably there could be both system programs
;;; and application programs
;;; should there be a privilege level specified?
(define-object-type program
    :slots (host-os 
	    (processes :set-valued t)
	    (load-files :set-valued t))
    :included-object-types (computer-resource))

;;; This is the application level program
(define-object-type application-program
    :included-object-types (program)
    )

(define-object-type system-process
    :included-object-types (process))

(define-object-type server-process
    :included-object-types (process))

(define-object-type storage-server-process
  :included-object-types (server-process))

(define-object-type display-server-process
  :included-object-types (server-process))

(define-object-type video-processing-server-process
  :included-object-types (server-process))

(define-object-type video-surveillance-manager-process
  :included-object-types (server-process))

(define-object-type operator-console-server-process
  :included-object-types (server-process))

(define-object-type opc-server-process
  :included-object-types (server-process))

(define-object-type web-server-process
  :included-object-types (server-process))

;;; Note:
;;; It might be more correct to say that there is an apache server program
;;; which includers an apache core process as well as request specific processes
;;; these might run at different privilege levels.

(define-object-type apache-web-server-process
  :included-object-types (web-server-process))

(define-object-type lisp-server-process
  :included-object-types (web-server-process))

(define-object-type cl-http-server-process
    :included-object-types (lisp-server-process))

(define-object-type allegro-http-server-process
    :included-object-types (lisp-server-process))

(define-object-type iis-web-server-process
  :included-object-types (web-server-process))

(define-object-type user-process
    :included-object-types (process)
    )

(define-object-type typical-user-process
  :included-object-types (user-process typical-object-mixin))

(define-object-type scheduler
  :included-object-types (system-process))

(define-object-type logon-controller
  :included-object-types (system-process))

(define-object-type access-controller
  :included-object-types (system-process))

(define-object-type network-stack
  :included-object-types (system-process))

;;; Hardware interfaces are defined as hardware (e.g., network card, interface port)
;;; that is available for use (not necessarily in use) on a computer
(define-object-type hardware-interfaces
    :included-object-types (print-nicely-mixin)
    )

(define-object-type network-card
    :included-object-types (hardware-interfaces)
    )

(define-object-type port
    :included-object-types (hardware-interfaces)
    )

(define-object-type processing-unit
    :included-object-types (hardware-interfaces)
    )

;;(define-object-type ethernet
;;  :included-object-types (network-card))

(define-object-type wifi
  :included-object-types (network-card))

(define-object-type bluetooth
  :included-object-types (network-card))

;;; Having a <port> device in-use and having an avaiable <port> port
;;; are esentially the same thing since an adversary can just remove 
;;; the <port> device to utilize the port
(define-object-type usb-2
  :included-object-types (port))

(define-object-type usb-3
  :included-object-types (port))

(define-object-type thunderbolt-2
  :included-object-types (port))

(define-object-type thunderbolt-3
  :included-object-types (port))

(define-object-type gpu
  :included-object-types (processing-unit))

(define-object-type video-display-processor
  :included-object-types (processing-unit))

(define-object-type asic
  :included-object-types (processing-unit))

;;; Note: actually the machines are os's
;;; authorization pools are groups of machines that log in 
;;; the same users with the same passwords together

;;; Note: Later on we talk about passwords, but that should really
;;; be a specialization of a more general notion like "credential"
;;; Certificates are also credentials as are physical tokens like CAC 
;;; Cards and RSA token generators (hard and soft) as well as biometrics

;;; In general to log into a system you need to POSSESS the credential
;;; However, in the case of a password you can possess it if you know it
;;; For a physical credential (e.g. a CAC card) you actually have to have it
;;; (or possibly fake it, by knowing its contents and then duplicating the token)
;;; for a biometric credential you have to mimic the behavior or physical characteristic 
;;; requested (e.g. fingerprint spoofing).

(define-object-type credential
    :included-object-types (print-nicely-mixin)
    )

(define-object-type password
    :included-object-types (credential)
    )

(define-object-type certificate
    :included-object-types (credential)
    )

(define-object-type physical-token
    :included-object-types (credential)
    )

(define-object-type biometric-characteristic
    :included-object-types (credential)
    )

(define-object-type behavioral-biometric
    :included-object-types (biometric-characteristic)
    )

(define-object-type physical-biometric
    :included-object-types (biometric-characteristic)
    )


(define-object-type authorization-pool
  :slots ((machines :set-valued t)
          (capabilities :set-valued t)
          (users :set-valued t))
  :included-object-types (print-nicely-mixin))

;;; "capability" is a level of authorization good enough to access
;;; this thing.

(define-object-type capability
  :slots ((more-general :set-valued t)
          authorization-pool 
          (more-specific :set-valued t))
  :included-object-types (print-nicely-mixin))

;;; Note: For mobile users don't we need to bind authorization
;;; pools with site?

(define-object-type user
  :slots (location name
                   email-address 
                   (capabilities :set-valued t)
                   (authorization-pool :set-valued t)
                   (machines :set-valued t))
  :included-object-types (print-nicely-mixin))

(define-object-type attacker
    :included-object-types (user)
    :slots (world)
    )

(define-object-type typical-user
  :included-object-types (user typical-object-mixin))

(define-object-type user-set
  :slots (os)
  :included-object-types (print-nicely-mixin))

(define-object-type workload
  :slots (os processes)
  :included-object-types (data-set print-nicely-mixin))

(define-object-type os-workload
  :slots (os)
  :parts  ((user-workload workload)
           (server-workload workload))
  :included-object-types (print-nicely-mixin))

(define-object-type job-launcher
  :included-object-types (system-process))

(define-object-type os-job-admitter
  :parts ((user-job-admitter job-launcher)
          (server-job-admitter job-launcher))
  :included-object-types (system-process))

(define-object-type job-launch-request-queue
    :slots (os)
    :included-object-types (print-nicely-mixin))

(define-object-type os-job-launch-request-queue
    :slots (os)
    :parts ((user-job-launch-request-queue job-launch-request-queue)
	    (server-job-launch-request-queue job-launch-request-queue))
    :included-object-types (print-nicely-mixin))

(defun make-workload-for-os (os-instance)
  (with-atomic-action
      (let* ((os-name (role-name os-instance))
             (new-name (gentemp (concatenate 'string (string-upcase "workload") "-" (string os-name) "-")))
             (workload (make-object 'os-workload :name new-name)))
        (tell `[value-of (,workload os) ,os-instance])
        (tell `[value-of (,workload user-workload os) ,os-instance])
        (tell `[value-of (,workload server-workload os) ,os-instance])
        (tell `[value-of (,os-instance workload) ,workload]))))

(defun make-user-set-for-os (os-instance)
  (with-atomic-action
      (let* ((os-name (role-name os-instance))
             (new-name (gentemp (concatenate 'string (string-upcase "user-set") "-" (string os-name) "-")))
             (user-set (make-object 'user-set :name new-name)))
        (tell `[value-of (,user-set os) ,os-instance])
        (tell `[value-of (,os-instance user-set) ,user-set]))))

(defun make-job-launch-queue-for-os (os-instance)
  (with-atomic-action
      (let* ((os-name (role-name os-instance))
	     (new-name (gentemp (concatenate 'string (string-upcase "job-launch-queue") "-" (string os-name) "-")))
	     (job-launch-queue (make-object 'os-job-launch-request-queue :name new-name)))
	(tell `[value-of (,job-launch-queue os) ,os-instance])
	(tell `[value-of (,os-instance job-launch-queue) ,job-launch-queue]))))

;;; Note:  This organization is probably wrong
;;; We probably want to characterize machines by their make and model number
;;; with the classes only reflecting just the broad family and slots
;;; reflecting the details
;;;  and possibly the configuration of components
;;; We probably want to characterize operating systems by Major Family 
;;;  (e.g. windows, linux, unix, macos)
;;;  with slots reflecting version

(define-object-type operating-system
    :slots (workload user-set superuser authorization-pool job-launch-queue 
                     (processes :set-valued t))
    :initializations ((make-workload-for-os self)
                      (make-user-set-for-os  self)
                      (make-job-launch-queue-for-os self)
                      (initialize-os-slots-of-parts self)
                      )
    :parts ((scheduler scheduler)
            (job-admitter os-job-admitter)
            (logon-controller logon-controller)
            (access-controller access-controller)
            (network-monitor network-stack))
    :included-object-types (print-nicely-mixin))

(defmethod initialize-os-slots-of-parts ((os operating-system))
  (ask `[part-of ,os ?part]
       #'(lambda (just)
	   (declare (ignore just))
	   (tell `[value-of (?part host-os) ,os])
	   (ask [part-of ?part ?his-part]
		#'(lambda (just)
		    (declare (ignore just))
		    (ask [object-type-of ?his-part system-process]
			 #'(lambda (just)
			     (declare (ignore just))
			     (tell `[value-of (?his-part host-os) ,os]))))))))

(define-object-type unix
  :included-object-types (operating-system))

(define-object-type linux
  :included-object-types (unix))

(define-object-type embedded-linux
  :included-object-types (linux))

(define-object-type open-wrt
  :included-object-types (embedded-linux))

(define-object-type android
  :included-object-types (embedded-linux))

(define-object-type solaris
  :included-object-types (unix))

(define-object-type hp-ux 
  :included-object-types (unix))

(define-object-type windows
  :included-object-types (operating-system))

(define-object-type windows-95
  :included-object-types (windows))

(define-object-type windows-98
  :included-object-types (windows))

(define-object-type windows-nt
  :included-object-types (windows))

(define-object-type windows-2000
    :included-object-types (windows))

(define-object-type windows-xp
  :included-object-types (windows))

(define-object-type windows-7
    :included-object-types (windows))

(define-object-type windows-8
  :included-object-types (windows))

(define-object-type windows-embedded
  :included-object-types (windows))

(define-object-type windows-embedded-compact
  :included-object-types (windows-embedded))

(define-object-type windows-embedded-standard
  :included-object-types (windows-embedded))

(define-object-type windows-embedded-industry
  :included-object-types (windows-embedded))

(define-object-type real-time-operating-system
  :included-object-types (operating-system))


(define-object-type genera
  :included-object-types (operating-system))

(define-object-type mac
  :included-object-types (operating-system))

(define-object-type Mac-OS
  :included-object-types (mac))

(define-object-type OS-X
  :included-object-types (mac unix)) 

(define-object-type cisco-ios
  :included-object-types (operating-system))

(defgeneric operating-system-for-machine (machine-type))

(define-object-type has-policy-mixin
    :other-instance-variables ((positive-policies :accessor positive-policies :initform nil)
			       (negative-policies :accessor negative-policies :initform nil))
    )

(define-object-type computer
  :parts ((os (operating-system-for-machine self)))
  :slots ((ip-addresses :set-valued t)
          (subnets :set-valued t)
          (resources :set-valued t)
          (site :set-valued t)
          (hardware-interfaces :set-valued t)
          (communication-protocols :set-valued t)
          system-type
          health-status)
  :included-object-types (has-policy-mixin print-nicely-mixin))

(define-object-type typical-computer
    :included-object-types (computer typical-object-mixin)
    )

;;; Note: These are machines that are always on all of its subnets
(define-object-type fixed-computer
    :included-object-types (computer))

;;; Note: These are machines that are sometimes on some of its subnets
;;; and sometimes on others
;;; Probably need a notion of CONNECTION-EPISODE, i.e. time when its
;;; on a particular network
;;; Also probably need a notion of TYPICAL-ROVING-NETWORK
;;; i.e. some repreentative of all the nets it might roam onto
(define-object-type mobile-computer
    :included-object-types (computer))

(defmethod operating-system-for-machine ((self computer)) 'operating-system)

(define-object-type mac-computer
  :included-object-types (computer))

(define-object-type unix-computer
  :included-object-types (computer))

(define-object-type windows-computer
  :included-object-types (computer))

(define-object-type windows-95-computer
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-95-computer)) 'windows-95)

(define-object-type windows-98-computer
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-98-computer)) 'windows-98)

(define-object-type windows-nt-computer
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-nt-computer)) 'windows-nt)

(define-object-type windows-2000-computer
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-2000-computer)) 'windows-2000)

(define-object-type windows-xp-computer
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-xp-computer)) 'windows-xp)

(define-object-type windows-7-computer
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-7-computer)) 'windows-7)

(define-object-type windows-8-computer
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-8-computer)) 'windows-8)

(define-object-type mac-os-computer
  :included-object-types (mac-computer))

;;; Might also want to elaborate all the variants of OSX and Linux
(defmethod operating-system-for-machine ((self mac-os-computer)) 'mac-os)

(define-object-type os-x-computer
  :included-object-types (mac-computer))

(defmethod operating-system-for-machine ((self os-x-computer)) 'mac-os-x)

(define-object-type linux-computer
  :included-object-types (unix-computer))

(defmethod operating-system-for-machine ((self linux-computer)) 'linux)

(define-object-type embedded-linux-computer
  :included-object-types (unix-computer))

(defmethod operating-system-for-machine ((self embedded-linux-computer)) 'embedded-linux)

(define-object-type solaris-computer
  :included-object-types (unix-computer))

(defmethod operating-system-for-machine ((self solaris-computer)) 'solaris)
  
(define-object-type lispm-computer
  :included-object-types (computer))

(defmethod operating-system-for-machine ((self lispm-computer)) 'genera)

#+genera
(define-object-type ip-address
  :slots (octet1 octet2 octet3 octet4)
  :other-instance-variables (integer)
  :included-object-types (print-nicely-mixin))

#+genera
(scl:defwhopper (integer ip-address) ()
  (if (scl:variable-boundp integer)
    (scl:continue-whopper scl:self)
    (setq integer
          (+ (ash (octet1 scl:self) 24.)
             (ash (octet2 scl:self) 16.)
             (ash (octet3 scl:self) 8.)
             (octet4 scl:self)))))
#-genera
(define-object-type ip-address
  :slots (octet1 octet2 octet3 octet4)
  :included-object-types (print-nicely-mixin)
  :other-instance-variables ((integer :accessor ip-address-integer)))

#-genera
(defmethod ip-address-integer :around ((iadd ip-address))
  (if (slot-boundp iadd 'integer)
      (call-next-method)
    (let ((answer 0))
      (setq answer (dpb (octet4 iadd) (byte 8 0) answer))
      (setq answer (dpb (octet3 iadd) (byte 8 8) answer))
      (setq answer (dpb (octet2 iadd) (byte 8 16) answer))
      (setq answer (dpb (octet1 iadd) (byte 8 24) answer))
      (setf (ip-address-integer iadd) answer)
      answer)))

(define-object-type basic-subnet-mask
  :parts ((ip-address ip-address)
	  (mask ip-address)))

(define-object-type subnet-mask
  :other-instance-variables ((exception-masks :accessor exception-masks :initform nil)
			     (intervals :accessor intervals :initform nil)
			     (intervals-computed? :accessor intervals-computed? :initform nil))
  :included-object-types (basic-subnet-mask print-nicely-mixin))

(defmethod intervals :around ((mask subnet-mask))
  (unless (intervals-computed? mask)
    (compute-intervals mask))
  (call-next-method))

(define-object-type positive-location
  :included-object-types (subnet-mask))

(define-object-type negative-location
  :included-object-types (subnet-mask))

(define-object-type network-traffic
  :slots (subnet)
  :included-object-types (print-nicely-mixin))

(defun make-traffic-for-subnet (subnet)
  (with-atomic-action
    (let* ((subnet-name (role-name subnet))
           (new-name (gentemp (concatenate 'string (string-upcase "traffic") "-" (string subnet-name) "-")))
           (traffic (make-object 'network-traffic :name new-name)))
      (tell `[value-of (,traffic subnet) ,subnet])
      (tell `[value-of (,subnet network-traffic) ,traffic]))))

(define-object-type subnet-mixin
    :slots ((computers :set-valued t)
	    (routers :set-valued t))
    )

(define-object-type subnet
  :slots (network-traffic site)
  :parts ((mask subnet-mask))
  :included-object-types (subnet-mixin print-nicely-mixin)
  :initializations ((make-traffic-for-subnet #-genera self #+genera scl:self)))

(define-object-type switched-subnet
  :slots (switch)
  :included-object-types (subnet))

(define-object-type shared-media-subnet
  :included-object-types (subnet))

;; A switch is on one subnet.
;; it is reponsible in a switched network for sending
;; traffic between the computers connected to that subnet
(define-object-type switch 
  :included-object-types (computer))

;; router is the thing connecting subnets
;; One might want to specialize this later into things with 
;; more specific capabilities

;; this doesn't need subnets slot because
;; computer provides that
(define-object-type router
  :included-object-types (computer)
  )

;; we'll assume that iot cameras are stationary
;; (i.e., have fixed IPs)
(define-object-type iot-camera
  :included-object-types (computer)
  )

(define-object-type wireless-access-point
  :included-object-types (computer)
  )

(define-object-type typical-mobile-computer
    :included-object-types (mobile-computer typical-object-mixin)
    )

(define-object-type smart-phone
  :included-object-types (mobile-computer))

(define-object-type tablet
  :included-object-types (mobile-computer))

(define-object-type site
  :included-object-types (print-nicely-mixin)
  :parts ((net-mask subnet-mask))
  :slots ((subnets :set-valued t)))

(define-object-type external-internet
    :included-object-types (subnet-mixin print-nicely-mixin)
    :slots ((subnets :set-valued t)
	    ))

(define-object-type communication-protocols
    :included-object-types (print-nicely-mixin)
    )

;; logon protocols (telnet, ssh)
(define-object-type logon-protocol
    :included-object-types (communication-protocols)
    )

(define-object-type telnet
    :included-object-types (logon-protocol)
    )

(define-object-type ssh
    :included-object-types (logon-protocol)
    )

;; web protocols (http, https)
(define-object-type web-protocol 
    :included-object-types (communication-protocols)
    )

(define-object-type http
    :included-object-types (web-protocol)
    )

(define-object-type https
    :included-object-types (web-protocol)
    )

;; transfer protocols (ftp, ftps)
(define-object-type transfer-protocol
    :included-object-types (communication-protocols)
    )

(define-object-type ftp 
    :included-object-types (transfer-protocol)
    )

(define-object-type ftps
    :included-object-types (transfer-protocol)
    )

;; multimedia protocols (skype)
(define-object-type multimedia-protocol
    :included-object-types (communication-protocols)
    )

(define-object-type voip
    :included-object-types (transfer-protocol)
    )

;; proprietary protocols (logon port 8992)
(define-object-type proprietary-protocol
    :included-object-types (communication-protocols)
    )
