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

(define-object-type can-be-typical-mixin
    :slots ((typical-p :tms t :initform nil :initarg :typical-p))
    )

(define-object-type system-entity
    :tms t
    :included-object-types (can-be-typical-mixin print-nicely-mixin)
    )

(define-object-type computer-resource
    :tms t
    :included-object-types (can-be-typical-mixin print-nicely-mixin)
    :slots ((machines :set-valued t :tms t)
	    (capability-requirements :set-valued t :tms t)))

(define-object-type code-in-memory
    :tms t
    :included-object-types (computer-resource)
    :slots ((load-image :tms t))
    )

(define-object-type data-resource
    :tms t
    :included-object-types (computer-resource)
    )

(define-object-type data-set
    :tms t
    :included-object-types (data-resource)
    )

(define-object-type file-system
    :tms t
    :included-object-types (data-resource)
    :slots ((files :set-valued t :tms t))
    )

(define-object-type file
    :tms t
  :included-object-types (data-resource)
  :slots ((directories :set-valued t :tms t)))

(define-object-type dynamically-loadable-code-file
    :tms t
    :included-object-types (file))

(define-object-type class-file
    :tms t
    :included-object-types (dynamically-loadable-code-file)
    :slots ((source-file :tms t)
	    (programs :set-valued t :tms t))
    )

(define-object-type source-file
    :tms t
    :included-object-types (file)
    :slots ((object-file :tms t))
    )

(define-object-type java-file
    :tms t
    :included-object-types (source-file)
    )

(define-object-type complex-encoded-data-file
    :tms t
    :included-object-types (file))

(define-object-type graphic-image-file
    :tms t
    :included-object-types (complex-encoded-data-file))

(define-object-type jpeg-file
    :tms t
    :included-object-types (graphic-image-file))

(define-object-type png-file
    :tms t
    :included-object-types (graphic-image-file))

(define-object-type graphic-video-file
    :tms t
    :included-object-types (complex-encoded-data-file))

(define-object-type wmv-file
    :tms t
    :included-object-types (graphic-video-file))

(define-object-type flv-file
    :tms t
    :included-object-types (graphic-video-file))

(define-object-type avi-file
    :tms t
    :included-object-types (graphic-video-file))

(define-object-type mp4-file
    :tms t
    :included-object-types (graphic-video-file))

(define-object-type database
    :tms t
    :included-object-types (data-resource)
    :slots ((schema :tms t) 
	    ;; Note, shouldn't there also be (servers :set-valued t)
	    (tables :set-valued t :tms t)))

;;; Note: need a notion of a web-site
;;;  this has several parts
;;; The web server program and its processes
;;; the home URL 
;;;  and the data store

(define-object-type password-file
    :tms t
  :included-object-types (file))

(define-object-type configuration-file
    :tms t
  :included-object-types (file))

(define-object-type scheduler-policy-file
    :tms t
  :included-object-types (file))

(define-object-type directory
    :tms t
  :included-object-types (computer-resource)
  :slots ((files :set-valued t :tms t)))

(define-object-type process
    :tms t
    :slots ((host-os :tms t)
	    (program :tms t)
	    (code-image :tms t))
    :included-object-types (computer-resource system-entity))

;;; presumably there could be both system programs
;;; and application programs
;;; should there be a privilege level specified?
(define-object-type program
    :tms t
    :slots ((host-os :tms t)
	    (processes :set-valued t :tms t)
	    (load-files :set-valued t :tms t))
    :included-object-types (computer-resource))

;;; This is the application level program
(define-object-type application-program
    :tms t
    :included-object-types (program)
    )

(define-object-type system-process
    :tms t
    :included-object-types (process))

(define-object-type server-process
    :tms t
    :included-object-types (process))

(define-object-type email-server-process
    :tms t
    :included-object-types (server-process))

(define-object-type storage-server-process
    :tms t
  :included-object-types (server-process))

(define-object-type display-server-process
    :tms t
  :included-object-types (server-process))

(define-object-type video-processing-server-process
    :tms t
  :included-object-types (server-process))

(define-object-type video-surveillance-manager-process
    :tms t
  :included-object-types (server-process))

(define-object-type operator-console-server-process
    :tms t
  :included-object-types (server-process))

(define-object-type opc-server-process
    :tms t
  :included-object-types (server-process))

(define-object-type web-server-process
    :tms t
    :included-object-types (server-process))

(define-object-type control-system-process
    :tms t
    :included-object-types (process))

(define-object-type embedded-sensor-process
    :tms t 
    :included-object-types (process))
    
;;; Note:
;;; It might be more correct to say that there is an apache server program
;;; which includers an apache core process as well as request specific processes
;;; these might run at different privilege levels.

(define-object-type apache-web-server-process
    :tms t
  :included-object-types (web-server-process))

;;; I rather think these are obsolete
;;;
; (define-object-type lisp-server-process
;     :tms t
;   :included-object-types (web-server-process))

; (define-object-type cl-http-server-process
;     :tms t
;     :included-object-types (lisp-server-process))

; (define-object-type allegro-http-server-process
;     :tms t
;     :included-object-types (lisp-server-process))

; (define-object-type iis-web-server-process
;     :tms t
;   :included-object-types (web-server-process))

(define-object-type user-process
    :tms t
    :included-object-types (process)
    )

(define-object-type scheduler
    :tms t
  :included-object-types (system-process))

(define-object-type logon-controller
    :tms t
  :included-object-types (system-process))

(define-object-type access-controller
    :tms t
  :included-object-types (system-process))

(define-object-type network-stack
    :tms t
  :included-object-types (system-process))

;;; Hardware interfaces are defined as hardware (e.g., network card, interface port)
;;; that is available for use (not necessarily in use) on a computer
(define-object-type hardware-interfaces
    :tms t
    :included-object-types (print-nicely-mixin)
    )

(define-object-type network-card
    :tms t
    :included-object-types (hardware-interfaces)
    )

(define-object-type port
    :tms t
    :included-object-types (hardware-interfaces)
    )

(define-object-type processing-unit
    :tms t
    :included-object-types (hardware-interfaces)
    )

;;(define-object-type ethernet
:tms t
;;  :included-object-types (network-card))

(define-object-type wifi
    :tms t
  :included-object-types (network-card))

(define-object-type bluetooth
    :tms t
  :included-object-types (network-card))

;;; Having a <port> device in-use and having an avaiable <port> port
;;; are esentially the same thing since an adversary can just remove 
;;; the <port> device to utilize the port
(define-object-type usb-2
    :tms t
  :included-object-types (port))

(define-object-type usb-3
    :tms t
  :included-object-types (port))

(define-object-type thunderbolt-2
    :tms t
  :included-object-types (port))

(define-object-type thunderbolt-3
    :tms t
  :included-object-types (port))

(define-object-type gpu
    :tms t
  :included-object-types (processing-unit))

(define-object-type video-display-processor
    :tms t
  :included-object-types (processing-unit))

(define-object-type asic
    :tms t
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
    :tms t
    :included-object-types (print-nicely-mixin)
    )

(define-object-type password
    :tms t
    :included-object-types (credential)
    )

(define-object-type certificate
    :tms t
    :included-object-types (credential)
    )

(define-object-type physical-token
    :tms t
    :included-object-types (credential)
    )

(define-object-type biometric-characteristic
    :tms t
    :included-object-types (credential)
    )

(define-object-type behavioral-biometric
    :tms t
    :included-object-types (biometric-characteristic)
    )

(define-object-type physical-biometric
    :tms t
    :included-object-types (biometric-characteristic)
    )


(define-object-type authorization-pool
    :tms t
  :slots ((machines :set-valued t :tms t)
          (capabilities :set-valued t :tms t)
          (users :set-valued t :tms t))
  :included-object-types (print-nicely-mixin))

;;; "capability" is a level of authorization good enough to access
;;; this thing.

(define-object-type capability
    :tms t
  :slots ((more-general :set-valued t :tms t)
          (authorization-pool :tms t)
          (more-specific :set-valued t :tms t))
  :included-object-types (print-nicely-mixin))

;;; Note: For mobile users don't we need to bind authorization
;;; pools with site?

;;; USER inherits can-be-typical-mixin from system-entity
(define-object-type user
    :tms t
    :slots (
	    (name :tms t)
	    (email-address :tms t)
	    (capabilities :set-valued t :tms t)
	    (authorization-pool :set-valued t :tms t)
	    (machines :set-valued t :tms t)
	    (ensemble :tms t :initform nil :initarg :ensemble)
	    (superuser-for :tms t :initform nil :set-valued t)
	    )
    :included-object-types (system-entity print-nicely-mixin))

(define-object-type attacker
    :tms t
    :included-object-types (user)
    :slots ((world :tms t)
	    ;; location is a subnet that the
	    ;; user might be on.  It's purpose is to provide an "IP address" for
	    ;; the attacker, who isn't at some specific machine but is somewhere
	    ;; in the external internet.
	    (location :tms t :set-valued t)
	    )
    )

;;; An ensemble is a collection of machines
;;; There are essentially the same from the attacker's perspective
;;; For each ensemble we specify a "typical" machine and a
;;; typical "user". The access rights for these typical elements
;;; apply to all members of the ensemble

(define-object-type ensemble
    :tms t
    :included-object-types (print-nicely-mixin)
    :slots ((typical-computer :tms t :initform nil :initarg :typical-computer)
	    (typical-user :tms t :initform nil :initarg :typical-user)
	    (enterprise :tms t :initarg :enterprise)
	    (size :tms t :initform 0 :initarg :size)
	    )
    )

(define-object-type user-set
    :tms t
  :slots ((os :tms t))
  :included-object-types (print-nicely-mixin))

(define-object-type workload
    :tms t
    :slots ((os :tms t)
	    (processes :tms t))
  :included-object-types (data-set print-nicely-mixin))

(define-object-type os-workload
    :tms t
  :slots ((os :tms t))
  :parts  ((user-workload workload)
           (server-workload workload))
  :included-object-types (print-nicely-mixin))

(define-object-type job-launcher
    :tms t
  :included-object-types (system-process))

(define-object-type os-job-admitter
    :tms t
  :parts ((user-job-admitter job-launcher)
          (server-job-admitter job-launcher))
  :included-object-types (system-process))

(define-object-type job-launch-request-queue
    :tms t
    :slots ((os :tms t))
    :included-object-types (print-nicely-mixin))

(define-object-type os-job-launch-request-queue
    :tms t
    :slots ((os :tms t))
    :parts ((user-job-launch-request-queue job-launch-request-queue)
	    (server-job-launch-request-queue job-launch-request-queue))
    :included-object-types (print-nicely-mixin))

(defun make-workload-for-os (os-instance)
  (with-atomic-action
      (let* ((os-name (role-name os-instance))
             (new-name (gentemp (concatenate 'string (string-upcase "workload") "-" (string os-name) "-")))
             (workload (make-object 'os-workload :name new-name)))
        (tell `[ltms:value-of (,workload os) ,os-instance])
        (tell `[ltms:value-of (,workload user-workload os) ,os-instance])
        (tell `[ltms:value-of (,workload server-workload os) ,os-instance])
        (tell `[ltms:value-of (,os-instance workload) ,workload]))))

(defun make-user-set-for-os (os-instance)
  (with-atomic-action
      (let* ((os-name (role-name os-instance))
             (new-name (gentemp (concatenate 'string (string-upcase "user-set") "-" (string os-name) "-")))
             (user-set (make-object 'user-set :name new-name)))
        (tell `[ltms:value-of (,user-set os) ,os-instance])
        (tell `[ltms:value-of (,os-instance user-set) ,user-set]))))

(defun make-job-launch-queue-for-os (os-instance)
  (with-atomic-action
      (let* ((os-name (role-name os-instance))
	     (new-name (gentemp (concatenate 'string (string-upcase "job-launch-queue") "-" (string os-name) "-")))
	     (job-launch-queue (make-object 'os-job-launch-request-queue :name new-name)))
	(tell `[ltms:value-of (,job-launch-queue os) ,os-instance])
	(tell `[ltms:value-of (,os-instance job-launch-queue) ,job-launch-queue]))))

;;; Note:  This organization is probably wrong
;;; We probably want to characterize machines by their make and model number
;;; with the classes only reflecting just the broad family and slots
;;; reflecting the details
;;;  and possibly the configuration of components
;;; We probably want to characterize operating systems by Major Family 
;;;  (e.g. windows, linux, unix, macos)
;;;  with slots reflecting version

(define-object-type operating-system
    :tms t
    :slots ((workload :tms t)
	    (user-set :tms t)
	    (superuser :tms t :set-value t :Initform nil)
	    (machine :tms t)
	    (users :tms t :set-valued t :Initform nil)
	    (authorization-pool :tms t)
	    (job-launch-queue :tms t) 
	    (processes :set-valued t :tms t))
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
	   (tell `[ltms:value-of (?part host-os) ,os])
	   (ask [part-of ?part ?his-part]
		#'(lambda (just)
		    (declare (ignore just))
		    (ask [ltms:object-type-of ?his-part system-process]
			 #'(lambda (just)
			     (declare (ignore just))
			     (tell `[ltms:value-of (?his-part host-os) ,os]))))))))

(define-object-type unix
    :tms t
  :included-object-types (operating-system))

(define-object-type linux
    :tms t
  :included-object-types (unix))

(define-object-type embedded-linux
    :tms t
  :included-object-types (linux))

(define-object-type open-wrt
    :tms t
  :included-object-types (embedded-linux))

(define-object-type android
    :tms t
  :included-object-types (embedded-linux))

(define-object-type solaris
    :tms t
  :included-object-types (unix))

(define-object-type hp-ux 
    :tms t
  :included-object-types (unix))

(define-object-type windows
    :tms t
  :included-object-types (operating-system))

(define-object-type windows-95
    :tms t
  :included-object-types (windows))

(define-object-type windows-98
    :tms t
  :included-object-types (windows))

(define-object-type windows-nt
    :tms t
  :included-object-types (windows))

(define-object-type windows-2000
    :tms t
    :included-object-types (windows))

(define-object-type windows-xp
    :tms t
  :included-object-types (windows))

(define-object-type windows-7
    :tms t
    :included-object-types (windows))

(define-object-type windows-8
    :tms t
  :included-object-types (windows))

(define-object-type windows-embedded
    :tms t
  :included-object-types (windows))

(define-object-type windows-embedded-compact
    :tms t
  :included-object-types (windows-embedded))

(define-object-type windows-embedded-standard
    :tms t
  :included-object-types (windows-embedded))

(define-object-type windows-embedded-industry
    :tms t
  :included-object-types (windows-embedded))

(define-object-type real-time-operating-system
    :tms t
  :included-object-types (operating-system))


(define-object-type genera
    :tms t
  :included-object-types (operating-system))

(define-object-type mac
    :tms t
  :included-object-types (operating-system))

(define-object-type Mac-OS
    :tms t
  :included-object-types (mac))

(define-object-type OS-X
    :tms t
  :included-object-types (mac unix)) 

(define-object-type cisco-ios
    :tms t
  :included-object-types (operating-system))

(defgeneric operating-system-for-machine (machine-type))

(define-object-type has-policy-mixin
    :tms t
    :other-instance-variables ((positive-policies :accessor positive-policies :initform nil)
			       (negative-policies :accessor negative-policies :initform nil))
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Hardware
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-object-type hardware
    :tms t
    :slots ((hardware-interfaces :set-valued t :tms t))
    )

(define-object-type computer
    :tms t
    :parts ((os (operating-system-for-machine self)))
    :slots ((ip-addresses :set-valued t :tms t)
	    (subnets :set-valued t :tms t)
	    (resources :set-valued t :tms t)
	    (site :set-valued t :tms t)
	    (communication-protocols :set-valued t :tms t)
	    (system-type :tms t)
	    (health-status :tms t)
	    (ensemble :tms t :initform nil :initarg :ensemble)
	    (users :tms t :set-valued t :initform nil :Initarg :users))
    :included-object-types (has-policy-mixin hardware can-be-typical-mixin print-nicely-mixin))

(define-object-type attacker-computer
    :tms t
    :included-object-types (computer))

;;; Note: These are machines that are always on all of its subnets
(define-object-type fixed-computer
    :tms t
    :included-object-types (computer))

;;; Note: These are machines that are sometimes on some of its subnets
;;; and sometimes on others
;;; Probably need a notion of CONNECTION-EPISODE, i.e. time when its
;;; on a particular network
;;; Also probably need a notion of TYPICAL-ROVING-NETWORK
;;; i.e. some repreentative of all the nets it might roam onto
(define-object-type mobile-computer
    :tms t
    :included-object-types (computer))

(defmethod operating-system-for-machine ((self computer)) 'operating-system)

(define-object-type mac-computer
    :tms t
  :included-object-types (computer))

(define-object-type unix-computer
    :tms t
    :included-object-types (computer))

(define-object-type windows-computer
    :tms t
  :included-object-types (computer))

(define-object-type windows-95-computer
    :tms t
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-95-computer)) 'windows-95)

(define-object-type windows-98-computer
    :tms t
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-98-computer)) 'windows-98)

(define-object-type windows-nt-computer
    :tms t
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-nt-computer)) 'windows-nt)

(define-object-type windows-2000-computer
    :tms t
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-2000-computer)) 'windows-2000)

(define-object-type windows-xp-computer
    :tms t
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-xp-computer)) 'windows-xp)

(define-object-type windows-7-computer
    :tms t
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-7-computer)) 'windows-7)

(define-object-type windows-8-computer
    :tms t
  :included-object-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-8-computer)) 'windows-8)

(define-object-type mac-os-computer
    :tms t
  :included-object-types (mac-computer))

;;; Might also want to elaborate all the variants of OSX and Linux
(defmethod operating-system-for-machine ((self mac-os-computer)) 'mac-os)

(define-object-type os-x-computer
    :tms t
  :included-object-types (mac-computer))

(defmethod operating-system-for-machine ((self os-x-computer)) 'mac-os-x)

(define-object-type linux-computer
    :tms t
  :included-object-types (unix-computer))

(defmethod operating-system-for-machine ((self linux-computer)) 'linux)

(define-object-type embedded-linux-computer
    :tms t
  :included-object-types (unix-computer))

(defmethod operating-system-for-machine ((self embedded-linux-computer)) 'embedded-linux)

(define-object-type solaris-computer
    :tms t
  :included-object-types (unix-computer))

(defmethod operating-system-for-machine ((self solaris-computer)) 'solaris)
  
(define-object-type lispm-computer
    :tms t
  :included-object-types (computer))

(defmethod operating-system-for-machine ((self lispm-computer)) 'genera)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; IP addresses and masks
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


#+genera
(define-object-type ip-address
    :tms t
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
    :tms t
    :slots ((octet1 :tms t)
	    (octet2 :tms t)
	    (octet3 :tms t)
	    (octet4 :tms t))
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
    :tms t
    :parts ((ip-address ip-address)
	    (mask ip-address)))

(define-object-type subnet-mask
    :tms t
  :other-instance-variables ((exception-masks :accessor exception-masks :initform nil)
			     (intervals :accessor intervals :initform nil)
			     (intervals-computed? :accessor intervals-computed? :initform nil))
  :included-object-types (basic-subnet-mask print-nicely-mixin))

(defmethod intervals :around ((mask subnet-mask))
  (unless (intervals-computed? mask)
    (compute-intervals mask))
  (call-next-method))

(define-object-type positive-location
    :tms t
  :included-object-types (subnet-mask))

(define-object-type negative-location
    :tms t
  :included-object-types (subnet-mask))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Subnets and network traffic
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(define-object-type network-traffic
    :tms t
  :slots ((subnet :tms t))
  :included-object-types (print-nicely-mixin))

(defun make-traffic-for-subnet (subnet)
  (with-atomic-action
    (let* ((subnet-name (role-name subnet))
           (new-name (gentemp (concatenate 'string (string-upcase "traffic") "-" (string subnet-name) "-")))
           (traffic (make-object 'network-traffic :name new-name)))
      (tell `[ltms:value-of (,traffic subnet) ,subnet])
      (tell `[ltms:value-of (,subnet network-traffic) ,traffic]))))

(define-object-type subnet-mixin
    :tms t
    :slots ((computers :set-valued t :tms t)
	    (routers :set-valued t :tms t))
    )

(define-object-type subnet
    :tms t
    :slots ((network-traffic :tms t)
	    (site :tms t))
  :parts ((mask subnet-mask))
  :included-object-types (subnet-mixin print-nicely-mixin)
  :initializations ((make-traffic-for-subnet #-genera self #+genera scl:self)))

;;; This is a "star-like" wired subnet in which packets are delivered from
;;; the connected devices to the switch which sends them to the connected
;;; device which is the intended destination.  Is there a "promiscuous" mode in which 
;;; a connected device gets sent every packet?

(define-object-type switched-subnet
    :tms t
  :slots ((switch :tms t))
  :included-object-types (subnet))

;;; This is a network type like the old thick ethernet
;;; in which any device physically connected to it can see every packet
(define-object-type shared-media-subnet
    :tms t
    :included-object-types (subnet))

;;; In addition anybody nearby could see any packet
(define-object-type wireless-subnet
    :tms t
    :included-object-types (shared-media-subnet))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Switches and Routers
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; An unmastered medium is something
;;; that has promiscuous access, like a
;;; switch (maybe more appropriate would be switched-network)
;;; or a bus without a master, e.g. canbus

(define-object-type unmastered-medium
    :tms t
    :slots ((connected-systems :set-valued t :tms t))
    )

;; A switch is on one subnet.
;; it is reponsible in a switched network for sending
;; traffic between the computers connected to that subnet
;;; Doesn't it also connect to a next level router?


(define-object-type switch 
    :tms t
    ;; PUT IN FOR AUTOPILOT EXAMPLE
    ;; WHERE THE SWITCH HAS PORTS
    :slots ((ports :set-valued t :tms t))
    :included-object-types (unmastered-medium computer))

(define-object-type wireless-router
    :tms t
    :included-object-types (switch))

(define-object-type wired-switch
    :tms t
    :included-object-types (switch)
    )

;; router is the thing connecting subnets
;; One might want to specialize this later into things with 
;; more specific capabilities

;; this doesn't need subnets slot because
;; computer provides that
(define-object-type router
    :tms t
  :included-object-types (computer)
  )

;; we'll assume that iot cameras are stationary
;; (i.e., have fixed IPs)
(define-object-type iot-camera
    :tms t
  :included-object-types (computer)
  )

(define-object-type wireless-access-point
    :tms t
  :included-object-types (computer)
  )

(define-object-type smart-phone
    :tms t
  :included-object-types (mobile-computer))

(define-object-type tablet
    :tms t
  :included-object-types (mobile-computer))

(define-object-type enterprise
    :tms t
    :included-object-types (print-nicely-mixin)
    :slots ((sites :set-valued t :tms t :initform nil :initarg :sites))
    )

(define-object-type site
    :tms t
  :included-object-types (print-nicely-mixin)
  :parts ((net-mask subnet-mask))
  :slots ((subnets :set-valued t :tms t)
	  (enterprise :tms t :initarg :enterprise :initform nil)
	  ))

(define-object-type external-internet
    :tms t
    :included-object-types (subnet-mixin print-nicely-mixin)
    :slots ((subnets :set-valued t :tms t)
	    ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Protocols
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-object-type communication-protocols
    :tms t
    :included-object-types (print-nicely-mixin)
    )

;; logon protocols (telnet, ssh)
(define-object-type logon-protocol
    :tms t
    :included-object-types (communication-protocols)
    )

(define-object-type telnet
    :tms t
    :included-object-types (logon-protocol)
    )

(define-object-type ssh
    :tms t
    :included-object-types (logon-protocol)
    )

;; web protocols (http, https)
(define-object-type web-protocol 
    :tms t
    :included-object-types (communication-protocols)
    )

(define-object-type http
    :tms t
    :included-object-types (web-protocol)
    )

(define-object-type https
    :tms t
    :included-object-types (web-protocol)
    )

;; transfer protocols (ftp, ftps)
(define-object-type transfer-protocol
    :tms t
    :included-object-types (communication-protocols)
    )

(define-object-type ftp 
    :tms t
    :included-object-types (transfer-protocol)
    )

(define-object-type ftps
    :tms t
    :included-object-types (transfer-protocol)
    )

;; multimedia protocols (skype)
(define-object-type multimedia-protocol
    :tms t
    :included-object-types (communication-protocols)
    )

(define-object-type voip
    :tms t
    :included-object-types (communication-protocols)
    )

;; proprietary protocols (logon port 8992)
(define-object-type proprietary-protocol
    :tms t
    :included-object-types (communication-protocols)
    )

(define-object-type email-send-protocol
    :tms t
    :included-object-types (communication-protocols)
    )

(define-object-type smtp 
    :tms t
    :included-object-types (email-send-protocol)
    )

(define-object-type email-receive-protocol
    :tms t
    :included-object-types (communication-protocols)
    )

(define-object-type email-pop
    :tms t
    :included-object-types (email-receive-protocol)
    )

(define-object-type imap
    :tms t
    :included-object-types (email-receive-protocol)
    )

(define-object-type database-protocol
    :tms t
    :included-object-types (communication-protocols)
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Buses that machines plug into
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-object-type bus
    :tms t
    :slots ((slots :set-valued t :tms t))
    :included-object-types (unmastered-medium print-nicely-mixin))

;;; This is the standard automotive and other control system
;;; bus.  It's not a network
(define-object-type canbus
    :tms t
    :slots ()
    :included-object-types (bus))


(define-object-type peripheral
    :tms t
    :slots ((hardware-interfaces :set-valued t :tms t))
    :included-object-types (hardware print-nicely-mixin)
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Control System
;;;   Includes a sensor, an effector and a controller
;;;    the controller is a computer
;;;
;;;   Notes: maybe this should really be a sensor-set
;;;          and an effector set
;;;       
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-object-type controller
    :tms t
    :included-object-types (computer)
    :slots ((set-point :tms t)
	    (controller-parameters :tms t)
	    (inputs :set-valued t :tms t))
    )

(define-object-type sensor
    :tms t
    :included-object-types (hardware)
    :slots ((sensed-value :tms t)
	    (physical-signal :tms t))
    )

(define-object-type effector
    :tms t
    :included-object-types (hardware)
    :slots ((command :tms t)
	    (physical-position :tms t))
    )

(define-object-type system
    :tms t
    :included-object-types (print-nicely-mixin)
    :slots ((components :set-valued t :tms t))
    )

(define-object-type control-system
    :included-object-types (system)
    :tms t
    :slots ((sensors :tms t :set-valued t)
	    (controller :tms t)
	    (effectors :set-valued t :tms t ))
    )

(define-object-type auto-pilot
    :tms t
    :included-object-types (computer peripheral)
    )

(define-object-type gps
    :tms t
    :included-object-types (computer peripheral)
    )

;;; ADDED FOR AUTOPILOT BUT PROBABLY IT SHOULD HAVE BEEN HERE
;;; ALREADY.  SENSORS PRODUCE SIGNALS.
(define-object-type sensor-signal
    :tms t
    :included-object-types (data-resource)
    )




