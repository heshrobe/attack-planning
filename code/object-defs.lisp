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
    :slots ((typical-p :initarg :typical-p :initform nil))
    )

(define-object-type aplan-object 
    :slots ()
  )

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defmacro define-aplan-object (name &rest plist)
    (let* ((super-types (getf plist :super-types))
	   (slots (getf plist :slots)))
      (loop for slot in slots
	  unless (getf (rest slot) :truth-maintenance)
	  do (setf (getf (rest slot) :truth-maintenance) 'value-of))
      (setf (getf plist :included-object-types) `(,@super-types aplan-object)
	    (getf plist :tms) t)
      (remf plist :super-types)
      )
    `(define-object-type ,name ,@plist)))

(defmethod ji::part-of-predicate-for-object-type ((thing aplan-object)) 'named-component)

(define-aplan-object system-entity
    :super-types (can-be-typical-mixin print-nicely-mixin)
    )

(define-aplan-object in-authorization-pool
    :slots ((authorization-pool :set-valued t)))

(define-aplan-object has-owner-mixin
    :super-types (print-nicely-mixin)
    :slots ((owner :initarg :owner)))

(define-aplan-object computer-resource
    :super-types (has-owner-mixin in-authorization-pool can-be-typical-mixin print-nicely-mixin)
    :slots ((machines :set-valued t)
            (primary-machine)
	    (capability-requirements :set-valued t)))

(define-aplan-object code-in-memory
    :super-types (computer-resource)
    :slots ((load-image ))
    )

(define-aplan-object data-resource
    :super-types (computer-resource)
    )

(define-aplan-object data-set
    :super-types (data-resource)
    )

(define-aplan-object file-system
    :super-types (data-resource)
    :slots ((files :set-valued t ))
    )

(define-aplan-object file
  :super-types (data-resource)
  :slots ((directories :set-valued t )))

(define-aplan-object dynamically-loadable-code-file
    :super-types (file))

(define-aplan-object class-file
    :super-types (dynamically-loadable-code-file)
    :slots ((source-file )
	    (programs :set-valued t ))
    )

(define-aplan-object source-file
    :super-types (file)
    :slots ((object-file ))
    )

(define-aplan-object java-file
    :super-types (source-file)
    )

(define-aplan-object complex-encoded-data-file
    :super-types (file))

(define-aplan-object graphic-image-file
    :super-types (complex-encoded-data-file))

(define-aplan-object jpeg-file
    :super-types (graphic-image-file))

(define-aplan-object png-file
    :super-types (graphic-image-file))

(define-aplan-object graphic-video-file
    :super-types (complex-encoded-data-file))

(define-aplan-object wmv-file
    :super-types (graphic-video-file))

(define-aplan-object flv-file
    :super-types (graphic-video-file))

(define-aplan-object avi-file
    :super-types (graphic-video-file))

(define-aplan-object mp4-file
    :super-types (graphic-video-file))

(define-aplan-object database
    :super-types (data-resource)
    :slots ((schema ) 
	    ;; Note, shouldn't there also be (servers
	    ;; :set-valued t)
	    (tables :set-valued t )))

;;; Note: need a notion of a web-site
;;;  this has several parts
;;; The web server program and its processes
;;; the home URL 
;;;  and the data store

(define-aplan-object password-file
  :super-types (file))

(define-aplan-object configuration-file
  :super-types (file))

(define-aplan-object scheduler-policy-file
  :super-types (file))

(define-aplan-object process
    :slots ((host-os )
	    (program )
	    (code-image ))
    :super-types (computer-resource system-entity))

;;; presumably there could be both system programs
;;; and application programs
;;; should there be a privilege level specified?
(define-aplan-object program
    :slots ((host-os )
	    (processes :set-valued t )
            (generic)
            (cpe)
	    (load-files :set-valued t ))
    :super-types (computer-resource))

;;; This is the application level program
(define-aplan-object application-program
    :super-types (program)
    )

(define-aplan-object system-process
    :super-types (process))

(define-aplan-object server-process
    :super-types (process))

(define-aplan-object email-server-process
    :super-types (server-process))

(define-aplan-object storage-server-process
  :super-types (server-process))

(define-aplan-object display-server-process
  :super-types (server-process))

(define-aplan-object video-processing-server-process
  :super-types (server-process))

(define-aplan-object video-surveillance-manager-process
  :super-types (server-process))

(define-aplan-object operator-console-server-process
  :super-types (server-process))

(define-aplan-object opc-server-process
  :super-types (server-process))

(define-aplan-object web-server-process
    :super-types (server-process))

(define-aplan-object control-system-process
    :super-types (process))

(define-aplan-object embedded-sensor-process
    :super-types (process))

(define-aplan-object embedded-actuator-process
    :super-types (process))
    
;;; Note:
;;; It might be more correct to say that there is an apache server program
;;; which includers an apache core process as well as request specific processes
;;; these might run at different privilege levels.

(define-aplan-object apache-web-server-process
  :super-types (web-server-process))

;;; I rather think these are obsolete
;;;
; (define-aplan-object lisp-server-process
;     
;   :super-types (web-server-process))

; (define-aplan-object cl-http-server-process
;     
;     :super-types (lisp-server-process))

; (define-aplan-object allegro-http-server-process
;     
;     :super-types (lisp-server-process))

; (define-aplan-object iis-web-server-process
;     
;   :super-types (web-server-process))

(define-aplan-object user-process
    :super-types (process)
    )

(define-aplan-object application-process 
    :super-types (user-process)
    )

(define-aplan-object office-process
  :super-types (application-process)
  )
  

(define-aplan-object browser-process 
    :super-types (user-process))

(define-aplan-object safari-process
    :super-types (browser-process)
    )

(define-aplan-object chrome-process
    :super-types (browser-process)
    )

(define-aplan-object ie-process
    :super-types (browser-process)
    )

(define-aplan-object firefox
  :super-types (browser-process)
  )

(define-aplan-object scheduler
  :super-types (system-process))

(define-aplan-object logon-controller
  :super-types (system-process))

(define-aplan-object access-controller
  :super-types (system-process))

(define-aplan-object network-stack
  :super-types (system-process))

;;; Hardware interfaces are defined as hardware (e.g., network card, interface port)
;;; that is available for use (not necessarily in use) on a computer
(define-aplan-object hardware-interfaces
    :super-types (print-nicely-mixin)
    )

(define-aplan-object network-card
    :super-types (hardware-interfaces)
    )

(define-aplan-object port
    :super-types (hardware-interfaces)
    )

(define-aplan-object processing-unit
    :super-types (hardware-interfaces)
    )

;;(define-aplan-object ethernet
;;  :super-types (network-card))

(define-aplan-object wifi
  :super-types (network-card))

(define-aplan-object bluetooth
  :super-types (network-card))

;;; Having a <port> device in-use and having an avaiable <port> port
;;; are esentially the same thing since an adversary can just remove 
;;; the <port> device to utilize the port
(define-aplan-object usb-2
  :super-types (port))

(define-aplan-object usb-3
  :super-types (port))

(define-aplan-object thunderbolt-2
  :super-types (port))

(define-aplan-object thunderbolt-3
  :super-types (port))

(define-aplan-object gpu
  :super-types (processing-unit))

(define-aplan-object video-display-processor
  :super-types (processing-unit))

(define-aplan-object asic
  :super-types (processing-unit))

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

(define-aplan-object credential
    :super-types (computer-resource)
    )

(define-aplan-object password
    :super-types (credential)
    )

(define-aplan-object certificate
    :super-types (credential)
    )

(define-aplan-object physical-token
    :super-types (credential)
    )

(define-aplan-object encryption-key
    :super-types (credential))

(define-aplan-object biometric-characteristic
    :super-types (credential)
    )

(define-aplan-object behavioral-biometric
    :super-types (biometric-characteristic)
    )

(define-aplan-object physical-biometric
    :super-types (biometric-characteristic)
    )

(define-aplan-object has-resources-mixin
    :slots ((resources :set-valued t )))

(define-aplan-object authorization-pool
  :slots ((machines :set-valued t )
          (capabilities :set-valued t )
          (users :set-valued t ))
  :super-types (has-resources-mixin print-nicely-mixin))

(define-aplan-object domain
    :super-types (authorization-pool))

;;; "capability" is a level of authorization good enough to access
;;; this thing.

(define-aplan-object capability
  :slots ((more-general :set-valued t )
          (authorization-pool )
          (more-specific :set-valued t)
          (role :initarg :role))
  :super-types (print-nicely-mixin))

;;; Note: For mobile users don't we need to bind authorization
;;; pools with site?


;;; USER inherits can-be-typical-mixin from system-entity
(define-aplan-object user
    :slots (
	    (name )
	    (email-address )
	    (capabilities :set-valued t )
	    (machines :set-valued t )
	    (ensemble  :initarg :ensemble)
	    (superuser-for :set-valued t)
	    )
    :super-types (in-authorization-pool system-entity print-nicely-mixin))

(define-aplan-object normal-user
    :super-types (user))

(define-aplan-object admin-user
    :super-types (user))

(define-aplan-object domain-admin
    :super-types (admin-user))

(define-aplan-object attacker
    :super-types (user)
    :slots ((world )
	    ;; location is a subnet that the
	    ;; user might be on.  It's purpose is to provide an "IP address" for
	    ;; the attacker, who isn't at some specific machine but is somewhere
	    ;; in the external internet.
	    (location  :set-valued t)
	    )
    )

(define-aplan-object collection
    :super-types (print-nicely-mixin)
    :slots ((member-type :initarg :member-type)
            (members :initarg :member :set-valued t))
    )

(define-aplan-object file-collection
    :super-types (data-resource collection)
    :slots ((member-type :initform 'file))
    )

(define-aplan-object directory
    :super-types (file-collection)
    :slots ((files :set-valued t ))
    )

;;; An ensemble is a collection of machines
;;; There are essentially the same from the attacker's perspective
;;; For each ensemble we specify a "typical" machine and a
;;; typical "user". The access rights for these typical elements
;;; apply to all members of the ensemble

(define-aplan-object ensemble
    :super-types (collection print-nicely-mixin)
    :slots ((typical-computer :initarg :typical-computer)
	    (typical-user :initarg :typical-user)
	    (enterprise  :initarg :enterprise)
	    (size  :initarg :size)
	    (ip-range  :initarg :ip-range)
	    )
    )

(define-aplan-object user-set
  :slots ((os ))
  :super-types (print-nicely-mixin))

(define-aplan-object cycle-pool
    :slots ((os ))
    :super-types (computer-resource print-nicely-mixin)
    )

(define-aplan-object workload
    :slots ((os )
	    (processes ))
  :super-types (data-set print-nicely-mixin))

(define-aplan-object os-workload
  :slots ((os ))
  :parts  ((user-workload workload)
           (server-workload workload))
  :super-types (print-nicely-mixin))

(define-aplan-object job-launcher
  :super-types (system-process))

(define-aplan-object os-job-admitter
  :parts ((user-job-admitter job-launcher)
          (server-job-admitter job-launcher))
  :super-types (system-process))

(define-aplan-object job-launch-request-queue
    :slots ((os ))
    :super-types (print-nicely-mixin))

(define-aplan-object os-job-launch-request-queue
    :slots ((os ))
    :parts ((user-job-launch-request-queue job-launch-request-queue)
	    (server-job-launch-request-queue job-launch-request-queue))
    :super-types (print-nicely-mixin))

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
	     (job-launch-queue (make-object 'os-job-launch-request-queue :name new-name))
             (user-job-launch-queue (subpart-named job-launch-queue 'user-job-launch-request-queue))
             (server-job-launch-queue (subpart-named job-launch-queue 'server-job-launch-request-queue)))        
	(tell `[value-of (,job-launch-queue os) ,os-instance])
	(tell `[value-of (,os-instance job-launch-queue) ,job-launch-queue])
        (tell `[value-of (,user-job-launch-queue os) ,os-instance])
        (tell `[value-of (,server-job-launch-queue os) ,os-instance])
        )))

;;; Note:  This organization is probably wrong
;;; We probably want to characterize machines by their make and model number
;;; with the classes only reflecting just the broad family and slots
;;; reflecting the details
;;;  and possibly the configuration of components
;;; We probably want to characterize operating systems by Major Family 
;;;  (e.g. windows, linux, unix, macos)
;;;  with slots reflecting version

(define-aplan-object operating-system
    :slots ((workload )
	    (user-set )
	    (superuser :set-valued t :Initform nil)
	    (machine )
	    (users :set-valued t :Initform nil)
	    (job-launch-queue ) 
	    (processes :set-valued t ))
    :initializations ((make-workload-for-os self)
                      (make-user-set-for-os  self)
                      (make-job-launch-queue-for-os self)
                      (initialize-os-slots-of-parts self)
                      )
    :parts ((scheduler scheduler)
            (job-admitter os-job-admitter)
            (logon-controller logon-controller)
            (access-controller access-controller)
            (network-monitor network-stack)
	    )
    :super-types (in-authorization-pool print-nicely-mixin))

(defmethod initialize-os-slots-of-parts ((os operating-system))
  (ask `[part-of ,os ?part]
       #'(lambda (just)
	   (declare (ignore just))
	   (tell `[value-of (?part host-os) ,os])
	   (ask [part-of ?part ?his-part]
		#'(lambda (just)
		    (declare (ignore just))
		    (ask [ltms:object-type-of ?his-part system-process]
			 #'(lambda (just)
			     (declare (ignore just))
			     (tell `[value-of (?his-part host-os) ,os]))))))))

(define-aplan-object unix
  :super-types (operating-system))

(define-aplan-object linux
  :super-types (unix))

(define-aplan-object embedded-linux
  :super-types (linux))

(define-aplan-object open-wrt
  :super-types (embedded-linux))

(define-aplan-object android
  :super-types (embedded-linux))

(define-aplan-object solaris
  :super-types (unix))

(define-aplan-object hp-ux 
  :super-types (unix))

(define-aplan-object windows
  :super-types (operating-system))

(define-aplan-object windows-95
  :super-types (windows))

(define-aplan-object windows-98
  :super-types (windows))

(define-aplan-object windows-nt
  :super-types (windows))

(define-aplan-object windows-2000
    :super-types (windows))

(define-aplan-object windows-xp
  :super-types (windows))

(define-aplan-object windows-7
    :super-types (windows))

(define-aplan-object windows-8
  :super-types (windows))

(define-aplan-object windows-embedded
  :super-types (windows))

(define-aplan-object windows-embedded-compact
  :super-types (windows-embedded))

(define-aplan-object windows-embedded-standard
  :super-types (windows-embedded))

(define-aplan-object windows-embedded-industry
  :super-types (windows-embedded))

(define-aplan-object real-time-operating-system
  :super-types (operating-system))


(define-aplan-object genera
  :super-types (operating-system))

(define-aplan-object mac
  :super-types (operating-system))

(define-aplan-object Mac-OS
  :super-types (mac))

(define-aplan-object OS-X
  :super-types (mac unix)) 

(define-aplan-object cisco-ios
  :super-types (operating-system))

(defgeneric operating-system-for-machine (machine-type))

(define-aplan-object has-policy-mixin
    :other-instance-variables ((positive-policies :accessor positive-policies :initform nil)
			       (negative-policies :accessor negative-policies :initform nil))
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Hardware
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-aplan-object hardware
    :slots ((hardware-interfaces :set-valued t ))
    )

(define-aplan-object computer
    :parts ((os (operating-system-for-machine self))
	    (cycle-pool 'cycle-pool))
    :slots ((ip-addresses :set-valued t )
	    (subnets :set-valued t )
	    (site :set-valued t )
	    (communication-protocols :set-valued t )
	    (system-type )
	    (health-status )
	    (ensemble :initarg :ensemble)
	    (users :set-valued t :initform nil :Initarg :users)
	    )
    :super-types (has-resources-mixin has-policy-mixin hardware can-be-typical-mixin print-nicely-mixin))

(define-aplan-object attacker-computer
    :super-types (computer))

;;; Note: These are machines that are always on all of its subnets
(define-aplan-object fixed-computer
    :super-types (computer))

;;; Note: These are machines that are sometimes on some of its subnets
;;; and sometimes on others
;;; Probably need a notion of CONNECTION-EPISODE, i.e. time when its
;;; on a particular network
;;; Also probably need a notion of TYPICAL-ROVING-NETWORK
;;; i.e. some repreentative of all the nets it might roam onto
(define-aplan-object mobile-computer
    :super-types (computer))

(defmethod operating-system-for-machine ((self computer)) 'operating-system)

(define-aplan-object mac-computer
  :super-types (computer))

(define-aplan-object unix-computer
    :super-types (computer))

(define-aplan-object windows-computer
  :super-types (computer))

(define-aplan-object windows-95-computer
  :super-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-95-computer)) 'windows-95)

(define-aplan-object windows-98-computer
  :super-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-98-computer)) 'windows-98)

(define-aplan-object windows-nt-computer
  :super-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-nt-computer)) 'windows-nt)

(define-aplan-object windows-2000-computer
  :super-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-2000-computer)) 'windows-2000)

(define-aplan-object windows-xp-computer
  :super-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-xp-computer)) 'windows-xp)

(define-aplan-object windows-7-computer
  :super-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-7-computer)) 'windows-7)

(define-aplan-object windows-8-computer
  :super-types (windows-computer))

(defmethod operating-system-for-machine ((self windows-8-computer)) 'windows-8)

(define-aplan-object mac-os-computer
  :super-types (mac-computer))

;;; Might also want to elaborate all the variants of OSX and Linux
(defmethod operating-system-for-machine ((self mac-os-computer)) 'mac-os)

(define-aplan-object os-x-computer
  :super-types (mac-computer))

(defmethod operating-system-for-machine ((self os-x-computer)) 'mac-os-x)

(define-aplan-object linux-computer
  :super-types (unix-computer))

(defmethod operating-system-for-machine ((self linux-computer)) 'linux)

(define-aplan-object embedded-linux-computer
  :super-types (unix-computer))

(defmethod operating-system-for-machine ((self embedded-linux-computer)) 'embedded-linux)

(define-aplan-object solaris-computer
  :super-types (unix-computer))

(defmethod operating-system-for-machine ((self solaris-computer)) 'solaris)
  
(define-aplan-object lispm-computer
  :super-types (computer))

(defmethod operating-system-for-machine ((self lispm-computer)) 'genera)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; IP addresses and masks
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


#+genera
(define-aplan-object ip-address
  :slots (octet1 octet2 octet3 octet4)
  :other-instance-variables (integer)
  :super-types (print-nicely-mixin))

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
(define-aplan-object ip-address
    :slots ((octet1 )
	    (octet2 )
	    (octet3 )
	    (octet4 ))
  :super-types (print-nicely-mixin)
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

(defmethod ip-address-string ((iadd ip-address))
  (format nil "~d.~d.~d.~d"
	  (octet1 iadd) (octet2 iadd) (octet3 iadd) (octet4 iadd)))

(defmethod octal-ip-address-string ((iadd ip-address))
  (format nil "~o.~o.~o.~o"
	  (octet1 iadd) (octet2 iadd) (octet3 iadd) (octet4 iadd)))

(define-aplan-object basic-subnet-mask
    :parts ((ip-address ip-address)
	    (mask ip-address)))

(define-aplan-object subnet-mask
    :other-instance-variables ((exception-masks :accessor exception-masks :initform nil)
			       (intervals :accessor intervals :initform nil)
			       (intervals-computed? :accessor intervals-computed? :initform nil))
    :super-types (basic-subnet-mask print-nicely-mixin))

(defmethod intervals :around ((mask subnet-mask))
  (unless (intervals-computed? mask)
    (compute-intervals mask))
  (call-next-method))

(define-aplan-object positive-location
  :super-types (subnet-mask))

(define-aplan-object negative-location
  :super-types (subnet-mask))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Subnets and network traffic
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(define-aplan-object network-traffic
  :slots ((subnet ))
  :super-types (print-nicely-mixin))

(defun make-traffic-for-subnet (subnet)
  (with-atomic-action
    (let* ((subnet-name (role-name subnet))
           (new-name (gentemp (concatenate 'string (string-upcase "traffic") "-" (string subnet-name) "-")))
           (traffic (make-object 'network-traffic :name new-name)))
      (tell `[value-of (,traffic subnet) ,subnet])
      (tell `[value-of (,subnet network-traffic) ,traffic]))))

(define-aplan-object subnet-mixin
    :slots ((computers :set-valued t )
	    (routers :set-valued t ))
    )

(define-aplan-object subnet
    :slots ((network-traffic )
	    (site ))
  :parts ((mask subnet-mask))
  :super-types (subnet-mixin print-nicely-mixin)
  :initializations ((make-traffic-for-subnet #-genera self #+genera scl:self)))

;;; This is a "star-like" wired subnet in which packets are delivered from
;;; the connected devices to the switch which sends them to the connected
;;; device which is the intended destination.  Is there a "promiscuous" mode in which 
;;; a connected device gets sent every packet?

(define-aplan-object switched-subnet
  :slots ((switch ))
  :super-types (subnet))

;;; This is a network type like the old thick ethernet
;;; in which any device physically connected to it can see every packet
(define-aplan-object shared-media-subnet
    :super-types (subnet))

;;; In addition anybody nearby could see any packet
(define-aplan-object wireless-subnet
    :super-types (shared-media-subnet))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Switches and Routers
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; An unmastered medium is something
;;; that has promiscuous access, like a
;;; switch (maybe more appropriate would be switched-network)
;;; or a bus without a master, e.g. canbus

(define-aplan-object unmastered-medium
    :slots ((connected-systems :set-valued t ))
    )

;; A switch is on one subnet.
;; it is reponsible in a switched network for sending
;; traffic between the computers connected to that subnet
;;; Doesn't it also connect to a next level router?


(define-aplan-object switch 
    ;; PUT IN FOR AUTOPILOT EXAMPLE
    ;; WHERE THE SWITCH HAS PORTS
    :slots ((ports :set-valued t ))
    :super-types (unmastered-medium computer))

(define-aplan-object wireless-router
    :super-types (switch))

(define-aplan-object wired-switch
    :super-types (switch)
    )

(define-aplan-object cellular-modem
    :super-types (switch)
    )

;; router is the thing connecting subnets
;; One might want to specialize this later into things with 
;; more specific capabilities

;; this doesn't need subnets slot because
;; computer provides that
(define-aplan-object router
  :super-types (computer)
  )

;; we'll assume that iot cameras are stationary
;; (i.e., have fixed IPs)
(define-aplan-object iot-camera
  :super-types (computer)
  )

(define-aplan-object wireless-access-point
  :super-types (computer)
  )

(define-aplan-object smart-phone
  :super-types (mobile-computer))

(define-aplan-object tablet
  :super-types (mobile-computer))

(define-aplan-object enterprise
    :super-types (print-nicely-mixin)
    :slots ((sites :set-valued t  :initform nil :initarg :sites))
    )

(define-aplan-object site
  :super-types (print-nicely-mixin)
  :parts ((net-mask subnet-mask))
  :slots ((subnets :set-valued t )
	  (enterprise  :initarg :enterprise)
	  ))

(define-aplan-object external-internet
    :super-types (subnet-mixin print-nicely-mixin)
    :slots ((subnets :set-valued t )
	    ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Protocols
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-aplan-object communication-protocols
    :super-types (print-nicely-mixin)
    )

;; logon protocols (telnet, ssh)
(define-aplan-object logon-protocol
    :super-types (communication-protocols)
    )

(define-aplan-object telnet
    :super-types (logon-protocol)
    )

(define-aplan-object ssh
    :super-types (logon-protocol)
    )

;; web protocols (http, https)
(define-aplan-object web-protocol 
    :super-types (communication-protocols)
    )

(define-aplan-object http
    :super-types (web-protocol)
    )

(define-aplan-object https
    :super-types (web-protocol)
    )

;; transfer protocols (ftp, ftps)
(define-aplan-object transfer-protocol
    :super-types (communication-protocols)
    )

(define-aplan-object ftp 
    :super-types (transfer-protocol)
    )

(define-aplan-object ftps
    :super-types (transfer-protocol)
    )

;; multimedia protocols (skype)
(define-aplan-object multimedia-protocol
    :super-types (communication-protocols)
    )

(define-aplan-object voip
    :super-types (communication-protocols)
    )

;; proprietary protocols (logon port 8992)
(define-aplan-object proprietary-protocol
    :super-types (communication-protocols)
    )

(define-aplan-object email-send-protocol
    :super-types (communication-protocols)
    )

(define-aplan-object smtp 
    :super-types (email-send-protocol)
    )

(define-aplan-object email-receive-protocol
    :super-types (communication-protocols)
    )

(define-aplan-object email-pop
    :super-types (email-receive-protocol)
    )

(define-aplan-object imap
    :super-types (email-receive-protocol)
    )

(define-aplan-object database-protocol
    :super-types (communication-protocols)
    )

(define-aplan-object text
    :super-types (data-resource)
    )

(define-aplan-object application-file
    :super-types (data-resource)
    :slots ((application :initarg :application)))

(define-aplan-object email-message
    :super-types (data-resource)
    :slots ((body)
            (attachments :set-valued t :initarg :attachments)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Buses that machines plug into
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-aplan-object bus
    :slots ((slots :set-valued t ))
    :super-types (unmastered-medium print-nicely-mixin))

;;; This is the standard automotive and other control system
;;; bus.  It's not a network
(define-aplan-object canbus
    :slots ()
    :super-types (bus))


(define-aplan-object peripheral
    :slots ((hardware-interfaces :set-valued t ))
    :super-types (hardware print-nicely-mixin)
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

(define-aplan-object controller
    :super-types (computer)
    :slots ((set-point )
	    (controller-parameters )
	    (inputs :set-valued t ))
    )

(define-aplan-object sensor
    :super-types (hardware)
    :slots ((sensed-value )
	    (physical-signal ))
    )

(define-aplan-object effector
    :super-types (hardware)
    :slots ((command )
	    (physical-position ))
    )

(define-aplan-object system
    :super-types (print-nicely-mixin)
    :slots ((components :set-valued t ))
    )

(define-aplan-object control-system
    :super-types (system)
    :slots ((sensors  :set-valued t)
	    (controller )
	    (effectors :set-valued t  ))
    )

(define-aplan-object auto-pilot
    :super-types (computer peripheral)
    )

(define-aplan-object gps
    :super-types (computer peripheral)
    )

(define-aplan-object inertial-gyro
    :super-types (computer peripheral)
    )

(define-aplan-object seeker-tracker
    :super-types (computer peripheral)
    )

(define-aplan-object fin-control
    :super-types (computer peripheral)
    )

;;; ADDED FOR AUTOPILOT BUT PROBABLY IT SHOULD HAVE BEEN HERE
;;; ALREADY.  SENSORS PRODUCE SIGNALS.
(define-aplan-object sensor-signal
    :super-types (data-resource)
    )

(define-aplan-object actuator-command
    :super-types (data-resource)
    )




