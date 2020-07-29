;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

;;; macros for describing environment
;;; makes the telling of the whole description atomic.

(in-package :aplan)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;;  Some useful utilities
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun kill-redefined-object (name)
  (let ((object (follow-path (list name) t  nil)))
    (when object
      (kill object))))

;;; This defines the rules that set up a set of forward-backward pointers from one object to another
(defmacro def-symmetric-pointers (rule-name from-type from-type-variable from-slot to-type to-type-variable to-slot
				  ;; Note: In SCBL destructuring-bind is very strict and so
				  ;; if from-condition (or to-condition) is nil, the destructuring-binds
				  ;; below will barf.  Allegro is more permissive, but ANSI say SBCL is correct
				  &key (from-condition (list nil nil) from-condition-p)
				    (to-condition (list nil nil)) to-condition-p)
  (let ((rule-1-name (intern (string-upcase (concatenate 'string (string rule-name) "-1"))))
        (rule-2-name (intern (string-upcase (concatenate 'string (string rule-name) "-2")))))
    (destructuring-bind (from-property from-value) from-condition
      (destructuring-bind (to-property to-value) to-condition
	`(progn
	   (defrule ,rule-1-name (:forward)
	     if [and [ltms:object-type-of ,from-type-variable ,from-type]
		     [value-of (,from-type-variable ,from-slot) ,to-type-variable]
		     [ltms:object-type-of ,to-type-variable ,to-type]
		     ,@(when from-condition-p `([value-of (,from-type-variable ,from-property) ,from-value]))
		     ]
	     then [value-of (,to-type-variable ,to-slot) ,from-type-variable])
	   (defrule ,rule-2-name (:forward)
	     if [and [ltms:object-type-of ,to-type-variable ,to-type]
		     [value-of (,to-type-variable ,to-slot) ,from-type-variable]
		     [ltms:object-type-of ,from-type-variable ,from-type]
		     ,@(when to-condition-p `([value-of (,to-type-variable ,to-property) ,to-value]))
		     ]
	     then [value-of (,from-type-variable ,from-slot) ,to-type-variable]))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Defining the structure of an enterprise
;;;  its sites and enclaves of machines
;;; And the external internet
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; An enterprise is a organization with multiple sites within it
(defmacro define-enterprise (name &key sites)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((enterprise (make-object 'enterprise :name ',name)))
       (declare (ignorable enterprise))
       ,@(loop for site-name in sites
	     collect `(tell `[value-of (,enterprise sites) ,(object-named ',site-name)])))))

;;; A site is (possibly) part of an enterprise
;;; It owns a range of net addresses, which might be broken down into subnets
;;; The range may be specified either as a CIDR (e.g. "01.010.10.10/24")
;;; or as a list of an address and mask
(defmacro defsite (name range &key (enterprise nil enterprise-p))
  (multiple-value-bind (address-string address-mask) (parse-range range)
    `(with-atomic-action
      (kill-redefined-object ',name)
      (let* ((site (make-object 'site :name ',name))
	     (enterprise (when ,enterprise-p (object-named ',enterprise)))
	     (net-mask (follow-path `(,site net-mask))))
	(declare (ignorable enterprise))
	,@(when enterprise-p `((tell `[value-of (,site enterprise) ,enterprise])))
	(fill-in-subnet-mask net-mask ,address-string ,address-mask)
	site))))

;;; An ensemble is a collection of machines that identical from the attackers
;;; point of view.  Every ensemble has a typical instance which represents
;;; all the properties that are shared
(defmacro defensemble (name &key (enterprise nil enterprise-p)
				 (typical-computer nil computer-p)
				 (typical-user nil user-p)
				 (size 0 size-p)
				 (address-range nil address-range-p))
  `(with-atomic-action
    (kill-redefined-object ',name)
    (let* ((ensemble (make-object 'ensemble :name ',name)))
      ,@(when enterprise-p `((tell `[value-of (,ensemble enterprise) , (object-named ',enterprise)])))
      ,@(when computer-p `((tell `[value-of (,ensemble typical-computer) , (object-named ',typical-computer)])))
      ,@(when user-p `((tell `[value-of (,ensemble typical-user) ,(object-named ',typical-user)])))
      ,@(when size-p `((tell `[value-of (,ensemble size) ,',size])))
      ,@(when address-range-p
	  (multiple-value-bind (address mask) (parse-range address-range)
	  `((let ((subnet-mask (make-location-mask 'subnet-mask ,address ,mask)))
	      (tell `[value-of (,ensemble ip-range) ,subnet-mask])))))
      ensemble))
  )


(defmacro defexternal-internet (name &rest excluded-subnets)
  `(with-atomic-action
    (kill-redefined-object ',name)
    (let* ((site (make-object 'external-internet :name ',name))
	   (location (make-positive-location-mask "0.0.0.0" "0.0.0.0")))
      (tell `[value-of (,site subnets) ,location])
      ,@(loop for range in excluded-subnets
	    for (address mask) = (multiple-value-list (parse-range range))
	    collect `(push (make-location-mask 'subnet-mask ,address ,mask) (exception-masks location)))
      site)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Authorization Pools, Capabilities
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defmacro defauthorization-pool (name)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (make-object 'authorization-pool :name ',name)
     ))
(defmacro defcapability (name authorization-pool &key greater lesser)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((capability (make-object 'capability :name ',name)))
       (tell `[value-of (,capability authorization-pool) ,(follow-path '(,authorization-pool))])
       ,@(loop for g in greater
               collect `(tell `[value-of (,capability more-general) ,(follow-path '(,g))]))
       ,@(loop for l in lesser
               collect `(tell `[value-of (,capability more-specific) ,(follow-path '(,l))]))
       )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Stuff for defining the structure of a computer
;;; Its peripherals and its users
;;; Its processes and other resources
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmacro defcomputer (name computer-type
		       &key ip-address-string
			    superuser authorization-pool interfaces
			    (typical nil typical-p)
			    (ensemble nil ensemble-p))
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((computer (make-object ',computer-type :name ',name)))
       ,@(if (listp ip-address-string)
	    (loop for ip-address-string in ip-address-string
		collect `(add-ip-address-to-computer ,ip-address-string computer))
	   `((add-ip-address-to-computer ,ip-address-string computer)))
       ,@(when superuser
          `((tell `[value-of (,computer os superuser) ,(follow-path '(,superuser))])))
       ,@(when authorization-pool
         `((tell `[value-of (,computer os authorization-pool) ,(follow-path '(,authorization-pool))])))
       ,@(when interfaces
	   (loop for interface in interfaces
	       collect `(tell `[value-of (,computer hardware-interfaces) ,',interface])))
       ,@(when ensemble-p `((tell `[value-of (,computer ensemble) ,(object-named ',ensemble)])))
       ,@(when typical-p `((tell `[value-of (,computer typical-p) ,,typical])))
       computer)))

(defmacro define-peripheral (name &key peripheral-type interfaces commands)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((device (make-object ',peripheral-type :name ',name)))
       ,@(when interfaces
	   (loop for interface in interfaces
	       collect `(tell `[value-of (,device hardware-interfaces) ,',interface])))
       ,@(when commands
	   (loop for command in commands
		 collect `(tell `[command-to ,device ,',command])))
       device)))

(defmacro defbus (name &key bus-type slots)
  `(with-atomic-action
    (kill-redefined-object ',name)
    (let ((bus (make-object ',bus-type :name ',name)))
      ,@(when slots
	  (loop for slot in slots
		collect `(tell `[value-of (,bus slots) ,',slot])))
      bus)))

(defmacro define-connection (device interface bus slot) cpe
  `(let ((device (follow-path '(,device)))
	 (bus (follow-path '(,bus))))
     (tell `[connected-to ,device ,',interface ,bus ,',slot])))

(defmacro defprogram (role-name &key generic cpe)
  `(with-atomic-action
    (kill-redefined-object ',role-name)
    (make-object 'program :name ',role-name :generic ',generic :cpe ,cpe)))


(defmacro defprocess (role-name &key process-type machine program)
  `(with-atomic-action
    (kill-redefined-object ',role-name)
    (instantiate-a-process ',process-type '(,machine)
                           :role-name ',role-name 
                           :program '(,program))))

(defun instantiate-a-process (process-type machine &key role-name program)
  (let* ((process-name (or role-name (gentemp (concatenate 'string (string-upcase (string process-type)) "-"))))
         (machine (follow-path machine))
         (os (follow-path (list machine 'os)))
         (process (make-object process-type :name process-name))
         (workload (follow-path (list os 'workload))))
    (when program
      (let ((program (follow-path program)))
	(tell `[value-of (,process program) ,program])))
    
    (tell `[value-of (,process host-os) ,os])
    (tell `[value-of (,process machines) ,machine])
    (typecase process
      ((or server-process system-process) (tell `[value-of (,workload server-workload processes) ,process]))
      (otherwise (tell `[value-of (,workload user-workload processes) ,process])))
    process))

(defmacro defuser (name &key email-address machines (user-type 'user)
			     authorization-pools capabilities
			     positive-address positive-mask
			     negative-address negative-mask
			     (ensemble nil ensemble-p)
			     (typical nil typical-p)
			     superuser-for
			     )
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((user (make-object ',user-type :name ',name)))
       (tell `[value-of (,user name) ,',name])
       ,@(when email-address
          `((tell `[value-of (,user email-address) ,',email-address])))
       ,@(loop for machine in machines
               collect `(tell `[uses-machine ,user ,(follow-path '(,machine))]))
       ,@(loop for pool in authorization-pools
               collect `(tell `[value-of (,user authorization-pool) ,(follow-path '(,pool))]))
       ,@(loop for cap in capabilities
	     collect `(tell `[value-of (,user capabilities) ,(follow-path '(,cap))]))
       (apply-positive-and-negative-masks user ,positive-address ,positive-mask ,negative-address ,negative-mask)
       ,@(when ensemble-p `((tell `[value-of (,user ensemble) ,(object-named ',ensemble)])))
       ,@(when typical-p `((tell `[value-of (,user typical-p) ,,typical])))
       ,@(when superuser-for (loop for machine in superuser-for
				collect `(tell `[value-of (,user superuser-for) ,(follow-path (list ',machine 'os))])))
       user)))

(defun apply-positive-and-negative-masks (user
					  positive-mask-address positive-mask-mask
					  negative-mask-address negative-mask-mask)
    (when (and positive-mask-address positive-mask-mask)
      (with-atomic-action
        (let ((positive-mask (make-positive-location-mask positive-mask-address positive-mask-mask)))
          (tell `[value-of (,user location) ,positive-mask]))))
    (when (and negative-mask-address negative-mask-mask)
      (with-atomic-action
        (let ((negative-mask (make-negative-location-mask negative-mask-address negative-mask-mask)))
          (tell `[value-of (,user location) ,negative-mask])))))

(defmacro defresource (name resource-type &key capability-requirements machines)
  `(with-atomic-action
       (kill-redefined-object ',name)
       (let ((resource (make-object ',resource-type :name ',name)))
       ,@(loop for machine in machines
	     collect `(tell `[value-of (,resource machines) ,(follow-path '(,machine))]))
       ,@(loop for (operation capability) in capability-requirements
	     collect `(tell `[value-of (,resource capability-requirements) (,',operation ,(follow-path '(,capability)))])))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Network related stuff like protocols "firewall" rules
;;; switches, routers, subnets
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; PORTS ADDED FOR AUTO PILOT EXAMPLE
;;; WHERE THE SWITCH HAS DISTINCT PORTS
(defmacro defswitch (name switch-type ip-address-string &key authorization-pool superuser ports)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((switch (make-object ',switch-type :name ',name)))
       (add-ip-address-to-computer ,ip-address-string switch)
       ,(when superuser
          `(tell `[value-of (,switch os superuser) ,(follow-path '(,superuser))]))
       ,(when authorization-pool
          `(tell `[value-of (,switch os authorization-pool) ,(follow-path '(,authorization-pool))]))
       ,@(when ports
	  (loop for port in ports
		collect `(tell `[value-of (,switch ports) ,',port])))
       switch)))

;;; The IP-Address-Strings field is a list of every IP address that this guy is reachable
;;; at.  The code in threading-objects.lisp will then decide to put this guy on every subnet
;;; that those addresses lie on.  So if the router has address 192.168.10.1 and there's a subnet
;;; called foobar with range (192.168.10.0 255.255.255.0), then the router will automatically have foobar
;;; as one of its subnets and foobqr will have the router as one of its computers.
;;; The external networks keyword argument is a list of NAMES of external networks, e.g. The-wild

(defmacro defrouter (name ip-address-strings &key authorization-pool superuser external-networks)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((router (make-object 'router :name ',name)))
       (loop for ip-address-string in ',ip-address-strings
	   do (add-ip-address-to-computer ip-address-string router))
       ,@(when external-networks
	  (loop for external-network-name in external-networks
	      collect `(tell `[value-of (,router subnets) ,(follow-path '(, external-network-name))])))
       ,(when superuser
          `(tell `[value-of (,router os superuser) ,(follow-path '(,superuser))]))
       ,(when authorization-pool
          `(tell `[value-of (,router os authorization-pool) ,(follow-path '(,authorization-pool))]))
       router)))

(defmacro defsubnet (name segment-type range)
  (multiple-value-bind (ip-address-string subnet-mask-string) (parse-range range)
    `(with-atomic-action
      (kill-redefined-object ',name)
      (let* ((subnet (make-object ',segment-type :name ',name))
	     (mask (follow-path '(,name mask))))
	(fill-in-subnet-mask mask ,ip-address-string ,subnet-mask-string)
	subnet))))

(defmacro define-protocol (name port &optional major-purpose sub-purpose)
  `(with-atomic-action
    (tell [is-protocol ,name])
    ,@(if (atom port)
	  `((tell [port-for-protocol ,name ,port]))
	(loop for number in port
	    collect `(tell [port-for-protocol ,name ,number])))
    ,@(when (and major-purpose sub-purpose)
	`((tell [protocol-for ,major-purpose ,sub-purpose ,name]))))
  )

;;; This lets you say that this thing will except a connetion from the positive space (1st arg), except for holes in that space
;;; that are the negative locations.
(defmacro tell-positive-routing-policy (bridge connection-type (location-address location-mask)
				&rest negative-locations-and-masks)
  `(let ((location (make-positive-location-mask ,location-address ,location-mask)))
     ,@(loop for (address mask) in negative-locations-and-masks
	   collect `(push (make-location-mask 'subnet-mask ,address ,mask) (exception-masks location)))
     (tell `[policy-for-bridge ,(follow-path '(,bridge)) ,',connection-type ,location])))

(defmacro tell-positive-policy-for-host (computer connection-type (location-address location-mask)
				&rest negative-locations-and-masks)
  `(let ((location (make-positive-location-mask ,location-address ,location-mask)))
     ,@(loop for (address mask) in negative-locations-and-masks
	   collect `(push (make-location-mask 'subnet-mask ,address ,mask) (exception-masks location)))
     (tell `[policy-for-host ,(follow-path '(,computer)) ,',connection-type ,location])))

;;; This lets you say that this thing will block connetions from the negative-space (1st arg), except for holes in that space
;;; that are the positive locationsl
(defmacro tell-negative-routing-policy (bridge connection-type (location-address location-mask)
				&rest positive-locations-and-masks)
  `(let ((location (make-negative-location-mask ,location-address ,location-mask)))
     ,@(loop for (address mask) in positive-locations-and-masks
	   collect `(push (make-location-mask 'subnet-mask ,address ,mask) (exception-masks location)))
     (tell `[policy-for-bridge ,(follow-path '(,bridge)) ,',connection-type ,location])))

(defmacro tell-negative-policy-for-host (computer connection-type (location-address location-mask)
				&rest positive-locations-and-masks)
  `(let ((location (make-negative-location-mask ,location-address ,location-mask)))
     ,@(loop for (address mask) in positive-locations-and-masks
	   collect `(push (make-location-mask 'subnet-mask ,address ,mask) (exception-masks location)))
     (tell `[policy-for-host ,(follow-path '(,computer)) ,',connection-type ,location])))

(defmacro defwhitelist ((protocol  bridge-or-computer)
			&key pass exceptions for-host)
  (when (and (symbolp pass) (eql pass 'everywhere))
    (setq pass (list "0.0.0.0" "0.0.0.0")))
  (let ((processed-exceptions (loop for exception in exceptions
				  collect (multiple-value-list (parse-range exception)))))
    (if for-host
	`(tell-positive-policy-for-host ,bridge-or-computer ,protocol ,pass ,@processed-exceptions)
      `(tell-positive-routing-policy ,bridge-or-computer ,protocol ,pass ,@processed-exceptions)
      )))

(defmacro defblacklist ((protocol  bridge-or-computer)
			&key block exceptions for-host)
  (when (and (symbolp block) (eql block 'everywhere))
    (setq block (list "0.0.0.0" "0.0.0.0")))
  (let ((processed-exceptions (loop for exception in exceptions
				  collect (multiple-value-list (parse-range exception)))))
    (if for-host
	`(tell-negative-policy-for-host ,bridge-or-computer ,protocol ,block ,@processed-exceptions)
      `(tell-negative-routing-policy ,bridge-or-computer ,protocol ,block ,@processed-exceptions))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Stuff for defining a "system" of components that fill specific roles
;;;  for example a control system with roles like controller, sensor, actuator
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmacro define-system (name &key (system-type 'system) components roles)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((the-system (make-object ',system-type :name ',name)))
       ,@(loop for component in components
	     collect `(tell `[value-of (,the-system components) ,(follow-path '(,component))]))
       ,@(loop for (role-name component-name) in roles
	     collect `(tell `[system-role ,the-system ,',role-name ,(follow-path '(,component-name))]))
       )))

(defmacro define-input (process-name data-name)
  `(tell `[input-of ,(follow-path '(,process-name)) ,(follow-path '(,data-name))]))

(defmacro define-output (process-name data-name)
  `(tell `[output-of ,(follow-path '(,process-name)) ,(follow-path '(,data-name))]))

(defmacro define-impact (property-1 resource-1 property-2 resource-2)
  `(tell `[impacts ,',property-1 ,(follow-path '(,resource-1)) ,',property-2 ,(follow-path '(,resource-2))]))

;;; BUT FALSE DATA INJECTION TO SENSORS IS A GENERAL MOTIVATION
(defmacro define-proximity (who what means)
  `(tell `[is-proximate-to ,(follow-path '(,who)) ,(follow-path '(,what)) ,',means]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Server specific stuff (like for email
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmacro def-email-clients (email-server &rest clients)
  `(let ((the-server (Follow-path (list ',email-server))))
     (loop for client-name in ',clients
	 for client = (Follow-path (list client-name))
           do (tell `[email-client-of ,client ,the-server]))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; With-output-to-pdf-stream
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

#+allegro
(defmacro with-output-to-pdf-stream ((pathname stream-var) &body body)
  `(let* ((real-name (translate-logical-pathname ,pathname))
	  (ps-pathname (make-pathname-with-type real-name "eps"))
	  (pdf-pathname (make-pathname-with-type real-name "pdf"))
	  ;; the magic option preserves the bounding vox
	  (command (format nil "ps2pdf -dEPSCrop ~a ~a" ps-pathname pdf-pathname)))
     (with-open-file (file ps-pathname :direction :output :if-exists :supersede :If-does-not-exist :create)
       (clim:with-output-to-postscript-stream (,stream-var file #+mcclim :device-type #+mcclim :eps)
	 ,@body))
     (excl:run-shell-command command :wait t :show-window :normal)
     (delete-file ps-pathname)
     ))

#+mcclim
(defmacro with-output-to-pdf-stream ((pathname stream-var) &body body)
  `(let* ((real-name (translate-logical-pathname ,pathname))
	  (pdf-pathname (make-pathname-with-type real-name "pdf")))
     (clim-pdf:with-output-to-pdf-stream (,stream-var pdf-pathname
                                                          :device-type :11x17
                                                          :orientation :landscape
                                                          :trim-page-to-output-size nil
                                                          :scale-to-fit t
                                                          )
       ,@body)))
