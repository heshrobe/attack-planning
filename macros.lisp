;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

;;; macros for describing environment
;;; makes the telling of the whole description atomic.

(in-package :aplan)

;;; This defines the rules that set up a set of forward-backward pointers from one object to another
(defmacro def-symmetric-pointers (rule-name from-type from-type-variable from-slot to-type to-type-variable to-slot
				  &key from-condition to-condition)
  (let ((rule-1-name (intern (string-upcase (concatenate 'string (string rule-name) "-1"))))
        (rule-2-name (intern (string-upcase (concatenate 'string (string rule-name) "-2")))))
    (destructuring-bind (from-property from-value) from-condition
      (destructuring-bind (to-property to-value) to-condition
	`(progn
	   (defrule ,rule-1-name (:forward)
	     if [and [ltms:object-type-of ,from-type-variable ,from-type]
		     [ltms:value-of (,from-type-variable ,from-slot) ,to-type-variable]
		     [ltms:object-type-of ,to-type-variable ,to-type]
		     ,@(when from-condition `([ltms:value-of (,from-type-variable ,from-property) ,from-value]))
		     ]
	     then [ltms:value-of (,to-type-variable ,to-slot) ,from-type-variable])
	   (defrule ,rule-2-name (:forward)
	     if [and [ltms:object-type-of ,to-type-variable ,to-type]
		     [ltms:value-of (,to-type-variable ,to-slot) ,from-type-variable]
		     [ltms:object-type-of ,from-type-variable ,from-type]
		     ,@(when to-condition `([ltms:value-of (,to-type-variable ,to-property) ,to-value]))
		     ]
	     then [ltms:value-of (,from-type-variable ,from-slot) ,to-type-variable]))))))

;;; An enterprise is a organization with multiple sites within it
(defmacro define-enterprise (name &key sites)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((enterprise (make-object 'enterprise :name ',name)))
       (declare (ignorable enterprise))
       ,@(loop for site-name in sites
	     collect `(tell `[ltms:value-of (,enterprise site) ,(object-named ',site-name)])))))

;;; A site is (possibly) part of an enterprise
;;; It owns a range of net addresses, which might be broken down into subnets
(defmacro defsite (name address-string address-mask &key (enterprise nil enterprise-p))
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let* ((site (make-object 'site :name ',name))
	    (enterprise (when ,enterprise-p (object-named ',enterprise)))
            (net-mask (follow-path `(,site net-mask))))
       (declare (ignorable enterprise))
       ,@(when enterprise-p `((tell `[ltms:value-of (,site enterprise) ,enterprise])))
       (fill-in-subnet-mask net-mask ,address-string ,address-mask)
       site)))

;;; An ensemble is a collection of machines that identical from the attackers
;;; point of view.  Every ensemble has a typical instance which represents
;;; all the properties that are shared
(defmacro defensemble (name &key (enterprise nil enterprise-p)
				 (typical-computer nil computer-p)
				 (typical-user nil user-p)
				 (size 0 size-p))
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let* ((ensemble (make-object 'ensemble :name ',name)))
       ,@(when enterprise-p `((tell `[ltms:value-of (,ensemble enterprise) , (object-named ',enterprise)])))
       ,@(when computer-p `((tell `[ltms:value-of (,ensemble typical-computer) , (object-named ',typical-computer)])))
       ,@(when user-p `((tell `[ltms:value-of (,ensemble typical-user) ,(object-named ',typical-user)])))
       ,@(when size-p `((tell `[ltms:value-of (,ensemble size) ,(object-named ',size)])))
       ensemble))
    )

(defmacro defauthorization-pool (name)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (make-object 'authorization-pool :name ',name)
     ))

(defun kill-redefined-object (name)
  (let ((object (follow-path (list name) t  nil)))
    (when object 
      (kill object))))

(defmacro defexternal-internet (name &rest excluded-subnets)
  `(with-atomic-action
       (kill-redefined-object ',name)
       (let* ((site (make-object 'external-internet :name ',name))
	      (location (make-positive-location-mask "0.0.0.0" "0.0.0.0")))
	 (tell `[ltms:value-of (,site subnets) ,location])
	 ,@(loop for (address mask) in excluded-subnets
	       collect `(push (make-location-mask 'subnet-mask ,address ,mask) (exception-masks location)))
	 site)))

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
          `((tell `[ltms:value-of (,computer os superuser) ,(follow-path '(,superuser))])))
       ,@(when authorization-pool
         `((tell `[ltms:value-of (,computer os authorization-pool) ,(follow-path '(,authorization-pool))])))
       ,@(when interfaces
	   (loop for interface in interfaces
	       collect `(tell `[ltms:value-of (,computer hardware-interfaces) ,',interface])))
       ,@(when ensemble-p `((tell `[ltms:value-of (,computer ensemble) ,(object-named ',ensemble)])))
       ,@(when typical-p `((tell `[ltms:value-of (,computer typical-p) ,,typical])))
       computer)))

(defmacro define-peripheral (name &key peripheral-type interfaces commands)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((device (make-object ',peripheral-type :name ',name)))
       ,@(when interfaces
	   (loop for interface in interfaces
	       collect `(tell `[ltms:value-of (,device hardware-interfaces) ,',interface])))
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
		collect `(tell `[ltms:value-of (,bus slots) ,',slot])))
      bus)))

(defmacro define-connection (device interface bus slot)
  `(let ((device (follow-path '(,device)))
	 (bus (follow-path '(,bus))))
     (tell `[connected-to ,device ,',interface ,bus ,',slot])))

;;; PORTS ADDED FOR AUTO PILOT EXAMPLE
;;; WHERE THE SWITCH HAS DISTINCT PORTS
(defmacro defswitch (name switch-type ip-address-string &key authorization-pool superuser ports)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((switch (make-object ',switch-type :name ',name)))
       (add-ip-address-to-computer ,ip-address-string switch)
       ,(when superuser
          `(tell `[ltms:value-of (,switch os superuser) ,(follow-path '(,superuser))]))
       ,(when authorization-pool
          `(tell `[ltms:value-of (,switch os authorization-pool) ,(follow-path '(,authorization-pool))]))
       ,@(when ports
	  (loop for port in ports
		collect `(tell `[ltms:value-of (,switch ports) ,',port])))
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
	      collect `(tell `[ltms:value-of (,router subnets) ,(follow-path '(, external-network-name))])))			    
       ,(when superuser
          `(tell `[ltms:value-of (,router os superuser) ,(follow-path '(,superuser))]))
       ,(when authorization-pool
          `(tell `[ltms:value-of (,router os authorization-pool) ,(follow-path '(,authorization-pool))]))
       router)))

(defmacro defsubnet (name segment-type ip-address-string subnet-mask-string)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let* ((subnet (make-object ',segment-type :name ',name))
            (mask (follow-path '(,name mask))))
       (fill-in-subnet-mask mask ,ip-address-string ,subnet-mask-string)
       subnet)))

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
       (tell `[ltms:value-of (,user name) ,',name])
       ,@(when email-address
          `((tell `[ltms:value-of (,user email-address) ,',email-address])))
       ,@(loop for machine in machines
               collect `(tell `[uses-machine ,user ,(follow-path '(,machine))]))
       ,@(loop for pool in authorization-pools
               collect `(tell `[ltms:value-of (,user authorization-pool) ,(follow-path '(,pool))]))
       ,@(loop for cap in capabilities
	     collect `(tell `[ltms:value-of (,user capabilities) ,(follow-path '(,cap))]))
       (apply-positive-and-negative-masks user ,positive-address ,positive-mask ,negative-address ,negative-mask)
       ,@(when ensemble-p `((tell `[ltms:value-of (,user ensemble) ,(object-named ',ensemble)])))
       ,@(when typical-p `((tell `[ltms:value-of (,user typical-p) ,,typical])))
       ,@(when superuser-for (loop for machine in superuser-for
				collect `(tell `[ltms:value-of (,user superuser-for) ,(follow-path (list ',machine 'os))])))
       user))) 

(defun apply-positive-and-negative-masks (user 
					  positive-mask-address positive-mask-mask
					  negative-mask-address negative-mask-mask)
    (when (and positive-mask-address positive-mask-mask)
      (with-atomic-action
        (let ((positive-mask (make-positive-location-mask positive-mask-address positive-mask-mask)))
          (tell `[ltms:value-of (,user location) ,positive-mask]))))
    (when (and negative-mask-address negative-mask-mask)
      (with-atomic-action
        (let ((negative-mask (make-negative-location-mask negative-mask-address negative-mask-mask)))
          (tell `[ltms:value-of (,user location) ,negative-mask])))))

(defmacro defcapability (name authorization-pool &key greater lesser)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((capability (make-object 'capability :name ',name)))
       (tell `[ltms:value-of (,capability authorization-pool) ,(follow-path '(,authorization-pool))])
       ,@(loop for g in greater
               collect `(tell `[ltms:value-of (,capability more-general) ,(follow-path '(,g))]))
       ,@(loop for l in lesser
               collect `(tell `[ltms:value-of (,capability more-specific) ,(follow-path '(,l))])) 
       )))

(defmacro defresource (name resource-type &key capability-requirements machines)
  `(with-atomic-action
       (kill-redefined-object ',name)
       (let ((resource (make-object ',resource-type :name ',name)))
       ,@(loop for machine in machines
	     collect `(tell `[ltms:value-of (,resource machines) ,(follow-path '(,machine))]))
       ,@(loop for (operation capability) in capability-requirements
	     collect `(tell `[ltms:value-of (,resource capability-requirements) (,',operation ,(follow-path '(,capability)))])))))

(defmacro def-email-clients (email-server &rest clients)
  `(let ((the-server (Follow-path (list ',email-server))))
     (loop for client-name in ',clients
	 for client = (Follow-path (list client-name))
	 do (tell `[email-client-of ,client ,the-server]))))

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
  (if for-host
      `(tell-positive-policy-for-host ,bridge-or-computer ,protocol ,pass ,@exceptions)
    `(tell-positive-routing-policy ,bridge-or-computer ,protocol ,pass ,@exceptions)
  ))

(defmacro defblacklist ((protocol  bridge-or-computer)
			&key block exceptions for-host)
  (when (and (symbolp block) (eql block 'everywhere))
    (setq block (list "0.0.0.0" "0.0.0.0")))
  (if for-host
      `(tell-negative-policy-for-host ,bridge-or-computer ,protocol ,block ,@exceptions)
  `(tell-negative-routing-policy ,bridge-or-computer ,protocol ,block ,@exceptions)))

(defmacro defprocess (role-name &key process-type machine program)
  `(with-atomic-action
       (kill-redefined-object ',role-name)
     (instantiate-a-process ',process-type '(,machine) :role-name ',role-name :program ',program)))

(defun instantiate-a-process (process-type machine &key role-name program)
  (let* ((process-name (or role-name (gentemp (concatenate 'string (string-upcase (string process-type)) "-"))))
         (machine (follow-path machine))
         (os (follow-path (list machine 'os)))
         (process (make-object process-type :name process-name))
         (workload (follow-path (list os 'workload))))
    (when program
      (let ((program (follow-path program)))
	(tell `[ltms:value-of (,process program) ,program])))
    (tell `[ltms:value-of (,process host-os) ,os])
    (tell `[ltms:value-of (,process machines) ,machine])
    (typecase process
      ((or server-process system-process) (tell `[ltms:value-of (,workload server-workload processes) ,process]))
      (otherwise (tell `[ltms:value-of (,workload user-workload processes) ,process])))
    process))

(defmacro define-system (name &key (system-type 'system) components roles)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((the-system (make-object ',system-type :name ',name)))
       ,@(loop for component in components
	     collect `(tell `[ltms:value-of (,the-system components) ,(follow-path '(,component))]))
       ,@(loop for (role-name component-name) in roles
	     collect `(tell `[system-role ,the-system ,',role-name ,(follow-path '(,component-name))]))
       )))

(defmacro define-input (process-name data-name)
  `(tell `[input-of ,(follow-path '(,process-name)) ,(follow-path '(,data-name))]))

(defmacro define-output (process-name data-name)
  `(tell `[output-of ,(follow-path '(,process-name)) ,(follow-path '(,data-name))]))

(defmacro define-impact (property-1 resource-1 property-2 resource-2)
  `(tell `[impacts ,',property-1 ,(follow-path '(,resource-1)) ,',property-2 ,(follow-path '(,resource-2))]))

;;; AUTO PILOT IS THE MOTIVATION
;;; BUT FALSE DATA INJECTION TO SENSORS IS A GENERAL MOTIVATION
(defmacro define-proximity (who what means)
  `(tell `[is-proximate-to ,(follow-path '(,who)) ,(follow-path '(,what)) ,',means]))

