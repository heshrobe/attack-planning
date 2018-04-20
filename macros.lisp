;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

;;; macros for describing environment
;;; makes the telling of the whole description atomic.

(in-package :aplan)


(defmacro def-symmetric-pointers (rule-name from-type from-type-variable from-slot to-type to-type-variable to-slot)
  (let ((rule-1-name (intern (string-upcase (concatenate 'string (string rule-name) "-1"))))
        (rule-2-name (intern (string-upcase (concatenate 'string (string rule-name) "-2")))))
    `(progn
       (defrule ,rule-1-name (:forward)
         if [and [object-type-of ,from-type-variable ,from-type]
                 [value-of (,from-type-variable ,from-slot) ,to-type-variable]
                 [object-type-of ,to-type-variable ,to-type]]
         then [value-of (,to-type-variable ,to-slot) ,from-type-variable])
       (defrule ,rule-2-name (:forward)
         if [and [object-type-of ,to-type-variable ,to-type]
                 [value-of (,to-type-variable ,to-slot) ,from-type-variable]
                 [object-type-of ,from-type-variable ,from-type]]
         then [value-of (,from-type-variable ,from-slot) ,to-type-variable]))))

(defmacro defsite (name address-string address-mask)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let* ((site (make-object 'site :name ',name))
            (net-mask (follow-path `(,site net-mask))))
       (fill-in-subnet-mask net-mask ,address-string ,address-mask)
       site)))

(defmacro defauthorization-pool (name)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (make-object 'authorization-pool :name ',name)
     ))


(defmacro tell-positive-policy (bridge-or-computer connection-type (location-address location-mask)
				&rest negative-locations-and-masks)
  `(let ((location (make-positive-location-mask ,location-address ,location-mask)))
     ,@(loop for (address mask) in negative-locations-and-masks
	   collect `(push (make-location-mask 'subnet-mask ,address ,mask) (exception-masks location)))
     (tell `[policy-for ,(follow-path '(,bridge-or-computer)) ,',connection-type ,location])))


(defun kill-redefined-object (name)
  (let ((object (follow-path (list name) t  nil)))
    (when object 
      (kill object))))

(defmacro defexternal-internet (name &rest excluded-subnets)
  `(with-atomic-action
       (kill-redefined-object ',name)
       (let* ((site (make-object 'external-internet :name ',name))
	      (location (make-positive-location-mask "0.0.0.0" "0.0.0.0")))
	 (tell `[value-of (,site subnets) ,location])
	 ,@(loop for (address mask) in excluded-subnets
	       collect `(push (make-location-mask 'subnet-mask ,address ,mask) (exception-masks location)))
	 site)))

(defmacro defcomputer (name computer-type ip-address-string &key superuser authorization-pool)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((computer (make-object ',computer-type :name ',name)))
       (add-ip-address-to-computer ,ip-address-string computer)
       ,(when superuser
          `(tell `[value-of (,computer os superuser) ,(follow-path '(,superuser))]))
       ,(when authorization-pool
          `(tell `[value-of (,computer os authorization-pool) ,(follow-path '(,authorization-pool))]))
       computer)))

(defmacro defswitch (name switch-type ip-address-string &key authorization-pool superuser)
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((switch (make-object ',switch-type :name ',name)))
       (add-ip-address-to-computer ,ip-address-string switch)
       ,(when superuser
          `(tell `[value-of (,switch os superuser) ,(follow-path '(,superuser))]))
       ,(when authorization-pool
          `(tell `[value-of (,switch os authorization-pool) ,(follow-path '(,authorization-pool))]))
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
			     negative-address negative-mask) 
  `(with-atomic-action
       (kill-redefined-object ',name)
     (let ((user (make-object ',user-type :name ',name)))
       (tell `[value-of (,user name) ,',name])
       ,@(when email-address
          `((tell `[value-of (,user email-address) ,',email-address])))
       ,@(loop for machine in machines
               collect `(tell `[uses-machine ,(follow-path '(,machine)) ,user]))
       ,@(loop for pool in authorization-pools
               collect `(tell `[value-of (,user authorization-pool) ,(follow-path '(,pool))]))
       ,@(loop for cap in capabilities
	     collect `(tell `[value-of (,user capabilities) ,(follow-path '(,cap))]))
       (apply-positive-and-negative-masks user ,positive-address ,positive-mask ,negative-address ,negative-mask)
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

(defmacro defresource (name resource-type &key capability-requirements machines)
  `(with-atomic-action
       (kill-redefined-object ',name)
       (let ((resource (make-object ',resource-type :name ',name)))
       ,@(loop for machine in machines
	     collect `(tell `[value-of (,resource machines) ,(follow-path '(,machine))]))
       ,@(loop for (operation capability) in capability-requirements
	     collect `(tell `[value-of (,resource capability-requirements) (,',operation ,(follow-path '(,capability)))])))))

(defmacro def-email-clients (email-server &rest clients)
  `(let ((the-server (Follow-path (list ',email-server))))
     (loop for client-name in ',clients
	 for client = (Follow-path (list client-name))
	 do (tell `[email-client-of ,client ,the-server]))))

(defmacro tell-positive-policy (bridge-or-computer connection-type (location-address location-mask)
				&rest negative-locations-and-masks)
  `(let ((location (make-positive-location-mask ,location-address ,location-mask)))
     ,@(loop for (address mask) in negative-locations-and-masks
	   collect `(push (make-location-mask 'subnet-mask ,address ,mask) (exception-masks location)))
     (tell `[policy-for ,(follow-path '(,bridge-or-computer)) ,',connection-type ,location])))

(defmacro tell-negative-policy (bridge-or-computer connection-type (location-address location-mask)
				&rest negative-locations-and-masks)
  `(let ((location (make-negative-location-mask ,location-address ,location-mask)))
     ,@(loop for (address mask) in negative-locations-and-masks
	   collect `(push (make-location-mask 'subnet-mask ,address ,mask) (exception-masks location)))
     (tell `[policy-for ,(follow-path '(,bridge-or-computer)) ,',connection-type ,location])))

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
	(tell `[value-of (,process program) ,program])))
    (tell `[value-of (,process host-os) ,os])
    (tell `[value-of (,process machines) ,machine])
    (typecase process
      ((or server-process system-process) (tell `[value-of (,workload server-workload processes) ,process]))
      (otherwise (tell `[value-of (,workload user-workload processes) ,process])))
    process))