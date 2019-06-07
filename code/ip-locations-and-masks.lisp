;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;;  Protocol Definitions
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-protocol telnet (23 2323) remote-execution remote-shell)
(define-protocol ssh 22 remote-execution remote-shell)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Knowledge about Connectivity, Access Rights and filtering policies
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Accepts Connection
;;;
;;; This is the top-level entry
;;; It can answer both positive and negative queries
;;; At some point merging all this into a single of ask-data predicate method
;;; might make sense, but if it works as it is that's OK for now.
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrule path-allows-connection-from-normal-machine (:backward)
  then [accepts-connection ?victim-machine ?connection-type ?attacker-machine]
  if [and [ltms:object-type-of ?victim-machine computer]
	  [ltms:object-type-of ?attacker-machine computer]
	  (not (eql ?victim-machine ?attacker-machine))
	  [reachable-from ?victim-machine ?attacker-machine ?path]
	  [ltms:value-of (?attacker-machine ip-addresses) ?attacker-ip-address]
	  (host-allows-connection-type ?victim-machine ?attacker-ip-address ?connection-type)
          (path-is-acceptable-for-connection-type (copy-object-if-necessary ?path)
                                                  ?attacker-ip-address ?connection-type)
          ]
  )

;;; Note, this rule is really here only for reasoning about what the attacker can 
;;; do.  The "Location" slot is unique to attacker.  Normally, we'll make queries 
;;; about machine to machine connections as in the next rule.
(defrule path-allows-connection-from-attacker (:backward)
  then [accepts-connection ?victim-machine ?connection-type ?attacker] 
  if [and [ltms:object-type-of ?victim-machine computer]
	  [ltms:object-type-of ?attacker attacker]
	  [reachable-from ?victim-machine ?attacker ?path]
	  [ltms:value-of (?attacker location) ?location]
	  ;; Does the host block it on its own
	  (host-allows-connection-type ?victim-machine ?location ?connection-type)
	  ;; Do any of the routers on the path block it
          (path-is-acceptable-for-connection-type (copy-object-if-necessary ?path)
                                                  ?location ?connection-type)
          ])

;;; This one is here specifically for the attacker machine
;;; and just passes through to the rule above
(defrule path-allows-connection-from-attacker-machine (:backward)
  then [accepts-connection ?machine ?connection-type ?attacker-machine] 
  if [and [ltms:object-type-of ?attacker-machine attacker-computer]
	  [ltms:value-of (?attacker-machine users) ?attacker]
          [accepts-connection ?machine ?connection-type ?attacker]
	  ])

;;; We also need a set of rules for the negated case.  


;;; The first two are normal machine to normal machine
;;; Case one: The victim machine isn't even reachable
(defrule path-does-not-allow-connection-from-machine-1 (:backward)
  then [not [accepts-connection ?victim-machine ?connection-type ?attacker-machine]]
  if [and [ltms:object-type-of ?victim-machine computer]
	  [ltms:object-type-of ?attacker-machine computer]
	  [not [reachable-from ?victim-machine ?attacker-machine ?path]]]
  )

;;; Case two: It is reachable but either the host or a router on the path blocks it
(defrule path-does-not-allow-connection-from-machine-2 (:backward)
  then [not [accepts-connection ?victim-machine ?connection-type ?attacker-machine]]
  if [and [ltms:object-type-of ?victim-machine computer]
	  [ltms:object-type-of ?attacker-machine computer]
	  [reachable-from ?victim-machine ?attacker-machine ?path]
	  [ltms:value-of (?attacker-machine ip-addresses) ?attacker-ip-address]
	  (or (not (host-allows-connection-type ?victim-machine ?attacker-ip-address  ?connection-type))
	      (not (path-is-acceptable-for-connection-type (copy-object-if-necessary ?path)
							   ?attacker-ip-address ?connection-type)))
	  ]	  
  )

;;; This one is here specifically for the attacker.
;;; This is the only case where you can call this with a user as the attacker
(defrule path-does-not-allow-connection-from-attacker (:backward)
  then [not [accepts-connection ?victim-machine ?connection-type ?attacker]]
  if [and [ltms:object-type-of ?victim-machine computer]
	  [ltms:object-type-of ?attacker attacker]
	  [reachable-from ?victim-machine ?attacker ?path]
	  [ltms:value-of (?attacker location) ?location]
	  ;; Does the host block it on its own
	  (or (not (host-allows-connection-type ?victim-machine ?location ?connection-type))
	      ;; Do any of the routers on the path block it
	      (not (path-is-acceptable-for-connection-type (copy-object-if-necessary ?path)
							   ?location ?connection-type)))
          ])

;;; This one is here specifically for the attacker machine
;;; and just passes through to the rule above
(defrule path-does-not-allow-connection-from-attacker-machine (:backward)
  then [not [accepts-connection ?machine ?connection-type ?attacker-machine]]
  if [and [ltms:object-type-of ?attacker-machine attacker-computer]
	  [ltms:value-of (?attacker-machine users) ?attacker]
          [not [accepts-connection ?machine ?connection-type ?attacker]]
	  ])


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; reachable-from
;;; 
;;; This only reasons about whether there's a path but not about
;;; whether anybody would block the connection because of the connection type
;;; 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; If both things are computers just reduce to a call to connected
(defrule reachable-machine-to-machine (:backward)
  then [reachable-from ?target-computer ?source-computer ?path]
  if [and [ltms:object-type-of ?target-computer computer]
	  [ltms:object-type-of ?source-computer computer]
	  [path-between ?target-computer ?source-computer ?path]
	  ]
  )

;;; This finds a computer that the user uses
;;; And then use connected to find a path between
;;; the user computer and the target computer
(defrule bridges-on-pathway (:backward)
  then [reachable-from ?target-computer ?user ?path]
  if [and [ltms:object-type-of ?user user]
          [ltms:object-type-of ?target-computer computer]
	  [uses-machine ?user ?user-computer]
	  [ltms:object-type-of ?user-computer computer]
          [path-between ?target-computer ?user-computer ?path]
	  ]
  )

;;; We can also affirm that they aren't reachable 
(defrule machine-cant-reach-machine (:backward)
  then [not [reachable-from ?target-computer ?source-computer ?path]]
  if [and [ltms:object-type-of ?target-computer computer]
	  [ltms:object-type-of ?source-computer computer]
	  [not [path-between ?target-computer ?source-computer ?path]]
	  ])

(defrule user-cant-reach-machine (:backward)
  then [not [reachable-from ?target-computer ?user ?path]]
  if [and [ltms:object-type-of ?user user]
          [ltms:object-type-of ?target-computer computer]
	  [uses-machine ?user ?user-computer]
	  [ltms:object-type-of ?user-computer computer]
          [not [path-between ?target-computer ?user-computer ?path]]
	  ]
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 
;;; Paths between
;;;
;;; This returns a list of routers that establish a path between the 
;;; source and the destination.
;;;
;;; This predicate method depends on normal methods for find-paths-between
;;; The only caller of the methods for find-paths-between is the ask-data predicate method
;;; For that, the source-destination pair can be any of these:
;;; A computer and a router
;;; A user and a computer
;;; A computer and a computer
;;; A subnet and a subnet
;;;
;;; How this all stacks up:
;;; The top-level functionality is the predicate Accepts-Connection which takes 2 machines (or a machine and a user) and a connection-type
;;;          and binds the path by which they are connected (does anybody care)
;;;   Accepts-Connection invokes Reachable-From which takes 2 machines (or a machine and a user) and binds the path but ignores the connection-type
;;;     Reachable-From invokes Connected it takes 2 machines (or a machine and a user) and binds the path
;;; Connected calls find-paths-between
;;; 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate-method (ask-data path-between) (truth-value continuation)
  (with-statement-destructured (thing1 thing2 path) self
    (let ((connections (find-paths-between thing1 thing2)))
      (cond
       ((and (eql truth-value +true+) (not (null connections)))
	(loop for connection in connections
				;; why is this check here?
	    unless (or (member thing1 connection)
		       (member thing2 connection))		 
            do (with-unification
		   (unify connection path)
                 (stack-let ((backward-support (list self +true+ '(ask-data connected))))
			    (funcall continuation backward-support)))))
       ((and (eql truth-value +false+) (null connections))
	(with-unification
	    (unify path nil)
	  (stack-let ((backward-support (list self +false+ `(ask-data connected))))
		     (funcall continuation backward-support))))
       ))))


(defmethod find-paths-between (thing1 thing2)
  (declare (ignore thing1 thing2))
  nil)

(defmethod find-paths-between ((thing1 computer) (thing2 router))
  (cond
   ((eql thing1 thing2) (list nil))
   (t (let ((answers nil))
        (labels ((do-one-hop (next-subnet path-so-far source)
                   (cond ((member thing2 (routers next-subnet))
                          (when (typep thing2 'switched-subnet)
                            (push (switch thing2) path-so-far))
                          (pushnew (reverse path-so-far) answers :test #'equal))
                         (t (loop for router in (routers next-subnet)
                                  unless (equal router source)
                                  do (loop for subnet in (subnets router)
                                           for my-path = path-so-far
                                           when (typep subnet 'switched-subnet)
                                           do (push (switch subnet) my-path)
                                           do (do-one-hop subnet (cons router my-path) router)))))))
          (loop for subnet in (subnets thing1)
                for starting-path = (if (typep subnet 'switched-subnet) (list (switch subnet)) nil)
                do (do-one-hop subnet starting-path thing1)))
        answers))))

(defmethod find-paths-between ((thing1 user) (thing2 computer))
  (loop for machine in (machines thing1)
      append (find-paths-between machine thing2)))

(defmethod find-paths-between ((thing1 computer) (thing2 computer))
  (cond 
   ((eql thing1 thing2) (list nil))
   (t (let ((answers nil))
        (loop for subnet1 in (subnets thing1)
              do (loop for subnet2 in (subnets thing2)
                       for paths = (find-paths-between subnet1 subnet2)
                       do (loop for path in paths
                                do (pushnew path answers :test #'equal))))
        answers))))

;;; fix to include the switch on the path
(defmethod find-paths-between ((thing1 subnet-mixin) (thing2 subnet-mixin))
  (cond 
   ((eql thing1 thing2) (list nil))
   (t (let ((answers nil))
        (labels ((do-one-hop (next-router path-so-far source-subnet)
                   (cond ((member thing2 (subnets next-router))
                          (push next-router path-so-far)
                          (when (typep thing2 'switched-subnet)
                            (push (switch thing2) path-so-far))
                          (pushnew (reverse path-so-far) answers :test #'equal))
                         (t (loop for subnet in (subnets next-router)
                                  for my-path = path-so-far
                                  unless (equal subnet source-subnet)
                                  when (typep subnet 'switched-subnet)
                                  do (push (switch subnet) my-path)
                                  do (loop for router in (routers subnet)
                                           unless (member router path-so-far)
                                           do (do-one-hop router (cons next-router my-path) subnet)))))))
           (loop for router in (routers thing1)
                for starting-path = (if (typep thing1 'switched-subnet) (list (switch thing1)) nil)
                do (do-one-hop router starting-path thing1)))
        answers))))


;;; Test Code
(defun find-connected (subnet1 subnet2)
  (let ((sub1 (follow-path `(,subnet1)))
        (sub2 (follow-path `(,subnet2))))
    (ask `[connected ,sub1 ,sub2 ?path] 
         #'(lambda (ignore)
             (declare (ignore ignore))
             (format t "~&Subnet ~a is connect to subnet ~a by ~a"
                     sub1 sub2 ?path)))))



;;; Test Code
(defun find-reachables (computer1 computer2)
  (ask `[reachable-from ,computer1 ,computer2 ?path]
       #'(lambda (ignore)
           (declare (ignore ignore))
           (format t "~%computer ~a is connected to computer ~a by path ~a"
                   computer1 computer2 ?path))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Dealing with IP addresses and ranges of IP addresses and seeing if they intersect
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
 

(defun parse-ip-address (ip-address-string)
  (loop for last-position = 0 then (1+ position)
        for position = (position #\. ip-address-string :start last-position)
        collect (read-from-string ip-address-string nil nil :start last-position :end position)
        until (null position))) 

(defun create-ip-address (ip-address-string)
  (let* ((octets (parse-ip-address ip-address-string))
         (name (intern (apply #'format nil "IP-~d.~d.~d.~d" octets)))
         (ip-address (or (follow-path (list name) t nil) (make-object 'ip-address :name name))))
    (loop for octet in '(octet1 octet2 octet3 octet4)
          for value in octets
          do (tell `[ltms:value-of (,ip-address ,octet) ,value]))
    ip-address))

(defun add-ip-address-to-computer (ip-address-string computer)
  (let* ((ip-address (create-ip-address ip-address-string)))
    (tell `[ltms:value-of (,computer ip-addresses) ,ip-address])))

(defun fill-in-subnet-mask (subnet-mask ip-address-string subnet-mask-string)
  (let ((address-octets (parse-ip-address ip-address-string))
        (mask-octets (parse-ip-address  subnet-mask-string)))
    (loop for octet-name in '(octet1 octet2 octet3 octet4)
          for address-octet in address-octets
          for mask-octet in mask-octets
          do (tell `[ltms:value-of (,subnet-mask ip-address ,octet-name) ,address-octet])
             (tell `[ltms:value-of (,subnet-mask mask ,octet-name) ,mask-octet]))))

(defun ip-address-is-on-subnet (ip-address subnet)
  (let* ((subnet-mask (ip-address-integer (follow-path `(,subnet mask mask))))
         (subnet-ip-address (ip-address-integer (follow-path `(,subnet mask ip-address))))
         (real-ip-address (ip-address-integer ip-address)))
    (let ((masked-address (logand real-ip-address subnet-mask)))
      ;; (break "~b ~%~b ~%~b ~%~b" subnet-mask subnet-ip-address real-ip-address masked-address)
      (equal masked-address subnet-ip-address))))

(defmethod subnet-is-at-site ((subnet external-internet) (site site)) nil)

(defmethod subnet-is-at-site ((subnet subnet) (site site))
  (let ((sub-ip-address (ip-address-integer (follow-path `(,subnet mask ip-address))))
        (sub-mask (ip-address-integer (follow-path `(,subnet mask mask))))
        (site-ip-address (ip-address-integer (follow-path `(,site net-mask ip-address))))
        (site-mask (ip-address-integer (follow-path `(,site net-mask mask)))))
    (and (= (logand site-mask sub-mask) site-mask)
         (= (logand site-mask sub-ip-address) site-ip-address)))) 




(defun make-positive-location-mask (address-string mask-string)
  (make-location-mask 'positive-location address-string mask-string))

(defun make-negative-location-mask (address-string mask-string)
  (make-location-mask 'negative-location address-string mask-string))

(defun make-location-mask (mask-type address-string mask-string)
  (with-atomic-action
    (let ((the-mask (make-object mask-type :name (gentemp (string-upcase "mask")) :superpart-object nil)))
      (fill-in-subnet-mask the-mask address-string mask-string)
      the-mask)))

;;; Fix: Check who uses any of this (vs the interval based stuff later on)
;;; And see if they are obeying the semantics of Policies specifying a region with holes
;;; These are the currently listed callers of this generic function
;;; other methods of this 
;;;(METHOD LOCATION-IS-IN-NET-SEGMENT (SITE T)), :OPERATOR
;;;(METHOD LOCATION-IS-IN-NET-SEGMENT (SUBNET-MASK SUBNET)), :OPERATOR
;;;USER-CAN-USE-COMPUTER-RULE-PROCEDURAL-TRIGGER-3647, :OPERATOR  This rule is commented out
;;;USER-CAN-USE-COMPUTER-RULE-PROCEDURAL-TRIGGER-1358, :OPERATOR  ditto
;;; I think the only method that calls this is wrong
;;;(FLET (METHOD ACCEPTABLE-LOCATION-FOR-CONNECTION (COMPUTER IP-ADDRESS T)) JOSHUA-INTERNALS::CONTINUATION), :OPERATOR
;;;(FLET (METHOD ACCEPTABLE-LOCATION-FOR-CONNECTION (COMPUTER T T)) JOSHUA-INTERNALS::CONTINUATION), :OPERATORi
;;; Dead code, nobody calls acceptable location for policy
;;;(METHOD ACCEPTABLE-LOCATION-FOR-POLICY (SITE SUBNET-MASK (EQL 'LOCAL-ONLY))), :OPERATOR

;;;(FLET (:INTERNAL (FLET (:INTERNAL (FLET BRIDGES-ON-PATHWAY-2 SUCCEED) 0) SUCCEED) 0) SUCCEED), :OPERATOR
;;; Apparently, it's dead code
;;;(defmethod location-is-in-net-segment ((segment subnet-mask) (location external-internet))
;;;  (let ((segment-intervals (intervals segment))
;;;	(location-subnets (subnets location)))
;;;    (loop for segment-interval in segment-intervals
;;;	do (loop for subnet in location-subnets
;;;	       do (loop for subnet-interval in (intervals subnet)
;;;		      for intersection = (interval-intersection segment-interval subnet-interval)
;;;		      when intersection
;;;		      do (return-from location-is-in-net-segment t))))
;;;    nil))
;;;
;;;
;;;(defmethod location-is-in-net-segment ((segment subnet-mask) (location subnet))
;;;  (let ((subnet-mask (subpart-named location 'mask)))
;;;    (location-is-in-net-segment segment subnet-mask)))
;;;
;;;
;;;;; a subnet mask can be used as a positive location
;;;(defmethod location-is-in-net-segment ((segment subnet-mask) (location subnet-mask))
;;;  (let ((segment-mask (ip-address-integer (follow-path `(,segment mask))))
;;;        (segment-ip-address (ip-address-integer (follow-path `(,segment ip-address))))
;;;        (location-mask (ip-address-integer (follow-path `(,location mask))))
;;;        (location-ip-address (ip-address-integer (follow-path `(,location ip-address)))))
;;;    (and 
;;;    ;; location mask must be more specific extension
;;;     (eql (logand segment-mask location-mask) segment-mask)
;;;     ;; location address is on segment
;;;     (equal (logand location-ip-address segment-mask) segment-ip-address))))
;;;
;;;
;;;(defmethod location-is-in-net-segment ((segment subnet-mask) (location positive-location))
;;;  (let ((segment-mask (ip-address-integer (follow-path `(,segment mask))))
;;;        (segment-ip-address (ip-address-integer (follow-path `(,segment ip-address))))
;;;        (location-mask (ip-address-integer (follow-path `(,location mask))))
;;;        (location-ip-address (ip-address-integer (follow-path `(,location ip-address)))))
;;;    (and 
;;;    ;; location mask must be more specific extension
;;;     (eql (logand segment-mask location-mask) segment-mask)
;;;     ;; location address is on segment
;;;     (equal (logand location-ip-address segment-mask) segment-ip-address))))
;;;
;;;
;;;(defmethod location-is-in-net-segment ((segment subnet-mask) (location negative-location))
;;;  (let ((segment-mask (ip-address-integer (follow-path `(,segment mask))))
;;;        (segment-ip-address (ip-address-integer (follow-path `(,segment ip-address))))
;;;        (location-mask (ip-address-integer (follow-path `(,location mask))))
;;;        (location-ip-address (ip-address-integer (follow-path `(,location ip-address)))))
;;;    (not
;;;     (and 
;;;      ;; segment mask must be more specific extension
;;;      (eql (logand segment-mask location-mask) location-mask)
;;;      ;; segment address is in the location span
;;;      (equal (logand segment-ip-address location-mask) location-ip-address)))))
;;;
;;;
;;;(defmethod location-is-in-net-segment ((segment subnet-mask) (location ip-address))
;;;  (let ((segment-mask (ip-address-integer (follow-path `(,segment mask))))
;;;        (segment-ip-address (ip-address-integer (follow-path `(,segment ip-address))))
;;;        (location-ip-address (ip-address-integer location)))
;;;     ;; location address is on segment
;;;     (equal (logand location-ip-address segment-mask) segment-ip-address)))
;;;
;;;
;;;(defmethod location-is-in-net-segment ((site site) location)
;;;  (let ((site-mask (follow-path `(,site net-mask))))
;;;    (location-is-in-net-segment site-mask location)))


;;; Apparently nobobody calls this
;;;(defmethod acceptable-location-for-policy ((site site) (location subnet-mask) (policy (eql 'local-only)))
;;;  (location-is-in-net-segment site location))
;;;
;;;(defmethod acceptable-location-for-policy ((site site) location (policy (eql 'global)))
;;;  (declare (ignore location))
;;;  t) 


(defmethod path-is-acceptable-for-connection-type (path location connection-type)
  (loop for bridge in path
        always (acceptable-location-for-connection bridge location connection-type)))

;;; What we really should be checking:
;;; A bridge (router, switch, or even computer) specifies a policy
;;; by providing a set of positive and negative masks.
;;; To be acceptable, the location must not be in any negative location
;;;                   and must be in at least one positive location (if there are any)
;;; Here a location is specified as one of:
;;;   1) A specific IP address
;;;   2) A positive range of IP addresses
;;;   3) A negative range of IP addesses
;;; So for each of these we need to check the following:
;;; 1) Specific IP address -- It's actually within at least one positive region and no negative regions
;;; 2) Positive Range of IP addresses -- It's not completely included in any negative region
;;;                                      It intersects at least one positive region 
;;; 3) Negative Range of IP addresses  -- For each positive region the range doesn't include that region
;;;                                       For each negative regsion the range includes that region
;;; Note that cases 2 & 3 aren't really accurate for complicated cases.  For example, the policy might have
;;; a set of excluded regions whose union encompasses the positive range of addresses explicitly provided in 
;;; 2 or implied by 3.  Or you might have partial intersections between two positive ranges.  All this arises because
;;; we don't know where the attacker is only some range (usually everything except the site being attacked) but I don't want to get
;;; into major league computational geometry about IP interval ranges.  Or maybe the right thing is to actually convert into
;;; an interval representation and then proceed from that.

;;; Fix: doesn't this need to do the same things that the method after it does
;;; at least to consider whether it's a positive or negative mask?

;;;(defmethod acceptable-location-for-connection ((bridge computer) location connection-type)
;;;  (ask `[policy-for ,bridge ,connection-type ?bridge-mask]
;;;       #'(lambda (just)
;;;           (declare (ignore just))
;;;           (when (location-is-in-net-segment ?bridge-mask location)
;;;             (return-from acceptable-location-for-connection 
;;;               (values t)))))
;;;  nil)


;;; 1) If the IP address is in a prohibited region that takes precedence
;;; A prohibited region is an interval of a negative mask
;;; 2) If it's not explicitly prohibited, then it has to be positively permitter
;;; meaning it's in some interval of a positive mask
;;; 3) If neither of these occurs we default to prohibited

(defparameter *policy-default* 'permit)

(defmethod acceptable-location-for-connection ((bridge computer) (ip-address ip-address) connection-type)
  (ask* `[policy-for-bridge ,bridge ,connection-type ?bridge-mask]
	(cond
	 ((and (eql *policy-default* 'permit) (typep ?bridge-mask 'negative-location))
	  (loop for interval in (intervals ?bridge-mask) 
	      when (ip-is-in-interval ip-address interval)
	      do (return-from acceptable-location-for-connection nil)))
	 ((and (eql *policy-default* 'reject) (typep ?bridge-mask 'positive-location))
	  (loop for interval in (intervals ?bridge-mask)
	      when (ip-is-in-interval ip-address interval)
	      do (return-from acceptable-location-for-connection t)))))
  (if (eql *policy-default* 'permit) t nil))

(defmethod host-allows-connection-type ((host computer) (ip-address ip-address) connection-type)
  (ask* `[policy-for-host ,host ,connection-type ?host-mask]
	(cond
	 ((and (eql *policy-default* 'permit) (typep ?host-mask 'negative-location))
	  (loop for interval in (intervals ?host-mask) 
	      when (ip-is-in-interval ip-address interval)
	      do (return-from host-allows-connection-type nil)))
	 ((and (eql *policy-default* 'reject) (typep ?host-mask 'positive-location))
	  (loop for interval in (intervals ?host-mask)
	      when (ip-is-in-interval ip-address interval)
	      do (return-from host-allows-connection-type t)))))
  (if (eql *policy-default* 'permit) t nil)
  )

(defmethod intervals ((location external-internet))
  (sort (loop for subnet in (subnets location) append (intervals subnet))
				   #'< :key #'first))

(defun make-everywhere () (make-positive-location-mask "0.0.0.0" "0.0.0.0"))

(defparameter *everywhere* (make-everywhere))

;;; This is necessary so that when a model is loaded (which is usually preceded by a (clear)
;;; *everywhere* is up to date.  The clear operation deletes it's sub-parts

(define-predicate-method (after-clear default-predicate-model :after) (&optional clear-database undefrules)
  (when (and clear-database (not undefrules))
    (setq *everywhere* (make-everywhere))))

;;; Fix: Does this need to do with default-policy, or does it already.  I think it does
;;; via pushing everywhere into the list of permitted
(defmethod acceptable-location-for-connection ((bridge computer) (location external-internet) connection-type)
  (let* ((positive-masks nil)
	 (negative-masks nil)
	 (location-intervals (intervals location)))
    (ask* `[policy-for-bridge ,bridge ,connection-type ?bridge-mask]
	  (if (typep ?bridge-mask 'negative-location)
	      (push ?bridge-mask negative-masks)
	    (push ?bridge-mask positive-masks)))
    ;; If we're in permissive policy then add a mask that allows everything
    (when (eql *policy-default* 'permit) (push *everywhere* positive-masks))
    ;; initially we start with all the intervals covered by the external internet
    (let ((permitted-areas location-intervals))
      ;; now for each negative mask and each of the masks intervals
      ;; we subtract out from each permitted interval the spaces
      ;; covered by the negative mask's intervals
      ;; making the resulting intervals the new permitted areas
      (loop for negative-mask in negative-masks
	  append (loop for interval in (intervals negative-mask)
		     do (setq permitted-areas  (loop for permitted-area in permitted-areas
						   append (interval-subtract permitted-area interval)))))
      ;; now we check whether any of the remaining intervals
      ;; intersect with any positive mask's intervals
      (when permitted-areas
	(loop for permitted-area in permitted-areas
	    do
	       (loop for positive-mask in positive-masks
		   do 
		      (loop for interval in (intervals positive-mask)
			  when (interval-intersection permitted-area interval)
			  do (return-from acceptable-location-for-connection t))))))
    nil))

(defmethod host-allows-connection-type ((host computer) (location external-internet) connection-type)
  (let* ((positive-masks nil)
	 (negative-masks nil)
	 (location-intervals (intervals location)))
    (ask* `[policy-for-host ,host ,connection-type ?host-mask]
	  (if (typep ?host-mask 'negative-location)
	      (push ?host-mask negative-masks)
	    (push ?host-mask positive-masks)))
    ;; If we're in permissive policy then add a mask that allows everything
    (when (eql *policy-default* 'permit) (push *everywhere* positive-masks))
    ;; initially we start with all the intervals covered by the external internet
    ;; (break "Positive Masks: ~a Negative Masks: ~a" positive-masks negative-masks)
    (let ((permitted-areas location-intervals))
      ;; now for each negative mask and each of the masks intervals
      ;; we subtract out from each permitted interval the spaces
      ;; covered by the negative mask's intervals
      ;; making the resulting intervals the new permitted areas
      (loop for negative-mask in negative-masks
	  append (loop for interval in (intervals negative-mask)
		     do (setq permitted-areas  (loop for permitted-area in permitted-areas
						   append (interval-subtract permitted-area interval)))))
      ;; now we check whether any of the remaining intervals
      ;; intersect with any positive mask's intervals
      (when permitted-areas
	;; (break "permitted areas: ~a" permitted-areas)
	(loop for permitted-area in permitted-areas
	    do 
	       (loop for positive-mask in positive-masks
		   do 
		      (loop for interval in (intervals positive-mask)
			  when (interval-intersection permitted-area interval)
			  do (return-from host-allows-connection-type t))))))
    nil))


(defvar *all-on-ip-address* (ip-address-integer (create-ip-address "255.255.255.255")))

(defmethod ip-address-is-within-location ((address ip-address) (location external-internet))
  (loop for interval in (intervals location)
      thereis (ip-is-in-interval address interval)))

(defmethod ip-is-in-interval ((ip ip-address) interval)
  (let ((address (ip-address-integer ip)))
    (destructuring-bind (low high) interval
      (and (<= low address high)))))

(defun interval-from-address-and-mask (address mask)
  (let* ((low (logand mask address))
	 (upmask (logxor *all-on-ip-address* mask)) 
	 (high (logior low upmask)))
    (list low high)))

(defun interval-intersection (interval1 interval2)
  (destructuring-bind (low1 high1) interval1
    (destructuring-bind (low2 high2) interval2
      (let ((low (max low1 low2))
	    (high (min high1 high2)))
	(when (< low high)
	  (list low high))))))

(defun interval-merge (interval1 interval2)
  (destructuring-bind (low1 high1) interval1
    (destructuring-bind (low2 high2) interval2
	(when (>= high1 low2)
	  (list low1 high2)))))

;;; The answer here is a list of (at most 2) intervals
(defun interval-subtract (interval1 interval2)
  (destructuring-bind (low1 high1) interval1
    (destructuring-bind (low2 high2) interval2
      (let ((answer nil))
	(when (or (<= high2 low1) (<= high1 low2))
	  (push interval1 answer))
	(when (and (< low2 high1) (> low2 low1))
	  (push (list low1 low2) answer))
	(when (and (> high2 low1) (< high2 high1))
	  (push (list high2 high1) answer))
	(nreverse answer)))))
	  
(defun subtract-holes-from-interval (interval holes)
  (loop with survivors = (list interval)
      for hole in holes
      do (loop for survivor in survivors
	     for new-survivors = (interval-subtract survivor hole)
	     append new-survivors into next-step
	     finally (setq survivors next-step))
      finally (return survivors)))
      
(defmethod compute-intervals ((location subnet-mask))
  (let* ((ip-address (ip-address-integer (follow-path `(,location ip-address))))
	 (mask (ip-address-integer (follow-path `(,location mask))))
	 (base-interval (interval-from-address-and-mask ip-address mask))
	 (holes (loop for exception in (exception-masks location)
		    for his-ip = (ip-address-integer (follow-path `(,exception ip-address)))
		    for his-mask = (ip-address-integer (follow-path `(,exception mask)))
		    collect (interval-from-address-and-mask his-ip his-mask))))
    (setf (intervals location) (subtract-holes-from-interval base-interval holes)
	  (intervals-computed? location) t)))



;;; this handles the case for a user whose "location" in ip-space
;;; is known (by a mask) but for which we don't know a specific machine.
;;; At the moment, the only such user is the attacker.
;;; Stragey: Find a router that has an IP address that is in the range
;;; of the user's location.  Then find a path (using connected) between
;;; that router and the target-computer. But the attacker does have a machine
;;; and given that bridges-on-pathway is all we need

;;;(defrule bridges-on-pathway-2 (:backward)
;;;  then [reachable-from ?computer ?user (?router . ?path)]
;;;  if [and [ltms:object-type-of ?user attacker]
;;;	  [ltms:value-of (?user location) ?location]
;;;	  [ltms:object-type-of ?router router]
;;;	  [ltms:value-of (?router ip-addresses) ?ip-address]
;;;	  (ip-address-is-within-location ?ip-address ?location)
;;;	  (break)
;;;          [connected ?computer ?router ?path]]
;;;  )


;;;(defrule bridges-on-pathway-2 (:backward)
;;;  then [reachable-from ?computer ?user (?router . ?path)]
;;;  if [and [ltms:object-type-of ?user attacker]
;;;	  ;; is the computer at some site in common with the router
;;;	  [ltms:object-type-of ?router router]
;;;          [ltms:value-of (?router site) ?site]
;;;	  [ltms:object-type-of ?site site]
;;;          [ltms:object-type-of ?computer computer]
;;;          [ltms:value-of (?computer site) ?site]
;;;	  ;; so now we know that the computer can talk
;;;	  ;; to the router.  Next, can the user talk to
;;;	  ;; the router.
;;;	  ;; Note: The only user's with a location are the attacker
;;;	  ;; (at the moment)
;;;          [ltms:value-of (?user location) ?location]
;;;	  [ltms:value-of (?router ip-addresses) ?ip-address)
;;;	  [ltms:object-type-of ?ip-address ip-address]
;;;          (not (location-is-in-net-segment ?site ?location))
;;;          ;; should really check for being the router to the outside
;;;          [connected ?computer ?router ?path]])
