;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*-

(in-package :aplan)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; JSON Dumping
;;;
;;; Every element of a merged attack plan has a slot called json-id
;;; So dumping to JSON format involves two steps
;;; 1) Open a Json Object.  This will have four key-value pairs: Users, Computers, Nodes and Edges
;;; 2) For the value of Nodes, open a JSON array. Map over the attack graph for each node, open
;;;    a JSON object.  Dump the pair consisting of unique-id and the json-id
;;;    Then dump whatever other key-value pairs are relevant to the node.
;;;    For goal nodes this involves doing pretty much what the print method does
;;;    but in JSON format
;;; 3) For the value of Edges, Open a Json array.  Map over the attack graph,
;;;    for any node that points to something else for each pointer open an object
;;;    with key the json-id of the node and value the json id of the destination
;;;
;;; 4) Similarly for Users and computers

;;; This provides a model of how the macros are used
; (json:with-array ()
;   (json:as-array-member ()
;     (json:with-object ()
;       (do-external-symbols (sym (find-package "FOO"))
;         (json:as-object-member (sym)
;           (json:with-object ()
;             (if (boundp sym)
;                 (let ((value (symbol-value sym)))
;                   (json:encode-object-member 'val value)))
;             (if (fboundp sym)
;                 (json:encode-object-member 'fun t))))))))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; What this does:
;;; 1) Unique-izes goals
;;; 2) Unique-izes actions
;;; 3) unique-izes plans


(defun dump-plan (root-node &optional (stream *standard-output*))
  (multiple-value-bind (computers users) (collect-computers-and-users root-node)
    (json:with-object (stream) 
      (format stream "~2%")
      (json:as-object-member ('computers stream) (dump-computers computers stream))
      (format stream "~2%")
      (json:as-object-member ('users stream) (dump-users users stream))
      (format stream "~2%")
      (json:as-object-member ('nodes stream) (dump-nodes root-node stream))
      (format stream "~2%")
      (json:as-object-member ('links stream) (dump-links root-node stream)))
    ))

(defun dump-plan-to-file (root-node pathname)
  (with-open-file (f pathname :direction :output :if-exists :supersede :if-does-not-exist :create)
    (dump-plan (first root-node) f)))

(defgeneric subordinates (graph-node))

(defun traverse-merged-attack-graph (root-node action-fun)
  (let ((visited (make-hash-table)))
    (labels ((do-a-node (node)
	       (unless (gethash node visited)
		 (setf (gethash node visited) t)
		 (funcall action-fun node)
		 (loop for subordinate in (subordinates node)
		     do (do-a-node subordinate)))))
      (do-a-node root-node))))

(defmethod subordinates ((node attack-goal)) (supporting-plans node))
(defmethod subordinates ((node attack-action)) nil)
(defmethod subordinates ((node attack-plan)) (steps node))
(defmethod subordinates ((node plan-or-node)) (supporting-plans node))

(defun collect-computers-and-users (root-node)
  (let ((computers nil)
	(users nil))
    (flet ((collector (node)
	     (typecase node
	       (attack-goal
		(let ((form (goal-name node)))
		  (loop for thing in form
		      do (typecase thing
			   (computer (pushnew thing computers))
			   (user (pushnew thing users))))))
	       (attack-action
		(let ((form (action-name node)))
		  (loop for thing in form
			do (typecase thing
			     (computer (pushnew thing computers))
			     (user (pushnew thing users))))))
	       )))
      (traverse-merged-attack-graph root-node #'collector)
      (values computers users)
      )))

;;; so we a generic function for dumping a node's contents
;;; and then one for dumping its pointers

(defgeneric dump-node (node &optional stream))

(defun dump-nodes (root-node &optional (stream *standard-output*))
  (flet ((do-a-node (node) 
	   (terpri stream)
	   (json:as-array-member (stream) (dump-node node stream))))
    (json:with-array (stream)
      (traverse-merged-attack-graph root-node #'do-a-node)
      )))

(defmethod dump-node ((node attack-goal) &optional (stream *standard-output*))
  (destructuring-bind (goal-type &rest values) (goal-name node)
    (let* ((predicate-args (ji::find-predicate-arglist goal-type))
	   (unique-id (json-id node)))
      (terpri stream)
      (json:with-object (stream)
	(json:encode-object-member 'id unique-id stream)
	(terpri stream)
	(json:encode-object-member 'type 'goal stream)
	(terpri stream)
	(json:encode-object-member 'goal goal-type stream)
	(loop for key in predicate-args
	    for value in values
	    for value-token = (cond ((or (symbolp value) (numberp value)) value) ((typep value 'state) value) (t (role-name value)))
	    if (eql key 'resource-or-component) do (setq key 'resource)
	    unless (typep value-token 'state)
	    do (terpri stream)
	       (json:encode-object-member key value-token stream))))))

(defmethod dump-node ((node attack-action) &optional (stream *standard-output*))
  (destructuring-bind (action-type &rest values) (action-name node)
    (let ((predicate-args (ji::find-predicate-arglist action-type))
	  (unique-id (json-id node)))
      (unless (eql action-type 'goal-already-satisfied)
        (terpri stream)
        (json:with-object (stream)
          (json:encode-object-member 'id unique-id stream)
          (terpri stream)
          (json:encode-object-member 'type (typecase node (repeated-attack-action 'repeated-action) (otherwise 'action)) stream)
          (terpri stream)
          (json:encode-object-member 'action action-type stream)
          (loop for key in predicate-args
              for value in values
              for value-token = (cond ((or (symbolp value) (numberp value)) value) ((typep value 'state) value) (t (role-name value)))
              when (eql key 'resource-or-component) do (setq key 'resource)
              unless (typep value-token 'state)
              do 	(terpri stream)
                        (json:encode-object-member key value-token stream)))))))

(defmethod dump-node ((node attack-plan) &optional (stream *standard-output*))
  (with-slots (combinator attack-identifier (unique-id json-id)) node
    (terpri stream)
    (json:with-object (stream)
      (json:encode-object-member 'id unique-id stream)
      	(terpri stream)
	(json:encode-object-member 'type 'plan stream)
	(terpri stream)
	(json:encode-object-member 'combinator combinator stream)
        (when attack-identifier
          (break "~a ~a" unique-id attack-identifier)
          (terpri stream)
          (json:encode-object-member 'attack-identifier attack-identifier stream))
  )))

(defmethod dump-node ((node plan-or-node) &optional (stream *standard-output*))
  (with-slots ((unique-id json-id)) node
    (terpri stream)
    (json:with-object (stream)
      (json:encode-object-member 'id unique-id stream)
      (terpri stream)
      (json:encode-object-member 'type 'or stream)
      )))


(defun dump-links (root-node &optional (stream *standard-output*))
  (flet ((do-a-node (node) 
	   (unless (typep node 'attack-action)
	     (terpri stream)
	     (json:as-array-member (stream) (dump-link-set node stream)))))
    (json:with-array (stream)
      (traverse-merged-attack-graph root-node #'do-a-node)
      )))

(defmethod dump-link-set ((node attack-goal) &optional (stream *standard-output*))
  (with-slots ((unique-id json-id) supporting-plans) node
    (terpri stream)
    (json:with-object (stream)
      (json:encode-object-member 'id unique-id stream)
      (json:as-object-member ('destinations stream)
        (json:with-array (stream)
	  (loop for destination in supporting-plans
	      do (json:encode-array-member (json-id destination) stream)))
	))))

(defmethod dump-link-set ((node attack-plan) &optional (stream *standard-output*))
  (with-slots ((unique-id json-id) steps) node
    (terpri stream)
    (json:with-object (stream)
      (json:encode-object-member 'id unique-id stream)
      (json:as-object-member ('destinations stream)
         (json:with-array (stream)
	   (loop for destination in steps
	       do (json:encode-array-member (json-id destination) stream)))
	 ))))

(defmethod dump-link-set ((node plan-or-node) &optional (stream *standard-output*))
  (with-slots ((unique-id json-id) supporting-plans) node
    (terpri stream)
    (json:with-object (stream)
      (json:encode-object-member 'id unique-id stream)
      (json:as-object-member ('destinations stream)
         (json:with-array (stream)
	   (loop for destination in supporting-plans
	       do (json:encode-array-member (json-id destination) stream)))
	 ))))


(defmethod dump-link-set ((node attack-action) &optional (stream *standard-output*))
  ;; (declare (ignore stream))
  ;; actions are terminal nodes, so nothing to do
  (terpri stream)
  (json:with-object (stream)
    (json:encode-object-member 'id 'test-1 stream))
  (values)
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Dumping Computers
;;;
;;; For each computer we dump its name as used in the plan
;;; For each computer we dump whether it's a typical instance (standin true) of some ensemble
;;; and also whether it's an attacker computer (attacker true)
;;; If it's an attacker computer then we assume it's in the outside internet
;;;   and we dump the range of that outside (typicall 0.0.0.0 255.255.255.255)
;;;   together with a set of holes in that area
;;; If it's a typical computer then we dump the size of the ensemble
;;;    and the range and mask for the ensemble's IP addresses
;;;
;;; Things to add what hardware/os/application suite...
;;;  
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun dump-computers (computers stream)
  (json:with-array (stream)
    (loop for computer in computers
	do (terpri stream)
	   (json:as-array-member (stream) (dump-computer computer stream)))))

(defmethod dump-computer ((computer computer) &optional (stream *standard-output*))
  (terpri stream)
  (json:with-object (stream)
    (json:encode-object-member 'name (role-name computer) stream)
    (terpri stream)
    (json:encode-object-member 'standin (if (typical-p computer) 'true 'false) stream)
    (terpri stream)
    (json:encode-object-member 'attacker (typecase computer (attacker-computer 'true) (otherwise 'false)) stream)
    (terpri stream)
    (dump-subnet-data computer stream)
    (terpri stream)))  

(defmethod dump-subnet-data ((computer attacker-computer) &optional (stream *standard-output*))
  (let* ((subnet (first (subnets computer))))
    ;; Subnet is the external-internet
    ;; and its subnets is the included region)
    (when (typep subnet 'external-internet)
      (json:as-object-member ('range stream)
          (dump-mask (first (subnets subnet)) stream))
      (terpri stream)
      (json:as-object-member ('excluded stream)
          (json:with-array (stream)
            (loop for mask in (exception-masks (first (subnets subnet)))
                do (json:as-array-member (stream)
                     (dump-mask mask stream))
                   ))))))

(defmethod dump-subnet-data ((ensemble ensemble) &optional (stream *standard-output*))
  (let ((size (size ensemble))
	(range (ip-range ensemble)))
    (json:encode-object-member 'size  size stream)
    (terpri stream)
    (json:as-object-member ('range stream)
	(dump-mask range stream))))

;;; Fix: Needs to actually dump stuff
(defmethod dump-subnet-data ((computer computer) &optional (stream *standard-output*))
  (if (typical-p computer)
      (dump-subnet-data (ensemble computer) stream)
    (list :addresses (loop for address in (ip-addresses computer) collect (ip-address-string address)))))

(defmethod dump-mask ((mask subnet-mask) &optional (stream *standard-output*))
  (let ((address (ip-address-string (follow-path (list mask 'ip-address))))
	(mask (ip-address-string (follow-path (list mask 'mask)))))
    (when (and (string-equal address "0.0.0.0")
	       (string-equal mask "0.0.0.0"))
      (setq mask "255.255.255.255"))
    (json:with-object (stream)
      (json:encode-object-member 'address address stream)
      (json:encode-object-member 'mask mask stream))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Dumping Users
;;; For each user we dump its name as used in the plan
;;; For each user we indicate whether it's a typical member of some set of users (standin = true)
;;; For each user we indicate whether it's an attacker (attacker = true)
;;; We dump the set of computers that this user can access
;;;
;;; Other things: privilege level (admin or not)
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;




(defun dump-users (users stream)
  (json:with-array (stream)
    (loop for user in users
	do (terpri stream)
	   (json:as-array-member (stream) 
	     (dump-user user stream))))
  )

(defmethod dump-user ((user user) &optional (stream *standard-output*))
  (terpri stream)
  (json:with-object (stream)
    (json:encode-object-member 'name (role-name user) stream)
    (terpri stream)
    (json:encode-object-member 'standin (if (typical-p user) 'true 'false) stream)
    (terpri stream)
    (json:encode-object-member 'attacker (typecase user (attacker 'true) (otherwise 'false)) stream)
    (terpri stream)
    (json:as-object-member ('computers stream)
	(json:with-array (stream)
	  (Loop for computer in (computers user) 
		do (json:as-array-member (stream)
		     (json:with-object (stream)
		       (json:encode-object-member 'name (role-name computer) stream))))))
    (terpri stream)))