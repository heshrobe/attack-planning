;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The top level dispatcher for dealing with predicates that are stateful but
;;; maintain special data structures
;;;
;;; Dispatch to ask-in-state for ask
;;; Dispatch to insert-in-state for tell
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate-method (ask-data stateful-predicate-mixin :around) (truth-value continuation)
  (with-statement-destructured (internal-pred state) self
    (let ((state (intern-state state)))
      (typecase internal-pred
	(ji:not-model
	 (with-statement-destructured (real-internal-pred) internal-pred
	   (cond
	    ((typep real-internal-pred 'special-stateful-predicate-model)
	     (setq internal-pred real-internal-pred
		   truth-value (negate-truth-value truth-value))
	     (ask-in-state internal-pred truth-value state continuation))
	    (t (call-next-method)))))
	;; Named-part-of-mixin describes an immutable structural property of an
	;; object, so all we need to do is see if it's true in the initial state
	(ji::named-part-of-mixin (ask-data internal-pred truth-value continuation))
	(special-stateful-predicate-model
	 (ask-in-state internal-pred truth-value state continuation))
	(otherwise (call-next-method))))))

(define-predicate-method (insert stateful-predicate-mixin :around) ()
  (with-statement-destructured (internal-pred state) self
    (let ((state (intern-state state)))
      (typecase internal-pred
	(special-stateful-predicate-model (insert-in-state self internal-pred state))
	(otherwise (call-next-method))))))

;;; This is the default it does nothing
(defmethod insert-in-state ((outer-predication stateful-predicate-mixin) (internal-pred special-stateful-predicate-model) (state state))
  (values outer-predication nil))

;;; This is here so that the stanard state mapping trick for vanilla internal predications
;;; isn't invoked for guys that don't role that way.
(define-predicate-method (act-on-truth-value-change stateful-predicate-mixin :around) (old-truth-value &optional old-predication-state)
  (with-statement-destructured (internal-pred state) self
    (typecase internal-pred
      (special-stateful-predicate-model (act-on-truth-value-change-in-state self internal-pred (intern-state state)old-truth-value old-predication-state))
      (otherwise (call-next-method)))))

;;; This is the default method it does nothing
(defmethod act-on-truth-value-change-in-state ((outer-predication stateful-predicate-mixin) (internal-pred special-stateful-predicate-model)
					       (state state) old-truth-value old-predication-state)
  (declare (ignore old-truth-value old-predication-state))
  (values outer-predication))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Attacker and Machine
;;; Only asserted in the base environment
;;; Chases back through predecessor states of the state in the query
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod ask-in-state ((query attacker-and-machine) truth-value (state state) continuation)
  (unless (eql truth-value +true+)
    (error 'ji:model-can-only-handle-positive-queries
	   :query query
	   :model (type-of query)))
  (with-statement-destructured (attacker attacker-machine) query
    (loop for this-state = state then next-state
	while this-state
	for next-state = (predecessor this-state)
	for attacker-of-state = (attacker this-state)
	for machine-of-state = (attacker-machine this-state)
	when (and (not (null attacker-of-state)) (not (null machine-of-state)))
	do (with-unification 
	    (unify attacker-machine machine-of-state)
	    (unify attacker attacker-of-state)
	    (stack-let ((backward-support (list query +true+ (attacker-and-machine-pred this-state) '(ask-data attacker-and-machine))))
	      (funcall continuation backward-support)))
	   (return))))

(defmethod insert-in-state ((outer stateful-predicate-mixin) (inner attacker-and-machine) (state state))
  (let ((state (intern-state state)))
    (with-statement-destructured (attacker machine) inner
      (setf (attacker state) attacker
	    (attacker-machine state) machine
	    (attacker-and-machine-pred state) `[in-state [attacker-and-machine ,attacker ,machine] ,state])
      (values (attacker-and-machine-pred state) t))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Has-foothold
;;; Remember that the attacker has a foothold at this state (and all successors)
;;; (tell only I think)
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; This follows the protocol of insert: I.e. returns the interned predication
;;; and a new-p flag
(defmethod insert-in-state ((outer-predicaton stateful-predicate-mixin) (predication has-foothold) state)
  (let ((state (intern-state state)))
    (with-statement-destructured (foothold-machine foothold-role) predication
      (let ((existing-statement (loop for (existing-foothold-machine existing-foothold-role existing-pred) in (footholds-held state)
				    when (and (eql foothold-machine existing-foothold-machine)
					      (eql foothold-role existing-foothold-role))
				    return existing-pred)))
	(cond
	 (existing-statement (values existing-statement nil))
	 (t (push (list foothold-machine foothold-role predication) (footholds-held state))
	    (values predication t)))))))
      

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Current Foothold
;;; Stack-like behavior starting at the base environment
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod ask-in-state ((query current-foothold) truth-value (state state) continuation)
  (unless (eql truth-value +true+)
    (error 'ji:model-can-only-handle-positive-queries
	   :query query
	   :model (type-of query)))
  (with-statement-destructured (foothold-machine foothold-role) query
    (destructuring-bind (machine role) (first (footholds-held state))
      (with-unification 
       (unify machine foothold-machine)
       (unify role foothold-role)
       (stack-let ((backward-support (list query +true+ '(ask-data current-foothold))))
	 (funcall continuation backward-support))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Foothold Exists
;;; Checks whether there is a foothold in a state or any predecessor state
;;; Ask only (I think)
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod ask-in-state ((query foothold-exists) truth-value (state state) continuation)
  (with-statement-destructured (foothold-machine) query
    (cond
     ((eql truth-value +true+)
      (if (unbound-logic-variable-p foothold-machine)
	  (loop for (foothold nil pred) in (footholds-held state)
	      do (with-unification
		  (unify foothold foothold-machine)
		  (stack-let ((backward-support (list query +true+ pred '(ask-data foothold-exists))))
		    (funcall continuation backward-support))))
	(let ((entry (assoc foothold-machine (footholds-held state))))
	  (when entry
	    (stack-let ((backward-support (list query +true+ (third entry) '(ask-data foothold-exists))))
	      (funcall continuation backward-support))))))
     ((and (eql truth-value +false+) (not (unbound-logic-variable-p foothold-machine)))
      (unless (member foothold-machine (footholds-held state) :key #'first)
	(stack-let ((backward-support (list query +true+ '(ask-data foothold-exists))))
	  (funcall continuation backward-support))))
     ;; Wierd case: Are there no footholds?
     ((eql truth-value +false+)
      (when (null (footholds-held state))
	(stack-let ((backward-support (list query +true+ '(ask-data foothold-exists))))
		   (funcall continuation backward-support))))
     (t (error 'ji::model-cant-handle-query
	       :query query
	       :model (type-of query))))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Place-already-visited
;;; True if the search process has already seen this state
;;; (ask only I think)
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; If the purpose is remote-execution all we check is that there is a previous
;;; entry for the same machine.
(defmethod ask-in-state ((query place-already-visited?) truth-value (state state) continuation)
  (with-statement-destructured (machine purpose) query
    (let ((it-exists (case purpose
		       ;; For remote execution, if you got here as a subgoal of getting a foothold for this machine
		       ;; you're in a loop.  Obviously if you got here as a subgoal of getting remote execution that's 
		       ;; a loop as well
		       (remote-execution (loop for (visited-machine) in (places-visited state)
					     thereis (eql machine visited-machine)))
		       ;; For foothold, we might be here as a subgoal of getting remote execution so we only look
		       ;; at foothold entries.  We consider recursing with a different protocol to also be a loop
		       ;; so protocol is actually ignored.
		       (foothold (loop for (visited-machine visited-purpose) in (places-visited state)
				     thereis (and (eql machine visited-machine) (eql purpose visited-purpose)))))))
      (cond
       ((eql truth-value +true+)
	(when it-exists
	  (stack-let ((backward-support (list query +true+ '(ask-data place-already-visited?))))
	    (funcall continuation backward-support))))
       ((eql truth-value +false+)
	(unless it-exists
	  (stack-let ((backward-support (list query +false+ '(ask-data place-already-visited?))))
	    (funcall continuation backward-support))))
       (t (error 'model-cant-handle-query
		 :query query
		 :model (type-of query)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Place Visited
;;;  This is a told in a :note within the attack-method
;;;   It's the only thing we use :notes for so far
;;;
;;; The predication includes the machine, the purpose (either remote-execution or foothold) 
;;;
;;;
;;; We actually do nothing at the insert stage
;;; Because we have no need for a predication to hang a state map on
;;; But do all the work at the act-on-truth-value-stage
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod act-on-truth-value-change-in-state ((outer-predication stateful-predicate-mixin) (inner-predication place-visited) (state state)
					       old-truth-value old-predication-state)
  (declare (ignore old-truth-value old-predication-state))
  (when (or (not (eql (predication-truth-value outer-predication) +true+))
	    (typep inner-predication 'ji::Not-model))
    (error "Can only handle positive assertions"))
  (with-statement-destructured (machine purpose) inner-predication 
    ;; (format *error-output* "~%Noting that ~a was visited for purpose ~a" machine purpose)
    (pushnew (list machine purpose ) (places-visited state) :test #'equal)))
 