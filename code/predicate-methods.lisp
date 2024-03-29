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
;;; Attacker and Computer
;;; Only asserted in the base environment
;;; Chases back through predecessor states of the state in the query
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod ask-in-state ((query attacker-and-computer) truth-value (state state) continuation)
  (unless (eql truth-value +true+)
    (error 'ji:model-can-only-handle-positive-queries
	   :query query
	   :model (type-of query)))
  (with-statement-destructured (attacker attacker-computer) query
    (loop for this-state = state then next-state
	while this-state
	for next-state = (predecessor this-state)
	for attacker-of-state = (attacker this-state)
	for computer-of-state = (attacker-computer this-state)
	when (and (not (null attacker-of-state)) (not (null computer-of-state)))
	do (with-unification
	    (unify attacker-computer computer-of-state)
	    (unify attacker attacker-of-state)
	    (stack-let ((backward-support (list query +true+ (attacker-and-computer-pred this-state) )))
	      (funcall continuation backward-support)))
	   (return))))

(defmethod insert-in-state ((outer stateful-predicate-mixin) (inner attacker-and-computer) (state state))
  (let ((state (intern-state state)))
    (with-statement-destructured (attacker computer) inner
      (setf (attacker state) attacker
	    (attacker-computer state) computer
	    (attacker-and-computer-pred state) `[in-state [attacker-and-computer ,attacker ,computer] ,state])
      (values (attacker-and-computer-pred state) t))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Has-foothold
;;; Remember that the attacker has a foothold at this state (and all successors)
;;; (tell only I think)
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defclass foothold-record ()
    ((victim-computer :accessor victim-computer :initarg :victim-computer :initform nil)
     (foothold-computer :accessor foothold-computer :initarg :foothold-computer :initform nil)
     (foothold-role :accessor foothold-role :initarg :foothold-role :initform nil)
     (protocol :accessor protocol :initarg :protocol :initform nil)
     (foothold-predication :accessor foothold-predication :initform nil :initarg :foothold-predication)
     )
    )


;;; This follows the protocol of insert: I.e. returns the interned predication
;;; and a new-p flag
(defmethod insert-in-state ((outer-predicaton stateful-predicate-mixin) (predication has-foothold) state)
  (let ((state (intern-state state)))
    (with-statement-destructured (victim-computer foothold-computer foothold-role foothold-protocol) predication
      (let ((existing-statement (loop for foothold-record in (footholds-held state)
				    for existing-victim = (victim-computer foothold-record)
				    for existing-foothold-computer = (foothold-computer foothold-record )
				    for existing-foothold-role = (foothold-role foothold-record)
				    for existing-foothold-protocol = (protocol foothold-record)
				    for existing-pred = (foothold-predication foothold-record)
				    when (and (eql victim-computer existing-victim)
					      (eql foothold-computer existing-foothold-computer)
					      (eql foothold-role existing-foothold-role)
					      (eql existing-foothold-protocol foothold-protocol))
				    return existing-pred)))
	(cond
	 (existing-statement (values existing-statement nil))
	 (t (push (make-instance 'foothold-record
		    :victim-computer victim-computer
		    :foothold-computer foothold-computer
		    :foothold-role foothold-role
		    :protocol foothold-protocol
		    :foothold-predication predication)
		  (footholds-held state))
	    (values predication t)))))))

(defmethod ask-in-state ((query has-foothold) truth-value (state state) continuation)
  (unless (eql truth-value +true+)
    (error 'ji:model-can-only-handle-positive-queries
	   :query query
	   :model (type-of query)))
  (with-statement-destructured (victim-computer foothold-computer foothold-role foothold-protocol) query
    (loop for foothold-record in (footholds-held state)
	for existing-victim = (victim-computer foothold-record)
	for existing-foothold-computer = (foothold-computer foothold-record )
	for existing-foothold-role = (foothold-role foothold-record)
	for existing-foothold-protocol = (protocol foothold-record)
	for existing-pred = (foothold-predication foothold-record)
	do (with-unification
	    (unify existing-victim victim-computer)
	    (unify existing-foothold-computer foothold-computer)
	    (unify existing-foothold-role foothold-role)
	    (unify existing-foothold-protocol foothold-protocol)
	    (stack-let ((backward-support (list query +true+ existing-pred )))
	      (funcall continuation backward-support))))))




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
  (with-statement-destructured (foothold-computer foothold-role) query
    (let* ((foothold-record (first (footholds-held state)))
	   (existing-foothold-computer (foothold-computer foothold-record))
	   (existing-foothold-role (foothold-role foothold-record)))
      (with-unification
       (unify existing-foothold-computer foothold-computer)
       (unify existing-foothold-role foothold-role)
       (stack-let ((backward-support (list query +true+ '(ask-data current-foothold))))
	 (funcall continuation backward-support))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Foothold Exists
;;; Checks whether there is a foothold in a state or any predecessor state
;;; Ask only (I think)
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod ask-in-state ((query foothold-doesnt-exist) truth-value (state state) continuation)
  (with-statement-destructured (victim-computer) query
    (cond
     ((eql truth-value +true+)
      (let ((entry (find victim-computer (footholds-held state) :key #'victim-computer)))
	  (unless entry
	    (stack-let ((backward-support (list query +true+ '(ask-data foothold-exists))))
	      (funcall continuation backward-support)))))
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
;;; entry for the same computer.
(defmethod ask-in-state ((query place-already-visited?) truth-value (state state) continuation)
  (with-statement-destructured (computer purpose sub-purpose) query
    (let ((it-exists (case purpose
		       ;; For remote execution, if you got here as a subgoal of getting a foothold for this computer
		       ;; you're in a loop.  Obviously if you got here as a subgoal of getting remote execution that's
		       ;; a loop as well
		       (remote-execution (loop for (visited-computer visited-purpose visited-subpurpose) in (places-visited state)
					     thereis (and (eql computer visited-computer)
                                                          (eql purpose visited-purpose)
                                                          (eql sub-purpose visited-subpurpose)
                                                          )))
		       ;; For foothold, we might be here as a subgoal of getting remote execution so we only look
		       ;; at foothold entries.  We consider recursing with a different protocol to also be a loop
		       ;; so protocol is actually ignored.
		       (foothold (loop for (visited-computer visited-purpose) in (places-visited state)
				     thereis (and (eql computer visited-computer) (eql purpose visited-purpose)))))))
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
;;; The predication includes the computer, the purpose (either remote-execution or foothold)
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
    (error 'model-cant-handle-query
	   :query outer-predication
	   :model (type-of outer-predication)))
  (with-statement-destructured (computer purpose sub-purpose) inner-predication
    ;; (format *error-output* "~%Noting that ~a was visited for purpose ~a" computer purpose)
    (pushnew (list computer purpose sub-purpose) (places-visited state) :test #'equal)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; This is a special method (moved from objectmo.lisp where it really doesn't belong)
;;; which fetches slot-value predicates for the ask-data method below
;;; We've generalized slot-value things enough that it's now
;;; possible that the final thing isn't a slot but just an object
;;; in which case we're going to create a predication for it
;;; if one doesn't exist
;;;
;;; This is now obsoleted because the ask-data method for all predicates can take a
;;; truth-value argument of NIL, meaning to ignore truth value
;;; and Joshua now provides asks-data methods to handle this type of query.
;;; So there's no need to go down to the fetch level for stateful predicates
;;; to fetch the canonical version of a slot-value assertion
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;(define-predicate-method (fetch value-of) (continuation)
;;;  (with-statement-destructured (path value-in-query) self
;;;    (declare (ignore value-in-query))
;;;    (flet ((slot-continuation (final-slot)
;;;	     (typecase final-slot
;;;	       (ji::basic-slot
;;;		(with-slots (ji::all-predications) final-slot
;;;		  (loop for (nil . predication) in ji::all-predications
;;;		      do (funcall continuation predication))))
;;;	       ;; If resolving the path takes you to an actual object
;;;	       ;; then you just call the continuation.  Notice, this is
;;;	       ;; different than the case where the final thing is a slot
;;;	       ;; whose value is an object.  In that case, the path specifies a slot
;;;	       ;; whose value could change.  In this case, the last step takes
;;;	       ;; you to a "part" of the previous object.  Parts are fixed parts of the hierarchy
;;;	       ;; and can't be deduced by backward rules (I think).  Also in this case it's not set valued
;;;	       ;; so we just call the continuation after unifying the value part of the query to the object
;;;	       (ji::basic-object
;;;		(let* ((object final-slot)
;;;		       (his-role-name (ji::basic-object-role-name object))
;;;		       (his-parent (ji::basic-object-superpart-object object))
;;;		       (parent-predication-table (subpart-table his-parent))
;;;		       (his-predication (gethash his-role-name parent-predication-table)))
;;;		  (unless his-predication
;;;		    (setq his-predication `[named-part-of ,his-parent ,his-role-name ,object])
;;;		    (setf (ji::predication-bits-truth-value (ji::predication-bits his-predication)) +true+)
;;;		    (setf (gethash his-role-name parent-predication-table) his-predication))
;;;		  (funcall continuation his-predication))))))
;;;      (ji::follow-path-to-slot* path #'slot-continuation nil))))
