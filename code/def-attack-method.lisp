;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Componenets of attack planning
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; First a macro to make notation more abstract and clearer
;;; In this syntax in both the :to-achieve field and the :plan field
;;; there is a hidden last argument in the predications
;;; In the :to-achieve field this is ?plan
;;; In the :plan field it's the second part of the :goal :plan field
;;; The plan field is a nested set of :sequential :parallel constructions
;;; each one taking a list of (:goal :plan) pairs
;;; The macro rebuilds the predication-makers into ones with the last variable
;;; 
;;; In the :plan section, it traverses the structure, builds a buch of predication-makers
;;; for the sub-goal part of the rule and also builds up the plan list structure that 
;;; is unified with the plan logic-variable

(defun attach-logic-variable-to-predication-maker (predication-maker logic-variable-maker)
  (let ((new-statement (append (predication-maker-statement predication-maker)
			       (list logic-variable-maker))))
    `(predication-maker ',new-statement)))

(defun rebuild-plan-structure (plan-structure &optional (input-state `(logic-variable-maker .(intern (string-upcase "?input-state"))))
							(output-state `(logic-variable-maker ,(intern (string-upcase "?output-state")))))
  ;; as we traverse the plan-structure tree we accumulate the list structure
  ;; of the plan and push
  (labels ((do-next-level (structure connective input-state output-state)
	     ;; each level should either be a :sequential/:parallel
	     ;;  or a :goal/:plan pair
	     ;;  or maybe a :action item (to be dealth with later)
             (destructuring-bind (key . stuff) structure
               (case key
                 (:sequential
                  (loop for (thing . more-to-come) on stuff
		      for last = (not more-to-come)
		      for next-input-state = input-state then his-output-state
		      for next-output-state = (when last output-state)
		      for his-result = (do-next-level thing key next-input-state next-output-state)
                      for (his-stuff his-plan-structure his-output-state) = his-result
                      append his-stuff into stuff
		      when his-plan-structure  ;; a note provides no plan structure
                      collect his-plan-structure into plan-structure
                      finally (return (list stuff `(list ,key ,@plan-structure ,his-output-state) his-output-state))))
		 (:parallel
                  (loop for thing in stuff
		      for (his-stuff his-plan-structure) = (do-next-level thing key input-state output-state)
		      append his-stuff into stuff
		      when his-plan-structure ;; a note provides no plan structure
		      collect his-plan-structure into plan-structure
		      finally (return (list stuff `(list ,key ,@plan-structure)))))
		 (:note
		  (let* ((the-note (first stuff))
			 (input-state (or (getf structure :input-state)
					  input-state
					  (ji:make-logic-variable-maker (intern (string-upcase "?input-state")))))
			 (intermediate-state (or (getf structure :output-state)
						 output-state
						 (ji:make-logic-variable-maker (intern (string-upcase (gentemp "?intermediate-state-"))))))
			 (statement the-note)
			 (rebuilt-statement `(prog1 t (let ((new-state (intern-state (intern (string-upcase (gentemp "intermediate-state-"))) ,input-state)))
							(unify ,intermediate-state new-state)
							(tell (predication-maker '(in-state ,statement ,intermediate-state)))))))
		    (list (list rebuilt-statement)
			  nil
			  intermediate-state)))
		 (:break (list (list `(prog1 t (break ,@stuff)))
			       nil
			       input-state))
                 ((:goal :plan)
                  (let* ((goal (getf structure :goal))
                         (plan (getf structure :plan (ji::make-logic-variable-maker (gentemp (string-upcase "?plan-") ))))
			 (input-state (or (getf structure :input-state)
					  input-state
					  (ji:make-logic-variable-maker (intern (string-upcase "?input-state")))))
			 (output-state (or (getf structure :output-state)
					   output-state
					   (ji:make-logic-variable-maker (intern (string-upcase (gentemp "?intermediate-state-"))))))
                         (rebuilt-statement `(predication-maker '(achieve-goal ,goal ,input-state ,output-state ,plan))))
                    (list (list rebuilt-statement)
                          (if (null connective)
                              `(list :singleton
                                     (list :goal ,(fixup-syntax (predication-maker-statement goal))
                                           :plan ,plan))
                            `(list :goal ,(fixup-syntax (predication-maker-statement goal))
                                   :plan ,plan))
			  output-state)))
                 ((:action :repeated-action)
		  (let* ((statement (first stuff))
			 (input-state (or (getf structure :input-state)
					  input-state
					  (ji::make-logic-variable-maker (intern (string-upcase "?input-state")))))
			 (output-state (or (getf structure :output-state)
					   output-state
					   (ji::make-logic-variable-maker (intern (string-upcase "?output-state")))))
			 (rebuilt-statement `(predication-maker '(take-action ,statement ,input-state ,output-state))))
		    (list 
		     ;; The action requires no further sub-goaling
		     (list rebuilt-statement)
		   ;;; rebuilt action statement
		     (if (null connective)
			 `(list :singleton
				(list ,key ,(fixup-syntax (predication-maker-statement (first stuff)))))
		       `(list ,key ,(fixup-syntax (predication-maker-statement (first stuff)))))
		     output-state))))))
           (fixup-syntax (predication-maker-statement)
             `(list
               ,@(loop for thing in predication-maker-statement
                     collect (typecase thing
                               (logic-variable-maker thing)
                               (symbol `',thing)
                               (list (fixup-syntax thing)))))))
    (when plan-structure
      (do-next-level plan-structure nil input-state output-state))))

(defun process-post-conditions (assertions output-state)
  (when assertions
    `((prog1 t
	,@(loop for assertion in assertions
	      collect `(tell [in-state ,assertion ,output-state]))))))
						
(defun process-assertions (assertions input-state)
  (labels ((do-one (assertion)
	     (cond 
	      ((and (listp assertion) (not (predication-maker-p assertion)))
	       (if (eql (first assertion) 'break)
		   `(prog1 t ,assertion)
		 assertion))
	      ((eql (predication-maker-predicate assertion) 'or)
	       (with-predication-maker-destructured (&rest assertions) assertion
		 (loop for assertion in assertions 
		     collect (do-one assertion) into processed-assertions
		     finally (return `(predication-maker '(or ,@processed-assertions))))))
	      ((compile-without-state assertion) assertion)
	      (t `(predication-maker '(in-state ,assertion ,input-state))))))
    (loop for thing in assertions collect (do-one thing))))


(defun process-guards (assertions input-state) (process-assertions assertions input-state))

(defun process-bindings (assertions input-state)
  (process-assertions assertions input-state))

(defun process-prerequisites (assertions input-state) (process-assertions assertions input-state))

(defun compile-without-state (form)
  (if (predication-maker-p form)
    (let ((predicate (predication-maker-predicate form)))
      (cond
       ((eql predicate 'not)
	  (with-predication-maker-destructured (internal-pred) form
	    (let ((internal-predicate (predication-maker-predicate internal-pred)))
	      (subtypep internal-predicate 'non-stateful-predicate-model))))
       (t
	(or (subtypep predicate 'non-stateful-predicate-model)
	    (subtypep predicate 'ji::named-part-of-mixin)))))
    nil))

(defmacro defattack-method (method-name &key to-achieve 
					     (input-state `(logic-variable-maker ,(intern (string-upcase "?input-state"))))
					     (output-state `(logic-variable-maker ,(intern (string-upcase "?output-state"))))
					     guards 
					     bindings
					     prerequisites
					     typing
					     plan
					     post-conditions
					     )
  (let* ((plan-variable `(logic-variable-maker ,(gensym "?PLAN")))
         (real-head `(predication-maker '(achieve-goal ,to-achieve ,input-state  ,output-state ,plan-variable)))
	 (rebuilt-plan-structure (rebuild-plan-structure plan input-state output-state)))
    (destructuring-bind (stuff plan-structure) (or rebuilt-plan-structure (list nil nil))
      `(defrule ,method-name (:backward)
         then ,real-head
         if [and 
	     ,@(process-bindings bindings input-state)
	     ,@(process-guards guards input-state)
	     ,@typing
	     ,@(process-prerequisites prerequisites input-state)
	     ,@stuff
	     ,@(process-post-conditions post-conditions output-state)
	     (unify ,plan-variable ,plan-structure)
	     ]))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Define-goal
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmacro define-goal (name variables) `(define-predicate ,name ,variables (ltms:ltms-predicate-model)))

(define-predicate achieve-goal (goal-to-achieve input-state output-state plan) (ltms:ltms-predicate-model))

(define-predicate take-action (action-predicate input-state output-state) (ltms:ltms-predicate-model))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Define-action
;;;
;;; Similar to but simpler than def-attack-method
;;; and it uses some of the sub-routines from def-attack-method
;;;
;;; Actions are defined over a set of logic-variables
;;;  Have pre-conditions that are tested in the input-state
;;;  and post-conditions that are asserted in the output-state
;;;
;;; If the output state is not passed in a new successor of the input state
;;; is created and unified with the output-state logic-variable
;;;
;;; Given that it's a mix of asks and tells should it be a backward rule or just a procedure that returns
;;; the output state?
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defclass action ()
  ((action-name :accessor action-name :initarg :action-name)
   (arguments :accessor arguments :initarg :arguments)
   (prior-state :accessor prior-state :initarg :prior-state)
   (next-state :accessor next-state :initarg :next-state)))

(defun link-action (name arguments prior-state next-state)
  (let ((action (make-instance 'action
		  :action-name name
		  :arguments arguments
		  :prior-state prior-state
		  :next-state next-state)))
    (setf (next-action prior-state) action
	  (prior-action next-state) action)
    action))

(defmacro define-action (name variables &key bindings prerequisites post-conditions (define-predicate t)) 
  (flet ((make-logic-variables (names)
	   (loop for var in names 
	       if (logic-variable-maker-p var)
	       collect var
	       else collect `(logic-variable-maker ,(intern (string-upcase (format nil "?~a" var))))))
	 (make-symbols-from-lvs (lvs)
	   (loop for lv in lvs
	       for name = (logic-variable-maker-name lv)
	       for pname-string = (subseq (string name) 1) ;; strip off the ?
	       collect (intern pname-string))))
    (let* ((logic-variables (make-logic-variables variables))
	   (names (make-symbols-from-lvs logic-variables))
	   (rule-name (intern (string-upcase (format nil "do-~a" name))))
	   (state-logic-variables (make-logic-variables '(input-state output-state))))
      (destructuring-bind (input-state-variable output-state-variable) state-logic-variables
	`(eval-when (:compile-toplevel :load-toplevel :execute)
	   ,@(when define-predicate `((define-predicate ,name ,names (ltms:ltms-predicate-model))))
	   (defrule ,rule-name (:backward)
	     then [take-action [,name ,@logic-variables] ,@state-logic-variables]
	     if [and ,@(process-bindings bindings input-state-variable)
		     ,@(process-guards prerequisites input-state-variable)
		     (when (unbound-logic-variable-p ,output-state-variable)
		       (unify ,output-state-variable 
			      (intern-state (intern (string-upcase (gensym "state-"))) ,input-state-variable)))
		     (prog1 t (link-action ',name (list,@logic-variables) ,input-state-variable ,output-state-variable))
		     ,@(process-post-conditions post-conditions output-state-variable)
		     ]))))))

#|

Test case

(define-action foo (a b)
  :pre-conditions ([bar ?a ?b]
		   [baz ?b ?c])
  :post-conditions ([bam ?a ?b ?c]))

This expands to:

(EVAL-WHEN (:COMPILE-TOPLEVEL :LOAD-TOPLEVEL :EXECUTE)
  (DEFINE-PREDICATE FOO (A B) (LTMS:LTMS-PREDICATE-MODEL))
  (DEFRULE DO-FOO (:BACKWARD) 
    THEN [TAKE-ACTION [FOO ?A ?B] ?INPUT-STATE ?OUTPUT-STATE] 
    IF [AND [IN-STATE [BAR ?A ?B] ?INPUT-STATE]
	    [IN-STATE [BAZ ?B ?C] ?INPUT-STATE]
	    (WITH-UNIFICATION
		(WHEN (UNBOUND-LOGIC-VARIABLE-P ?OUTPUT-STATE)
		      (UNIFY (INTERN-STATE (INTERN (STRING-UPCASE (GENSYM 'STATE-))) ?INPUT-STATE)
			     ?OUTPUT-STATE))
	      (PROG1 T (TELL [IN-STATE [BAM ?A ?B ?C] ?OUTPUT-STATE])))]))

|#

