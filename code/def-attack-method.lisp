;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Componenets of attack planning
;;;
;;; First some useful utilitires for def-attack-method
;;;
;;; In this syntax in both the :to-achieve field and the :plan field
;;; there is a hidden last argument in the predications
;;; In the :to-achieve field this is ?plan
;;; In the :plan field it's the second part of the :goal :plan field
;;; The plan field is a nested set of :sequential :parallel constructions
;;; each one taking a list of (:goal :plan) pairs
;;; The macro rebuilds the predication-makers into ones with the last variable
;;; 
;;; In the :plan section, it traverses the structure, builds a bunch of predication-makers
;;; for the sub-goal part of the rule and also builds up the plan list structure that 
;;; is unified with the plan logic-variable
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defvar name-to-number-hash-table (make-hash-table))

(defun make-name (lead-in)
  (let ((existing-number (gethash lead-in name-to-number-hash-table)))
    (unless existing-number
      (setf (gethash lead-in name-to-number-hash-table) 0))
    (intern (string-upcase (format nil "~a-~d" lead-in (incf (gethash lead-in name-to-number-hash-table)))))))

(defun smash (&rest names)
  (let ((strings (loop for (name . rest) on names
                     for string = (string name)
                     collect string
                     when rest 
                          collect "-")))
    (intern (string-upcase (apply #'concatenate 'string strings)))))

(defun explode-string (string delim)
  ;; so it can handle a symbol
  (setq string (string string))
  (loop for last-pos = 0 then (1+ next-pos)
        for next-pos = (position delim string :start last-pos)
        collect (subseq string last-pos next-pos)
      until (null next-pos))
  )

(defmethod explode ((thing symbol) delimeter)
  (loop for string in (explode-string thing delimeter)
      collect (intern string)))

(defmethod explode ((thing list) delimeter)
  (if (logic-variable-maker-p thing)
      (destructuring-bind (first . rest) (explode (logic-variable-maker-name thing) delimeter)
        (list* (ji:make-logic-variable-maker first) rest))
    thing))



(defun attach-logic-variable-to-predication-maker (predication-maker logic-variable-maker)
  (let ((new-statement (append (predication-maker-statement predication-maker)
			       (list logic-variable-maker))))
    `(predication-maker ',new-statement)))

(defun rebuild-plan-structure (plan-structure &optional (input-state `(logic-variable-maker .(intern (string-upcase "?input-state"))))
							(output-state `(logic-variable-maker ,(intern (string-upcase "?output-state")))))
  ;; as we traverse the plan-structure tree we accumulate the list structure
  ;; of the plan and push
  ;; each this returns 3 values.  I'm not sure why the third yet
  (labels ((do-next-level (structure connective input-state output-state)
	     ;; each level should either be a :sequential/:parallel
	     ;;  or a :goal/:plan pair
	     ;;  or maybe a :action item (to be dealth with later)
             (destructuring-bind (key . stuff) structure
               (case key
                 (:sequential
                  (loop for (thing . more-to-come) on stuff
		      for last = (or (not more-to-come) (not (loop for (key) in more-to-come thereis (member key '(:goal :action)))))
		      for next-input-state = input-state then his-output-state
		      for next-output-state = (when last output-state)
		      for his-result = (do-next-level thing key next-input-state next-output-state)
                      for (his-stuff his-plan-structure his-output-state) = his-result
                      append his-stuff into stuff
		      when his-plan-structure  ;; a note provides no plan structure
                      collect his-plan-structure into plan-structure
                      finally (let* ((is-singleton? (null (rest plan-structure)))
				     (final-key (if is-singleton? :singleton key)))
				(return (list stuff `(list ,final-key ,@plan-structure) his-output-state)))))
		 (:parallel
                  (loop for thing in stuff
		      for (his-stuff his-plan-structure) = (do-next-level thing key input-state output-state)
		      append his-stuff into stuff
		      when his-plan-structure ;; a note provides no plan structure
		      collect his-plan-structure into plan-structure 
		      finally (return (list stuff `(list ,key ,@plan-structure) nil))))
		 (:bind
		  (let* ((the-binding (first stuff))
			 (input-state (or (getf structure :input-state)
					  input-state
					  (ji:make-logic-variable-maker (intern (string-upcase "?input-state")))))
			 (rebuilt-statement (if (compile-without-state the-binding) the-binding `(predication-maker '(in-state ,the-binding ,input-state)))))
		    (list (list rebuilt-statement)
			  nil
			  input-state)))
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
							(setf (intermediate-state? new-state) t)
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
					   (ji:make-logic-variable-maker (intern (string-upcase (gentemp "?intermediate-state-"))))))
			 (action-variable (ji:make-logic-variable-maker (intern (string-upcase (gentemp "?action-")))))
			 (rebuilt-statement `(predication-maker '(take-action ,statement ,input-state ,output-state ,action-variable)))
			 )
		    ;; (break "Action ~a ~a ~a ~a" statement input-state output-state rebuilt-statement)
		    (list 
		     ;; The action requires no further sub-goaling
		     (list rebuilt-statement)
		   ;;; rebuilt action statement
		     (if (null connective)
			 `(list :singleton
				(list ,key ,(fixup-syntax (predication-maker-statement (first stuff))) ,action-variable))
		       `(list ,key ,(fixup-syntax (predication-maker-statement (first stuff))) ,action-variable))
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



(defun process-post-conditions (assertions output-state &optional support)
  (when assertions
    (if support
        (loop for assertion in assertions
	      collect `(tell [in-state ,assertion ,output-state]
                             ,@(when support
                                 `(:justification ,support))))
    `((prog1 t
	,@(loop for assertion in assertions collect `(tell [in-state ,assertion ,output-state])))))))
						
(defun process-assertions (assertions input-state)
  (labels ((do-one (assertion)
	     (cond 
	      ;; special case for debugging
	      ((and (listp assertion) (not (predication-maker-p assertion)))
	       (if (eql (first assertion) 'break)
		   `(prog1 t ,assertion)
		 assertion))
	      ((eql (predication-maker-predicate assertion) 'or)
	       (with-predication-maker-destructured (&rest assertions) assertion
		 (loop for assertion in assertions 
		     collect (do-one assertion) into processed-assertions
		     finally (return `(predication-maker '(or ,@processed-assertions))))))
	      ((and (listp assertion) (not (predication-maker-p assertion))) assertion)
	      ((compile-without-state assertion) assertion)
	      (t `(predication-maker '(in-state ,assertion ,input-state))))))
    (loop for thing in assertions collect (do-one thing))))


(defun process-guards (assertions input-state) (process-assertions assertions input-state))



(defun is-pretty-binding (assertion)
  (cond 
   ((and (predication-maker-p assertion)
     (eql (predication-maker-predicate assertion) 'value-of)
         (with-predication-maker-destructured (path value) assertion
           (if (and (not (logic-variable-maker-p path))
                    (listp path))
               nil
             (and (logic-variable-maker-p value)
                  (find #\. (string (if (logic-variable-maker-p path)
                                        (logic-variable-maker-name path)
                                      path))
                        :test #'char-equal)))))
    t)
   ((listp assertion)
    (and (logic-variable-maker-p (first assertion))
         (eql (length assertion) 2)))
   (t nil)))

(defun de-prettify-binding (assertion)
  (cond
   ;; this case is a legacy since the implicit binding machinery 
   ;; would have already taken care of the dotted-path notation
   ;; But we need to keep it until define-action is updated with 
   ;; the implicit binding machinery
   ((predication-maker-p assertion)
    (with-predication-maker-destructured  (path logic-variable) assertion
      (flet ((process-path (list-of-strings)
               (loop for thing in list-of-strings
		   if (char-equal (aref thing 0) #\?)
		   collect (ji::make-logic-variable-maker (intern thing))
		   else collect (intern thing))))
        (if (logic-variable-maker-p path)
            (let* ((name (logic-variable-maker-name path))
                   (exploded-path (explode-string name #\.))
                   (real-path (cons (ji::make-logic-variable-maker (intern (first exploded-path)))
                                    (process-path (rest exploded-path)))))
              `(predication-maker '(value-of ,real-path ,logic-variable)))
          (let ((expanded-path (process-path (explode-string path #\.))))

            `(predication-maker '(value-of ,expanded-path ,logic-variable)))))))
   ((and (listp assertion) (eql (length assertion) 2) (logic-variable-maker-p (first assertion)))
    `(predication-maker '(value-of ,(second assertion) ,(first assertion))))))

(defun process-bindings (assertions input-state)
  (let ((expanded-bindings (loop for assertion in assertions
			       collect (if (is-pretty-binding assertion)
					   (de-prettify-binding assertion)
					 assertion))))
    (process-assertions expanded-bindings input-state)))



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

;;; As far as I can see, all the typing forms
;;; are the simple (thing type) so there might not
;;; need be an escape hatch for more complex forms
;;; Except that it allows break forms
(defun process-typing (forms)
  (loop for form in forms
      if (and (listp form) (eql (first form) :break))
         collect `(break ,@(rest form))
      else if (and (listp form) (= (length form) 2))
      collect `(predication-maker '(ltms:object-type-of ,@form))
      else collect form))

(defun mentioned-in? (lv-maker set-of-forms)
  (let ((name (logic-variable-maker-name lv-maker)))
    (labels ((in? (form)
               ;; (format t "~%Testing ~a in ~a" name form)
               (cond
                ((logic-variable-maker-p form)
                 (if (eql name (logic-variable-maker-name form))
                     (return-from mentioned-in? t)
                   nil))
                ((predication-maker-p form)
                 (loop for term in (predication-maker-statement form)
                     do (in? term)))
                ((listp form)
                 (loop for term in form do (in? term)))
                ((eql name form) 
                 (return-from mentioned-in? t))
                (t nil))))
      (in? set-of-forms))))

(defun bound-in? (lv-maker set-of-forms)
  (let ((name (logic-variable-maker-name lv-maker)))
    (loop for form in set-of-forms
        when (and (predication-maker-p form)
                  (member (predication-maker-predicate form) '(unify value-of))
                  (with-predication-maker-destructured (path value) form
                    (declare (ignore path))
                    (and (logic-variable-maker-p value)
                         (eql (logic-variable-maker-name value) name))))
        do (return-from bound-in? t))
      nil))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; defattach-method: The Macro for defining attack planning methods
;;; 
;;; This takes the declarative PDDL style definition of a HTM planning method
;;; and translates it into a Joshua backward chaining rule
;;;
;;; Does a modest amount of analysis to figure out where the type
;;; constraints can be placed
;;; 
;;; Allows one to refer to parts of data-structures through use of "dotted-path" notation
;;;  e.g.  ?foo.bar.baz.  Whenever one of these is found a binding of the form [value-of (?foo bar bar) ?lv-xxx]
;;; is generated and all references to ?foo.bar.baz are replaced by ?lv-xxx.  This is just a notational convenience.
;;; If ?foo.bar.baz is frequently referenced, it's easier to make an explicit binding in the bindings section.
;;; These implicit bindings are place just in front of the first reference to ?foo.bar.baz.
;;;
;;; The order of the generated code:
;;; Early typing: typing that only references the inputs
;;; Bindings: 
;;;   Implicit bindings in the bindings code
;;;   Implicit bindings in the typing code
;;;   The rest of the explicit bindings
;;; Guards (an idea to consider is to move guards that only refer to the inputs
;;;         to the front as we do with typing)
;;; Typing: Types that refer to things other than the inputs
;;; Implicit bindings reference by the prerequisites
;;; Prerequisites
;;; Implicit bindings in the plan
;;; The sub-goals and actions
;;; Implicit bindings in the post-conditions
;;; Postconditions
;;; Code to unify the plan variable with the plan data-structure
;;;
;;; Bindings can include any predication that would have the effect of binding some variable
;;; But there is a simplified notation when you just want to bind a variable to the value
;;; indicated by a dotted-path.  In that case, you can just use a list of length 2
;;; with the variable coming first and the path second.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defparameter *all-attack-methods* nil)

(defmacro defattack-method (method-name &key to-achieve 
					     (input-state `(logic-variable-maker ,(intern (string-upcase "?input-state"))))
					     (output-state `(logic-variable-maker ,(intern (string-upcase "?output-state"))))
					     guards 
					     bindings
					     prerequisites
					     typing
					     plan
					     post-conditions
                                             outputs
					     )
  (let* ((plan-variable `(logic-variable-maker ,(gensym "?PLAN")))
         (real-head `(predication-maker '(achieve-goal ,to-achieve ,input-state  ,output-state ,plan-variable)))
         (rebuilt-plan-structure (rebuild-plan-structure plan input-state output-state))
         (early-typing nil)
         (late-typing nil)
         (bindings-for-typing nil)
         (bindings-for-bindings nil)
         (bindings-for-prereqs nil) 
         (bindings-for-post-conditions nil) 
         (bindings-for-plan nil)
         )
    ;; First find all implicit bindings i.e. things of the form ?foo.bar.baz and note where the first reference occurs
    ;; Also for each generate a new logic-variable-maker
    (multiple-value-bind (all-refs hidden-bindings-alist) (find-bindings prerequisites post-conditions typing plan bindings)
      ;; Now replace all these implicit references by the corresponding logic-variable-maker
      (multiple-value-setq (prerequisites post-conditions typing bindings plan)
        (substitute-all-hidden-variables prerequisites post-conditions typing bindings plan all-refs))
      ;; Pull out all typing that refers only to the inputs 
      ;; And then leave the rest as late-typing.
      ;; This makes the first category act as prerequisites because they will be the first thing checked.
      ;; The reason for constraining them to only refer to inputs is that the generate code is an [objec-type-of xxx yyy]
      ;; form and if xxx is an unbound variable, this will successively bind xxx to all possible objects of type yyy
      ;; which isn't what we intended for a typing statement.  This requires us to declare any variable in the to-achieve
      ;; form that won't be bound as an "output".  That's probably a good thing to do anyhow, rather than just have it in a comment.
      (setq early-typing (loop for type in typing 
                             for variable = (first type) 
                             if (and (eql variable :break) (loop for var in (rest (rest type)) thereis (mentioned-in var real-head)))
                             collect type
                             else when (and (mentioned-in? variable real-head) (not (member (logic-variable-maker-name variable) outputs :key #'logic-variable-maker-name)))
                             collect type))
      (setq late-typing (set-difference typing early-typing :test #'equal))
      (loop for (dotted-form lv) in (second (assoc 'prerequisites hidden-bindings-alist))
          do (push (ji:make-predication-maker `(value-of ,dotted-form ,lv)) bindings-for-prereqs))
      (loop for (dotted-form lv) in (second (assoc 'typing hidden-bindings-alist))
          do (push (ji:make-predication-maker `(value-of ,dotted-form ,lv)) bindings-for-typing))
      (loop for (dotted-form lv) in (second (assoc 'post-conditions hidden-bindings-alist))
          do (push (ji:make-predication-maker `(value-of ,dotted-form ,lv)) bindings-for-post-conditions))
      (loop for (dotted-form lv) in (second (assoc 'bindings hidden-bindings-alist))
          do (push (ji:make-predication-maker `(value-of ,dotted-form ,lv)) bindings-for-bindings))
      (loop for (dotted-form lv) in (second (assoc 'plan hidden-bindings-alist))
          do (push (ji:make-predication-maker `(value-of ,dotted-form ,lv)) bindings-for-plan))
      (destructuring-bind (goals-to-achieve plan-structure thing) (or rebuilt-plan-structure (list nil nil nil))
        (declare (ignore thing))
        (setq goals-to-achieve (substitute-hidden-variables goals-to-achieve all-refs)
              plan-structure (substitute-hidden-variables plan-structure all-refs))
        `(eval-when (:load-toplevel :execute)
           (pushnew ',method-name *all-attack-methods*)
           ;; Now generate the backward rule
           ;; Note that by this time, any dotted notation in a binding form
           ;; will have been removed so the process-bindings code can be simplified.
           (defrule ,method-name (:backward)
             then ,real-head
             if [and 
                 ,@(process-typing early-typing)
                 ,@(process-bindings bindings-for-bindings input-state)
                 ,@(process-bindings bindings-for-typing input-state)
                 ,@(process-bindings bindings input-state)
                 ,@(process-guards guards input-state)
                 ,@(process-typing late-typing)
                 ,@(process-bindings bindings-for-prereqs input-state)
                 ,@(process-prerequisites prerequisites input-state)
                 ,@(process-bindings bindings-for-plan input-state)
                 ,@goals-to-achieve
                 ;; I think these refer to the input state ???
                 ,@(process-bindings bindings-for-post-conditions input-state)
                 ,@(process-post-conditions post-conditions output-state)
                 ,@(when (null rebuilt-plan-structure)
                     `((unify ,input-state ,output-state)))
                 (unify ,plan-variable ,plan-structure)
                 ]))))))






;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Dealing with dotted notation 
;;; Expand into a binding of a new variable
;;; and replace all references
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; To do:
;;; Keep a list of all bindings and make sure you.
;;; don't make an entry if it's already there
;;; need to distinguish what you need to substitute vs
;;; what new bindings need to be introduced for each category

(defun find-bindings (prerequisites post-conditions typing plan bindings)
  (let ((bindings-by-set-type nil) (master-alist nil))
    (labels ((do-one (form set-type)
               (cond
                ((and (predication-maker-p form) (eql (predication-maker-predicate form) 'value-of))
                 (with-predication-maker-destructured (slot value) form
                   (declare (ignore slot))
                   (do-one value set-type)))
                ((predication-maker-p form)
                 (do-one (predication-maker-statement form) set-type))
                ((logic-variable-maker-p form)
                 (do-one (logic-variable-maker-name form) set-type))
                ((listp form)
                 (loop for token in form do (do-one token set-type)))
                ((and (symbolp form) (find #\. (string form) :test #'char-equal))
                 ;; master-alist holds bindings across everything to avoid duplication
                 ;; Bindings-By-Set-Type is an Alist set-typeed by the name of the set.  It only
                 ;; gets an entry if this was a new symbol
                 (let ((entry (assoc set-type bindings-by-set-type)))
                   (unless entry 
                     (setq entry (list set-type nil))
                     (push entry bindings-by-set-type))
                   (unless (member form master-alist :key #'first :test #'equal)
                     ;; it's a new symbol
                     (let ((pair (list form (ji:make-logic-variable-maker (make-name '?lv)))))
                       ;; add it to the master alist
                       (push pair master-alist)
                       ;; and to the alist of new entries for this set-type
                       (push pair (second entry)))))))))
      (Loop for prereq in prerequisites do (do-one prereq 'prerequisites))
      (loop for postcon in post-conditions do (do-one postcon 'post-conditions))
      (loop for type in typing do (do-one type 'typing))
      (loop for binding in bindings do (do-one binding 'bindings))
      (loop for plan-element in plan do (do-one plan-element 'plan))
      )
    (values master-alist bindings-by-set-type)))

;;; To do: Break out the inner routine so that it can be called from top-level 
;;; Goals-to-achieve and plan-structure need to be handled later rather than with the bulk of the rest

(defun substitute-hidden-variables (set-of-stuff reference-alist)
  (labels ((do-one (form)
             (cond
              ((and (predication-maker-p form) (eql (predication-maker-predicate form) 'value-of))
               (with-predication-maker-destructured (slot value) form
                 (ji:make-predication-maker 
                  (list (predication-maker-predicate form) 
                        (explode slot #\.)
                        (do-one value)))))
              ((predication-maker-p form)
               (ji:make-predication-maker 
                (loop for token in (predication-maker-statement form)
                    collect (do-one token))))
              ((and (logic-variable-maker-p form) (find #\. (string (logic-variable-maker-name form)) :test #'char-equal))
               (let* ((entry (assoc (logic-variable-maker-name form) reference-alist)))
                 (second entry)))
              ((logic-variable-maker-p form) form)
              ((listp form)
               (loop for token in form collect (do-one token)))
              ((and (symbolp form) (find #\. (string form) :test #'char-equal))
               (let* ((entry (assoc form reference-alist)))
                 (second entry)))
              (t form))))
    (do-one set-of-stuff)    
    ))

;;; Just a convenience for doing most of the substitutions all at once

(defun substitute-all-hidden-variables (prerequisites post-conditions typing bindings plan reference-alist)
  (values
   (substitute-hidden-variables prerequisites reference-alist)
   (substitute-hidden-variables post-conditions reference-alist)
   (substitute-hidden-variables typing reference-alist)
   (substitute-hidden-variables bindings reference-alist)
   (substitute-hidden-variables plan reference-alist)
   ))





;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Define-goal macro & achieve goal predicate
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defparameter *all-goals* nil)

(defmacro define-goal (name variables) 
  `(eval-when (:load-toplevel :execute :compile-toplevel)
     (pushnew ',name *all-goals*)
     (define-predicate ,name ,variables (ltms:ltms-predicate-model))))

(define-predicate achieve-goal (goal-to-achieve input-state output-state plan) (ltms:ltms-predicate-model))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Classes for building a structured-backpointered plan object
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defclass has-parent-mixin ()
  ((parent :accessor parent :initform nil :initarg :parent)))

(defclass has-plan-mixin ()
  ((plan :accessor plan :initform nil :initarg nil)))

(defclass has-arguments-mixin ()
  ((arguments :accessor arguments :initarg :arguments)))

(defclass action (has-parent-mixin has-arguments-mixin print-nicely-mixin)
  ((action-name :accessor action-name :initarg :action-name)
   (prior-state :accessor prior-state :initarg :prior-state)
   (next-state :accessor next-state :initarg :next-state)
   (is-on-solution-path? :accessor is-on-solution-path? :initform nil)
   ))

(defclass goal (has-parent-mixin has-plan-mixin has-arguments-mixin)
  ((goal-name :accessor goal-name :initform nil :initarg :goal-name))
  )

(defclass plan (has-parent-mixin)
  ((connective :accessor connective :Initform nil :initarg :connective)
   (steps :accessor steps :initform nil :initarg :steps)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Define-action macro and take-action predicate & link-action function
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

(define-predicate take-action (action-predicate input-state output-state action) (ltms:ltms-predicate-model))
(define-predicate action-taken (action input-state output-state) (ltms:ltms-predicate-model))
   
(defun link-action (name arguments prior-state next-state)
  (let ((action (make-instance 'action
                  :role-name name
		  :action-name name
		  :arguments arguments
		  :prior-state prior-state
		  :next-state next-state)))
    (setf (next-action prior-state) action
	  (prior-action next-state) action)
    action))

(defun process-new-outputs (variable-list)
  (loop for (lv form) in variable-list
      collect `(unify ,lv ,form)))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Define-action macro for declaratively definings actions
;;; in a PDDL like syntax
;;;
;;; Compiles the source form into a Joshua backward chaining rule
;;;
;;; Fix: Still needs to do the implicitly binding stuff in def-atttack-method
;;; 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defparameter *all-actions* nil)

(defmacro define-action (name variables &key bindings prerequisites post-conditions (define-predicate t) capecs outputs typing) 
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
           (jusification-mnemonic (intern (string-upcase (format nil "prerequisites-satisfied-~a" name))))
	   (state-logic-variables (make-logic-variables '(input-state output-state)))
	   (capec-statements (loop for (victim capec-num cve-variable) in capecs
                                 collect `(predication-maker '(vulnerable-to-capec ,victim ,capec-num ,cve-variable))))
           (early-typing (loop for type in typing for lv = (first type) when (mentioned-in lv logic-variables) collect lv))
           (late-typing (set-difference typing early-typing))
           (action-variable (first (make-logic-variables '(action)))))
      (destructuring-bind (input-state-variable output-state-variable) state-logic-variables
        `(eval-when (:compile-toplevel :load-toplevel :execute)
           (pushnew ',name *all-actions*)
           ,@(when define-predicate `((define-predicate ,name ,names (ltms:ltms-predicate-model))))
           (defrule ,rule-name (:backward)
             then [take-action [,name ,@logic-variables] ,@state-logic-variables ,action-variable]
             if [and ,@(process-typing early-typing) 
                     ,@(process-bindings bindings input-state-variable)
                     ,@(process-typing late-typing)
                     ,@(process-guards prerequisites input-state-variable)
                     ,@capec-statements
                     ;; so at this point we've checked that the prerequisites are satisfied
                     (prog1 t
                       (when (unbound-logic-variable-p ,output-state-variable)
                         (unify ,output-state-variable 
                                (intern-state (intern (string-upcase (gensym "state-"))) ,input-state-variable)))
                       (let* ((action-taken-pred (tell [action-taken [,name ,@logic-variables] ,input-state-variable ,output-state-variable]
                                                       :justification :none))
                              (justification (build-justification-from-backward-support ji::*backward-support*)))
                         (destructuring-bind (nothing true-stuff false-stuff unknown-stuff) justification
                           (declare (ignore nothing))
                           (justify action-taken-pred +true+ ',jusification-mnemonic true-stuff false-stuff unknown-stuff))
                         ,@(process-new-outputs outputs)
                         ,@(let* ((mnemonic (intern (string-upcase (format nil "action-taken-~A" name))))
                                  (justification-2 `(list ',mnemonic (list action-taken-pred))))
                             (process-post-conditions post-conditions output-state-variable justification-2)))
                     (unify ,action-variable (link-action ',name (list,@logic-variables) ,input-state-variable ,output-state-variable)))
                     ]))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Converting the list structured attack plan into a fully backpointered
;;; plan linking in the actions and states
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun structure-attack-plan (top-level)
  (labels ((make-goal (goal-element &optional parent)
	     (let ((goal-statement (getf goal-element :goal))
		   (sub-plan (getf goal-element :plan)))
	       ;; (format t "~%Working on goal ~a" goal-statement)
	       (destructuring-bind (goal-name . arguments) goal-statement
		 (let* ((goal-object (make-instance 'goal :goal-name goal-name :arguments arguments :parent parent))
			(plan-object (make-plan sub-plan goal-object)))
		   (setf (plan goal-object) plan-object)
		   goal-object))))
	   (make-plan (plan-element parent)
	     (let ((connective (first plan-element))
		   (steps (rest plan-element)))
	       ;; (format t "~%For goal ~a with connective ~a there are ~a steps" parent connective (length steps))
	       (let* ((plan-object (make-instance 'plan
				  :connective connective
				  :parent parent))
		      (the-steps (loop for step in steps
				     for type = (first step)
				     for step-object = (case type
							 (:goal (make-goal step plan-object))
							 (:action (make-action step plan-object)))
				     ;; do (format t "~%For type ~a step ~a" type step-object)
				     collect step-object)))
		 ;; (format t "~%Steps for plan ~a ~{~a~^, ~}" plan-object the-steps)
		 (setf (steps plan-object) the-steps)
		 plan-object)))
	   (make-action (step parent)
	     (destructuring-bind (head list-version actual-action) step
	       (declare (ignore head list-version))
	       (setf (parent actual-action) parent)
	       actual-action)))
    (make-goal top-level)))