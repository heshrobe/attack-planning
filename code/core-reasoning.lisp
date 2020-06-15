;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*-

(in-package :aplan)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Top Level Query
;;; Find a plan(s) to affect a desirable property of some system
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defclass attack-plan-collector ()
  ((attack-plans :initform nil :accessor attack-plans)
   (merged-attack-plan :initform nil :accessor merged-attack-plan)
   (final-states :accessor final-states :initform nil :initarg :final-states)
   (Initial-state :accessor Initial-state :initform nil :initarg :Initial-state)
   )
  )

(defmethod all-action-sequences ((collector attack-plan-collector))
  (loop for s in (final-states collector)
      collect (action-sequence s)))

(defun do-it (&key (attacker (follow-path '(typical-attacker)))
                   (property 'performance) 
		   machine 
                   resource)
  (clear-all-states)
  (let ((plans nil)
	(final-states nil))
    ;; (os (follow-path `(,machine os)))
    (unwind-protect
	(ask `[achieve-goal [affect ,property ,resource] ,(intern-state 'initial) ?output-context ?plan]
	     #'(lambda (just)
		 (declare (ignore just))
		 (let* ((plan (copy-object-if-necessary ?plan))
			(final-structure (list :goal (list 'affect attacker property resource machine)
					       :plan plan)))
		   (unless (member final-structure plans :test #'plan-equal)
		     (mark-state-useful ?output-context)
		     (Pushnew ?output-context final-states)
		     (push final-structure plans)))))      
      (clear-useless-states))
    ;; This links the objects to a tree-structured set
    ;; of objects representing the plan with the 
    ;; actions at the leaves
    (loop for plan in plans do (structure-attack-plan plan))
    (values plans final-states)))

(defun plan-equal (thing1 thing2)
  (plan-step-equal (first thing1) (first thing2) (rest thing1) (rest thing2)))

(defgeneric plan-step-equal (head1 head2 step1 step2))

;;; Default method fails
(defmethod plan-step-equal ((head1 t) (head2 t) (plan1 t) (plan2 t)) nil)

;;; (:goal <goal> :plan (<steps>))
(defmethod plan-step-equal ((head1 (eql :goal)) (head2 (eql :goal)) step1 step2)
  (destructuring-bind (goal1 . plist1) step1
    (destructuring-bind (goal2 . plist2) step2
      ;; (format t "~%Checking goal ~a ~a" goal1 goal2)
      (and (equal goal1 goal2)
	   (plan-equal plist1 plist2)))))

;;; (:plan (<connective> (<goals-or-actions>)))
(defmethod plan-step-equal ((head1 (eql :plan)) (head2 (eql :plan)) step1 step2)
  ;; Here the step is a list of the connective followed by substeps
  ;; Check that it's actually a cons before popping
  ;; probably not necessary because it's already decided that 
  ;; its a plan structure
  (destructuring-bind ((keyword1 . rest1)) step1
    (destructuring-bind ((keyword2 . rest2)) step2
      ;; (format t "~%Checking plan ~a ~a" keyword1 keyword2)
      (and (equal keyword1 keyword2)
	   (loop for thing1 in rest1
	       for thing2 in rest2
	       always (plan-equal thing1 thing2))))))

;;; (:action action-predicate action-object)
(defmethod plan-step-equal ((head1 (eql :action)) (head2 (eql :action)) step1 step2)
  ;; (format t "~%Checking action ~a ~a" (first step1) (first step2))
  (equal (first step1) (first step2)))
		       



(defun make-attacker-computer (name attacker &key location (typical? t))
  (kill-redefined-object name)
  (let ((his-computer (make-object 'attacker-computer
			       :name name
			       :typical-p typical?)))
    (tell `[value-of (,attacker machines) ,his-computer])
    (tell `[uses-machine ,attacker ,his-computer])
    (when location
      (tell `[value-of (,location computers) ,his-computer]) 
      (tell `[value-of (,his-computer subnets) ,location]))
    his-computer))
    

(defmacro define-attacker (name &key location 
				     (computer nil computer-p) 
				     (other-computers nil other-computers-p)
				     (download-servers nil download-servers-p)
				     (adware-servers nil adware-servers-p)
				     )
  `(create-attacker ',name
		    :location (follow-path (list ',location))
		    :other-computers ,(when other-computers-p 
					`(list ,@(loop for name in other-computers
						     collect `(follow-path (list ',name)))))
		    :adware-servers ,(when adware-servers-p
				      (if (symbolp adware-servers)
					  `', adware-servers
					`(list ,@(loop for name in adware-servers
						     collect `(follow-path (list ',name))))))
		    :download-servers ,(when download-servers-p
					 (if (symbolp download-servers)
					   `', download-servers
					   `(list ,@(loop for name in download-servers
						      collect `(follow-path (list ',name))))))
		    :computer ,(when computer-p `(follow-path (list ',computer)))))

(defun create-attacker (attacker-name &key location computer other-computers download-servers adware-servers)
  (with-atomic-action
   (let ((created-computer-name (intern (string-upcase (format nil "~a-computer" attacker-name)))))
     (kill-redefined-object attacker-name)
     (let* ((attacker (make-object 'attacker :name attacker-name))
	    (his-computer (or computer 
			      (make-attacker-computer created-computer-name attacker
						      :location location))))
       (tell `[value-of (,attacker location) ,location])
       (loop for computer in other-computers
	   do (tell `[uses-machine ,attacker ,computer]))
       (if (symbolp download-servers)
	   (let ((attacker-computer (make-attacker-computer download-servers attacker :location location)))
	     (tell `[attacker-download-server ,attacker ,attacker-computer]))
	 (loop for computer in download-servers
	     do (tell `[attacker-download-server ,attacker ,computer])))
       (if (symbolp adware-servers)
	   (let ((attacker-computer (make-attacker-computer adware-servers attacker :location location)))
	     (tell `[attacker-adware-server ,attacker ,attacker-computer]))
	 (loop for computer in adware-servers
	     do (tell `[attacker-adware-server ,attacker ,computer])))
       ;; has foothold always has a victim in it.  But in this initial state
       ;; there isn't one.  It's just a starting point.
       (tell `[in-state [has-foothold nil ,his-computer ,attacker foothold] initial])
       (tell `[in-state [attacker-and-machine ,attacker ,his-computer] initial])
       attacker))))

(defun do-a-case (environment-pathname  &key attacker 
					     property 
					     machine 
					     resource)
  (clear)
  (load environment-pathname)
  (let* ((attacker (follow-path (list attacker)))
	 ;; (attacker-machine (first (follow-path (list attacker 'machines))))
	 (machine (follow-path (list machine)))
	 (resource (follow-path (list resource))))
    (multiple-value-bind (answers final-states)
	(do-it :attacker attacker
	       ;; :attacker-machine attacker-machine
	       :Property property
	       :machine machine
	       :resource resource)
      (let ((collector (make-instance 'attack-plan-collector)))
	(setf (attack-plans collector) answers
	      (merged-attack-plan collector)  (merge-attack-plans answers)
	      (final-states collector) final-states
	      (initial-state collector) *initial-state*)
      collector
      ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Core Data Structures
;;;'
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defparameter *json-id-counter* 0)

(defun reset-json-counter () (setq *json-id-counter* 0))

(defun get-json-id (prefix)
  (intern (format nil "~a-~d" (string-upcase (string prefix)) (incf *json-id-counter*)))
  )

(defclass json-id-mixin ()
  ((json-id :accessor json-id :Initarg :json-id))
  )

(defmethod initialize-instance :after ((thing json-id-mixin) &key &allow-other-keys)
  (setf (json-id thing) (get-json-id (json-id-key thing))))

(defclass attack-goal (json-id-mixin)
  ((name :initform nil :accessor goal-name :initarg :name)
   (supporting-plans :initform nil :accessor supporting-plans :initarg :supporting-plans)
   (supported-plans :initform nil :accessor supported-plans :initarg :suported-plans)))

(defmethod print-object ((object attack-goal) stream)
  (format stream "#<goal ~a>" (goal-name object)))

(defmethod json-id-key ((thing attack-goal)) 'goal)

(defclass attack-action (json-id-mixin)
  ((name :initform nil :accessor action-name :initarg :name)
   (supported-plans :initform nil :accessor supported-plans :initarg :suported-plans)))

(defmethod json-id-key ((thing attack-action)) 'action)

(defclass repeated-attack-action (attack-action)
  ()
  )

(defmethod print-object ((object attack-action) stream)
  (format stream "#<Action ~a>" (action-name object)))

(defmethod print-object ((object repeated-attack-action) stream)
  (format stream "#<Repeated-Action ~a>" (action-name object)))

(defclass attack-plan (json-id-mixin)
  ((supergoal :initform nil :accessor supergoal :initarg :supergoal)
   (combinator :initform nil :accessor combinator :initarg :combinator)
   (steps :initform nil :accessor steps :initarg :steps)
   (subgoals :initform nil :accessor subgoals :initarg :subgoals)
   (actions :initform nil :accessor actions :initarg :actions)
   ))

(defmethod json-id-key ((thing attack-plan)) 'plan)

(defclass plan-or-node (json-id-mixin)
  ((supporting-plans :initform nil :initarg :supporting-plans :accessor supporting-plans)))

(defmethod json-id-key ((thing plan-or-node)) 'or)



(defun merge-attack-plans (raw-plans)
  (let ((goal-hash-table (make-hash-table :test #'equal))
        (action-hash-table (make-hash-table :test #'equal))
        (interned-plans nil))
    (reset-json-counter)
    (labels ((intern-goal (goal-statement)
               (let* ((goal-without-contexts goal-statement)
		      (goal (gethash goal-without-contexts goal-hash-table)))
                 (unless goal
                   (setq goal (make-instance 'attack-goal :name goal-without-contexts))
                   (setf (gethash goal-without-contexts goal-hash-table) goal))
                 goal))
             (intern-action (name repeated?)
               (let ((action (gethash name action-hash-table)))
                 (unless action
                   (setq action (make-instance (if repeated? 'repeated-attack-action 'attack-action) :name name))
                   (setf (gethash name action-hash-table) action))
                 action))
             (intern-plan (combinator steps supergoal)
               (let ((the-plan (loop for plan in interned-plans
				   when (and 
					 (eql (combinator plan) combinator)
					 (null (set-exclusive-or (steps plan) steps)))
				   do (return plan))))
                 (unless the-plan
                   (setq the-plan (make-instance 'attack-plan
				    :combinator combinator
				    :steps steps
				    :subgoals (loop for step in steps when (typep step 'attack-goal) collect step)
				    :actions (loop for step in steps when (typep step 'attack-action) collect step)))
                   (push the-plan interned-plans))
                 (loop for goal in (subgoals the-plan) do (pushnew the-plan (supported-plans goal)))
                 (loop for action in (actions the-plan) do (pushnew the-plan (supported-plans action)))
                 (when supergoal
                   (setf (supergoal the-plan) supergoal)
                   (pushnew the-plan (supporting-plans supergoal)))
                 the-plan))
             (traverse (step supergoal)
	       (let ((type (first step)))
		 (case type
		   (:goal (let ((the-interned-goal (intern-goal (second step))))
			    (let ((his-plan (getf step :plan)))
			      (traverse his-plan the-interned-goal))
			    the-interned-goal))
		   ((:action :repeated-action) (intern-action (second step) (eq type :repeated-action)))
		   ((:sequential :parallel :singleton)
		    (let ((steps (loop for his-step in (rest step)
				     collect (traverse his-step supergoal))))
		      (intern-plan type steps supergoal)))
		   (:otherwise (break "What is this ~a" step))
		   ))))
      (loop for raw-plan in raw-plans 
	  for goal = (intern-goal (getf raw-plan :goal))
	  for plan = (getf raw-plan :plan)
	  do (traverse plan goal)))
    ;; Insert OR-nodes for goals with multiple supporting plans
    (loop for goal being the hash-values of goal-hash-table
	for supporting-plans = (supporting-plans goal)
	when (not (null (rest supporting-plans)))
	do (setf (supporting-plans goal)
	     (list (make-instance 'plan-or-node :supporting-plans supporting-plans))))
    (loop for plan in interned-plans for super-goal = (supergoal plan) when (null super-goal) do (break "Bad Plan ~a" plan))
    (values (loop for goal being the hash-values of goal-hash-table
		when  (loop for supported-plan in (supported-plans goal) always (null (supergoal supported-plan)))
		collect goal)
            interned-plans
	    (loop for action being the hash-values of action-hash-table
		collect action))))

(defun clean-up-plan (top-level-goals)
  (let ((number-of-merges 0) (number-of-goal-action-merges 0)
        (something-happened nil))
    (labels ((do-one-goal (goal)
               (loop with (mergeable-subgoals mergeable-actions)
                     do (multiple-value-setq (mergeable-subgoals mergeable-actions) (is-mergeable goal))
                     when mergeable-subgoals
                     do (merge-goals goal mergeable-subgoals)
                        (setq something-happened t)
                        (incf number-of-merges)
                     when mergeable-actions
                     do (loop for action in mergeable-actions
                              do (merge-goal-and-action goal action)
                                 (incf number-of-goal-action-merges))
                        (setq something-happened t)
                        (return-from do-one-goal)
                     until (null mergeable-subgoals))
               (loop for plan in (supporting-plans goal)
                     do (loop for subgoal in (subgoals plan)
                              do (do-one-goal subgoal))))
             (make-a-pass ()
               (loop for goal in top-level-goals
                     do (do-one-goal goal))))
      (loop doing 
            (setq something-happened nil)
            (make-a-pass)
            Until (null something-happened)))
    (values number-of-merges number-of-goal-action-merges)))

;;; Fix: This breaks when hitting a Plan-Or-Node
;;; because that doesn't have sub-goal
(defmethod is-mergeable ((goal attack-goal))
  (let* ((mergeable-subgoals nil) (sub-actions nil) 
         (subplans (supporting-plans goal))
         (single-subplan (when (null (cdr subplans)) (first subplans)))
         (single-subplan-without-subgoals (and single-subplan (null (subgoals single-subplan)))))
    (loop for plan in subplans
          for subgoals = (subgoals plan)
          for (first-subgoal . remaining-subgoals) = subgoals
          for actions = (actions plan)
          when (and first-subgoal (null remaining-subgoals) (null actions))
          do (push first-subgoal mergeable-subgoals)
          when actions do (setq sub-actions t)
         )
    (cond 
     ((and mergeable-subgoals (null sub-actions)) 
      (values mergeable-subgoals nil))
     ((and single-subplan-without-subgoals
           (null (cdr (actions single-subplan))))
      (values nil (actions (first subplans))))
     ;; single subplan with multiple actions no subgoals single superplan
     ((and single-subplan-without-subgoals
           ;; only support one thing
           (null (cdr (supported-plans goal)))
           ;; no subgoals
           )
      (values nil (actions (first subplans)))))))

(defmethod merge-goals (parent children)
  (let ((all-supporting-plans nil))
    (loop for child in children
          do (loop for support in (supporting-plans child)
                   do (pushnew support all-supporting-plans)))
    (setf (supporting-plans parent)
          all-supporting-plans)))

(defmethod merge-goal-and-action ((goal attack-goal) (action attack-action))
  (loop for parent in (supported-plans goal)
        do (setf (subgoals parent) (delete goal (subgoals parent)))
           (pushnew action (actions parent))
           (pushnew parent (supported-plans action))))
