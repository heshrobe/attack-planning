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
   )
  )

(defun do-it (&key (attacker (follow-path '(typical-attacker)))
		   (attacker-machine (follow-path '(typical-attacker-machine)))
                   (property 'performance) 
		   (machine 'dopey) 
                   (resource (follow-path '(typical-dopey-process))))
  (let ((answers nil)
	(starting-context (make-initial-search-context
			    :attacker attacker
			    :attacker-machine attacker-machine))
	;; (os (follow-path `(,machine os)))
	)
    (ask `[affect ,property ,resource ,starting-context ?output-context ?plan]
         #'(lambda (just)
             (declare (ignore just))
	     (let ((plan (copy-object-if-necessary ?plan)))
	       (pushnew (list :goal (list 'affect attacker property resource machine)
			      :plan plan)
			answers
			:test #'equal))))
    answers))

(defun create-attacker (name &key world-name)
  (with-atomic-action
      (kill-redefined-object name)
    (let ((machine-name (intern (string-upcase (format nil "~a-machine" name)))))
      (kill-redefined-object machine-name)
      (let* ((attacker (make-object 'attacker :name name))
	     (the-world (follow-path (list world-name)))
	     (his-machine (make-object 'attacker-computer :name machine-name
				       :typical-p t
				       )))
	(tell `[ltms:value-of (,attacker world) ,the-world])
	(tell `[ltms:value-of (,attacker machines) ,his-machine])
	(tell `[uses-machine ,attacker ,his-machine])
	(tell `[ltms:value-of (,his-machine subnets) ,the-world])
	(tell `[ltms:value-of (,the-world computers) ,his-machine])
	(tell `[ltms:value-of (,attacker location) ,the-world])
	attacker))))

(defun do-a-case (environment-pathname  &key attacker 
					     property 
					     machine 
					     resource)
  (clear)
  (load environment-pathname)
  (let* ((attacker (follow-path (list attacker)))
	 (attacker-machine (first (follow-path (list attacker 'machines))))
	 (machine (follow-path (list machine)))
	 (resource (follow-path (list machine resource))))
    (let* ((answers (do-it :attacker attacker
			   :attacker-machine attacker-machine
			   :Property property
			   :machine machine
			   :resource resource))
	   (collector (make-instance 'attack-plan-collector))
	   )
      (setf (attack-plans collector) answers
	    (merged-attack-plan collector)  (merge-attack-plans answers))
      collector
      )))

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
    (labels ((intern-goal (name)
               (let ((goal (gethash name goal-hash-table)))
                 (unless goal
                   (setq goal (make-instance 'attack-goal :name name))
                   (setf (gethash name goal-hash-table) goal))
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
		      (intern-plan type steps supergoal)))))))
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