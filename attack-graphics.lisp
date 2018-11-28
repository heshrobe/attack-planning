;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*-

(in-package :aplan)

(defun graph-an-attack-plan (plan &optional (stream *standard-output*) (orientation :vertical) (text-size :very-small) (action-only nil))
  (let ((*print-object-nicely* t))
    (declare (special *print-object-nicely*))
    (clim:with-text-size (stream :small)
    (clim:format-graph-from-root
     plan
     #'(lambda (step stream) (print-plan-object step stream text-size))
     (if action-only #'plan-inferior-action-only #'plan-inferior)
     :stream stream
     :merge-duplicates t
     :orientation orientation
     :arc-drawer #'(lambda (stream from-object to-object x1 y1 x2 y2 &rest drawing-options)
                     (declare (ignore from-object to-object))
                     (apply #'clim:draw-arrow* stream x1 y1 x2 y2 :from-head t :to-head nil 
                            :ink clim:+blue+ drawing-options))))))

(defun print-plan-object (step stream &optional (text-size :very-small))
  (clim:with-text-size (stream text-size)
    (clim:with-drawing-options (stream :line-thickness 2)
      (let ((connective (first step)))
        (case connective
	  ((:sequential :parallel)
	   (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+green+)
	     (clim:with-text-face (stream :bold)
	       (format stream "~A" (first step)))))
	  (:singleton
	   (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+green+)
	     (clim:with-text-face (stream :bold)
	       (format stream "reduces to"))))
          (:goal (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+blue+)
                   (destructuring-bind (goal-type &rest rest) (second step)
		     ;; total hack to reduce space consumption
		     (let* ((arglist (ji::find-predicate-arglist goal-type))
			    (path-so-far-position (position 'path-so-far arglist)))
		       (when path-so-far-position
			 (setq rest (loop for i from 0
					for name in rest
					unless (= i path-so-far-position)
					       collect name))))
                     (format stream "Goal: ~A~%~{~a~^~%~}" goal-type rest))))
          ((:action :repeated-action)
	   (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+red+)
	     (clim:with-text-face (stream :bold)
	       (destructuring-bind (action-type &rest rest) (second step)
		 (format stream "~:[Do:~;Repeatedly:~] ~A~%~{~a~^~%~}" (eql connective :repeated-action) action-type rest))))))))))

(defun plan-inferior (step)
  (case (first step)
    ((:sequential :parallel :singleton)
     (rest step))
    (:goal (let ((plan (getf step :plan)))
	     (when plan
             (list plan))))
    ((:action :repeated-action) nil)))

;;; Fix if possible: There must be a simpler way to construct this recursion
(defun plan-inferior-action-only (step)
  (labels ((collect-actions-below (step)
	     (case (first step)
	       ((:sequential :parallel)
		(loop for thing in (rest step)
		    append (if (member (first thing) '(:action :repeated-action :sequential :parallel))
			       (list thing)
			     (collect-actions-below thing))))
	       (:singleton (collect-actions-below (second step)))
	       (:goal (let ((plan (getf step :plan)))
			(when plan
			  (case (first plan)
			    (:singleton 
			     (if (member (first (second plan)) '(:action :repeated-action))
				 (rest plan)
			       (collect-actions-below (second plan))))
			    ((:sequential :parallel :action :repeated-action)
			     (list plan))
			    (otherwise (break "~a" plan))
			    ))))
	       ((:action :repeated-action) nil))))
    (collect-actions-below step)
    ))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (clim:define-presentation-type computer ()))

(clim:define-presentation-method clim:accept ((type computer) stream (view clim:textual-view) &key)
  (let ((answers nil))
    (ask [ltms:object-type-of ?m computer]
         #'(lambda (just)
             (declare (ignore just))
             (pushnew ?m answers)))
    (clim:completing-from-suggestions (stream :partial-completers '(#\-))
      (loop for m in answers
            do (clim:suggest (string (role-name m)) m)))
    ))

(clim:define-presentation-method clim:present (item (type computer) stream  (view clim:textual-view) &key)
  (write-string (string (role-name item)) stream))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (clim:define-presentation-type desirable-property ()))

(clim:define-presentation-method clim:present (object (type desirable-property) stream (view clim:textual-view) &key)
  (write-string (string object) stream))

(clim:define-presentation-method clim:accept ((type desirable-property) stream (view clim:textual-view) &key)
  (let ((answers nil)) 
    (ask [desirable-property-of ? ?property]
         #'(lambda (just)
             (declare (ignore just))
             (pushnew ?property answers)))
    (clim:completing-from-suggestions (stream :partial-completers '(#\-))
      (loop for property in answers
            do (clim:suggest (string property) property)))))


(eval-when (:compile-toplevel :load-toplevel :execute)
  (clim:define-presentation-type computer-resource (computer)))

(defun resources-on-machine (machine)
  (let ((answers nil))
    (ask `[ltms:value-of (,machine resources) ?resource]
         #'(lambda (just)
             (declare (ignore just))
             (pushnew ?resource answers)))
    answers))

(clim:define-presentation-method clim:accept ((type computer-resource) stream (view clim:textual-view) &key)
  (let ((machine (clim:with-presentation-type-parameters (computer-resource type) (values computer))))
    (let ((answers (resources-on-machine machine)))
      (clim:completing-from-suggestions (stream :partial-completers '(#\-))
        (loop for resource in answers
              do (clim:suggest (string (role-name resource)) resource))))))

(clim:define-presentation-method clim:present (item (type computer-resource) stream  (view clim:textual-view) &key)
  (write-string (string (role-name item)) stream))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (clim:define-presentation-type attacker ()))

(clim:define-presentation-method clim:accept ((type attacker) stream (view clim:textual-view) &key)
  (let ((answers nil))
    (ask [ltms:object-type-of ?m attacker]
         #'(lambda (just)
             (declare (ignore just))
             (pushnew ?m answers)))
    (clim:completing-from-suggestions (stream :partial-completers '(#\-))
      (loop for m in answers
            do (clim:suggest (string (role-name m)) m)))
    ))

(clim:define-presentation-method clim:present (item (type attacker) stream  (view clim:textual-view) &key)
  (write-string (string (role-name item)) stream))

(define-aplan-command (com-load-model :name t :menu t)
    ((pathname 'clim:pathname))
  (clear)
  ;; clear makes the current version of *everywhere* invalid
  ;; by removing its parts.
  (setq *everywhere* (make-everywhere))
  (ji:with-joshua-readtable 
      (load pathname)))

(define-aplan-command (com-find-plans :name t :menu t)
    ((computer 'computer)
     (property 'desirable-property :default 'performance)
     (resource `(computer-resource ,computer))
     &key (attacker 'attacker :default (follow-path '(typical-attacker))))
  (let ((answers (do-it :property property :machine computer :attacker attacker :resource resource)))
    (let ((stream (clim:get-frame-pane clim:*application-frame* 'attack-structure )))
      (clim:with-text-face (stream :bold)
	(clim:with-text-size (stream :large)
	  (format stream "~%There are ~d plans" (length answers)))))
    (setf (attack-plans clim:*application-frame*) answers
          (merged-attack-plan clim:*application-frame*) (merge-attack-plans answers))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Top Level Query
;;; Find a plan(s) to affect a desirable property of some system
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun do-it (&key (attacker (follow-path '(typical-attacker)))
                   (property 'performance) 
		   (machine 'dopey) 
                   (resource (follow-path '(typical-dopey-process))))
  (let ((answers nil)
	;; (os (follow-path `(,machine os)))
	)
    (ask `[affect ,attacker ,property ,resource ?plan]
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
				       :typical t
				       )))
	(tell `[ltms:value-of (,attacker world) ,the-world])
	(tell `[ltms:value-of (,attacker machines) ,his-machine])
	(tell `[uses-machine ,attacker ,his-machine])
	(tell `[ltms:value-of (,his-machine subnets) ,the-world])
	(tell `[ltms:value-of (,the-world computers) ,his-machine])
	(tell `[ltms:value-of (,attacker location) ,the-world])
	attacker))))

(define-aplan-command (com-show-plan :name t :menu t)
    ((which 'integer) 
     &key (orientation '(clim:member-alist (("horizontal" . :horizontal) ("vertical" . :vertical))) :default :vertical)
     (pdf? 'clim:boolean :default nil :prompt "Generate to a pdf file")
     (file-name 'clim:pathname)
     (text-size '(clim:member :very-small :small :normal :large :very-large))
     (actions-only 'clim:boolean :default nil :prompt "Only show actions?")
     )
  (let ((plan (nth which (attack-plans clim:*application-frame*))))
    (terpri)
    (when plan
      (flet ((body (stream)
               (clim:with-text-face (stream :bold)
                 (clim:with-text-size (stream text-size)
                   (format stream "~%Attack Plan ~d~%" which)
                   (graph-an-attack-plan plan stream orientation text-size actions-only))))
	     (make-file-name-of-type (file-name type)
	       (merge-pathnames (make-pathname :type type) file-name)))
        (cond
	 (pdf?
	  (let* ((ps-pathname (make-file-name-of-type file-name "ps"))
		 (pdf-pathname (make-file-name-of-type file-name "pdf"))
		 (command (format nil "pstopdf ~a -o ~a" ps-pathname pdf-pathname)))
	    (with-open-file (file ps-pathname :direction :output :if-exists :supersede)
	      (clim:with-output-to-postscript-stream (stream file)
		(body stream)))
	    #+Allegro
	    (excl:run-shell-command command :wait t)
	    #+sbcl
	    (uiop:run-program command)
	    (delete-file ps-pathname)))
	 (t
          (let ((stream (clim:get-frame-pane clim:*application-frame* 'attack-structure)))
            (multiple-value-bind (x y) (clim:stream-cursor-position stream)
              (clim:stream-set-cursor-position stream x (+ y 10))
              (setf (clim:window-viewport-position stream) (values x (+ y 10))))
            (body stream))))
        (terpri)))))

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

;;; What this does:
;;; 1) Unique-izes goals
;;; 2) Unique-izes actions
;;; 3) unique-izes plans
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
                       
(defun graph-merged-plans (top-level-goals &optional stream (direction :vertical) (text-size :very-small))
  (let ((*print-object-nicely* t))
    (clim:with-text-size (stream text-size)
      (clim:format-graph-from-roots
       top-level-goals
       #'print-merged-plan-object
       #'merged-plan-inferior
       :merge-duplicates t
       :maximize-generations nil
       :center-nodes t
       :generation-separation 15
       :within-generation-separation 10
       :stream stream
       :orientation direction
       :arc-drawer #'(lambda (stream from-object to-object x1 y1 x2 y2 &rest drawing-options)
		       (declare (ignore from-object to-object))
		       (apply #'clim:draw-arrow* stream x1 y1 x2 y2 :from-head t :to-head nil 
			      :ink clim:+blue+ drawing-options))))))

(defmethod print-merged-plan-object ((goal attack-goal) stream)
    (clim:with-drawing-options (stream :line-thickness 2)
      (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+blue+)
        (destructuring-bind (goal-type &rest rest) (goal-name goal)
          (format stream "~&Goal: ~A~%~{ ~a~^~%~}" goal-type rest)))))

(defmethod print-merged-plan-object ((action attack-action) stream)
    (clim:with-drawing-options (stream :line-thickness 2)
      (clim:surrounding-output-with-border (stream :shape :rectangle :ink clim:+red+)
        (clim:with-text-face (stream :bold)
          (destructuring-bind (action-type &rest rest) (action-name action)
            (format stream "~&~:[Do:~;Repeatedly~] ~A~%~{~a~^~%~}" 
		    (typep action 'repeated-attack-action)
		    action-type rest))))))

(defmethod print-merged-plan-object ((plan attack-plan) stream)
  (clim:with-drawing-options (stream :line-thickness 2)
    (clim:surrounding-output-with-border (stream :shape :oval :ink clim:+green+)
      (clim:with-text-face (stream :bold)
	(let ((combinator (combinator plan)))
	  (format stream "~a" (case combinator
				((:sequential :parallel) combinator)
				(:singleton :reduces-to))))
        ))))

(defmethod print-merged-plan-object ((or-node plan-or-node) stream)
  (clim:with-drawing-options (stream :line-thickness 2)
    (clim:surrounding-output-with-border (stream :shape :oval :ink clim:+green+)
      (clim:with-text-face (stream :bold)
      (format stream "~&OR")))))


(defmethod merged-plan-inferior ((goal attack-goal)) (supporting-plans goal))

(defmethod merged-plan-inferior ((plan attack-plan)) (steps plan))

(defmethod merged-plan-inferior ((action attack-action)) nil)

(defmethod merged-plan-inferior ((or-node plan-or-node)) (supporting-plans or-node))

(define-aplan-command (com-show-merged-plans :name t :menu t)
    (&key (direction '(member :horizontal :vertical) :default :vertical)
	  (text-size '(member :small :very-small :normal :large) :default :very-small)
	  (pdf? 'clim:boolean :default nil :prompt "Generate to a pdf file")
	  (file-name 'clim:pathname))
  (flet ((body (stream)
	   (terpri)
	   (let ((goals (merged-attack-plan clim:*application-frame*)))
	     (clim:with-text-size (stream :large)
	       (format stream "~%Merged Plans ~%"))
	     (clim:with-text-size (stream :small)
	       (graph-merged-plans goals stream direction text-size))
	     (terpri)))
	 (make-pathname-with-type (pathname type)
	   (merge-pathnames (make-pathname :type type) pathname)))
    (cond
     (pdf?
      (let* ((ps-pathname (make-pathname-with-type file-name "ps"))
	     (pdf-pathname (make-pathname-with-type file-name "pdf"))
	     (command (format nil "pstopdf ~a -o ~a" ps-pathname pdf-pathname)))
      (with-open-file (file ps-pathname :direction :output :if-exists :supersede)
	(clim:with-output-to-postscript-stream (stream file)
	  (body stream)
	  ))
      #+Allegro
      (excl:run-shell-command command :wait t)
      #+sbcl
      (uiop:run-program command)
      (delete-file ps-pathname)))
     (t
      (let ((stream (clim:get-frame-pane clim:*application-frame* 'attack-structure)))
	(multiple-value-bind (x y) (clim:stream-cursor-position stream)
	  (clim:stream-set-cursor-position stream x (+ y 10))
	  (setf (clim:window-viewport-position stream) (values x (+ y 10))))
	(body stream))))))




;;; surgery on merged plans

;; A goal all of whose supporting plans support only this goal
;; which must be true by definition
;; and for each supporting plan they have a unique subgoal which only supports the plan 
;; then the goal and all the subgoals of the subplans may be merged 

(define-aplan-command (com-simplify-merged-plan :name t :menu t)
                    ()
  (clean-up-plan (merged-attack-plan clim:*application-frame*)))


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

(define-aplan-command (com-clear-screen :name t :menu t)
    ()
  (clim:window-clear (clim:get-frame-pane clim:*application-frame* 'attack-structure)))

(define-aplan-command (com-clear-model :name t :menu t)
    ()
  (clear))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; JSON Dumping
;;;
;;; Every element of a merged attack plan has a slot called json-id
;;; So dumping to JSON format involves two steps
;;; 1) Open a Json Object.  This will have two key-value pairs: Nodes and Edges
;;; 2) For the value of Nodes, open a JSON array. Map over the attack graph for each node, open
;;;    a JSON object.  Dump the pair consisting of unique-id and the json-id
;;;    Then dump whatever other key-value pairs are relevant to the node.
;;;    For goal nodes this involves doing pretty much what the print method does
;;;    but in JSON format
;;; 3) For the value of Edges, Open a Json array.  Map over the attack graph,
;;;    for any node that points to something else for each pointer open an object
;;;    with key the json-id of the node and value the json id of the destination
;;;
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

(define-aplan-command (com-dump-merged-plans-to-json :name t :menu t)
    (&key (file-name 'clim:pathname))
  (let ((goals (merged-attack-plan clim:*application-frame*)))
    (dump-plan-to-file goals file-name)
    ))


(defun dump-plan (root-node &optional (stream *standard-output*))
  (json:with-object (stream) 
    (terpri stream)
    (json:as-object-member ('nodes stream) (dump-nodes root-node stream))
    (terpri stream)
    (json:as-object-member ('links stream) (dump-links root-node stream))))

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
    (let ((predicate-args (ji::find-predicate-arglist goal-type))
	  (unique-id (json-id node)))
      (setq predicate-args (append (butlast predicate-args) (list 'machine)))
      (terpri stream)
      (json:with-object (stream)
	(json:encode-object-member 'id unique-id stream)
	(terpri stream)
	(json:encode-object-member 'type 'goal stream)
	(terpri stream)
	(json:encode-object-member 'goal goal-type stream)
	(loop for key in predicate-args
	    for value in values
	    for value-token = (If (symbolp value) value (role-name value))
	    if (eql key 'resource-or-component) do (setq key 'thing)
	    do (terpri stream)
	       (json:encode-object-member key value-token stream))))))

(defmethod dump-node ((node attack-action) &optional (stream *standard-output*))
  (destructuring-bind (action-type &rest values) (action-name node)
    (let ((predicate-args (gethash action-type *action-table*))
	  (unique-id (json-id node)))
      (terpri stream)
      (json:with-object (stream)
	(json:encode-object-member 'id unique-id stream)
	(terpri stream)
	(json:encode-object-member 'type (typecase node (repeated-attack-action 'repeated-action) (otherwise 'action)) stream)
	(terpri stream)
	(json:encode-object-member 'action action-type stream)
	(loop for key in predicate-args
	    for value in values
	    for value-token = (If (symbolp value) value (role-name value))
	    if (eql key 'resource-or-component) do (setq key 'thing)
	    do 	(terpri stream)
		(json:encode-object-member key value-token stream))))))

(defmethod dump-node ((node attack-plan) &optional (stream *standard-output*))
  (with-slots (combinator (unique-id json-id)) node
    (terpri stream)
    (json:with-object (stream)
      (json:encode-object-member 'id unique-id stream)
      	(terpri stream)
	(json:encode-object-member 'type 'plan stream)
	(terpri stream)
	(json:encode-object-member 'combinator combinator stream)
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
  (flet ((do-a-node (node) (terpri stream) (dump-link-set node stream)))
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
  (declare (ignore stream))
  ;; actions are terminal nodes, so nothing to do
  (values)
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Graphing the capability hiearchy
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun get-root-capabilities (authorization-pool-name)
  (let* ((pool (object-named authorization-pool-name))
	 (capabilities (capabilities pool)))
    (loop for capability in capabilities
	when (null (more-general capability))
	collect capability)))
    

(defun graph-capabilities (authorization-pool-name &optional (stream *standard-output*))
  (let ((roots (get-root-capabilities authorization-pool-name)))
    (clim:format-graph-from-roots 
     roots
     #'(lambda (object stream) (format stream "~a" (role-name object)))
     #'more-specific
     :merge-duplicates t
     :stream stream)
    (values)))
     