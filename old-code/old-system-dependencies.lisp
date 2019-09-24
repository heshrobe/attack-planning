;;; -*- Syntax: Joshua; Package: APLAN; Mode: JOSHUA; syntax: joshua; readtable: Joshua  -*-

(in-package :aplan) 

(define-predicate desirable-property-of (system property))

;;; This is used in the sense that a process controls a data-set
(define-predicate process-controls-data-set (thing1 thing2))

(define-predicate impacts (component property os-instance thing))

(define-predicate input-of (component resource))

(define-predicate output-of (component resource))

(define-predicate residence (thing place))

(define-predicate migrates-from (thing place1 place2 process))

(define-predicate is-a-format-of (thing format-type other-thing))

(define-predicate transforms (process format1 format2))

(define-predicate has-permission (user object operation))

(define-predicate runs-with-permissions-of (process user))

(define-predicate requires-access-right (object operation capability))

(define-predicate vulnerable-to (thing attack))

(define-predicate protected-from (thing attack))

(define-predicate accepts-connection (machine type user path))

(define-predicate uses-machine (machine user))

;;; Typically, the DNS translation of a domain name to an IP address
(define-predicate translation-of (symbolic-rep concrete-rep))

;;; actions

(define-predicate affect (attacker property resource-or-component os-instance plan))

(define-predicate takes-control-of (attacker component plan))

(define-predicate uses-control-of-component-to-affect-resource (attacker component property resource plan))

(define-predicate modify (attacker object plan))

(define-predicate achieve-knowledge-of (attacker thing plan))

(define-predicate know (attacker thing plan))

(define-predicate observe (attacker object plan))

(define-predicate achieve-access-right (attacker right thing vehicle plan))

(define-predicate make-member-of (attacker thing set plan))

(define-predicate guess (attacker thing))

(define-predicate achieve-connection (attacker os-instance connection-type plan))

(define-predicate logon (attacker user os-instance plan))

;;; This is related to attacks in which for example the user is misdirected
;;; to a fake site or to a fake DNS resolver
(define-predicate cause-to-believe (attacker user thing plan))



;;; All this needs to be redone in a decision theoretic framework!
;;; inferring desirable properties

;;; These talk about OS instances, need to extend to application instances
;;; and to reflect that application instances are controlled by their OS instances
(defrule os-performance (:forward)
  If [object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance reliable-performance])

(defrule os-privacy (:forward)
  If [object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance data-privacy])

(defrule os-integrity (:forward)
  if [object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance data-integrity])

(defrule os-execution-integrity (:forward)
  if [object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance execution-integrity])

;;; Presentation integrity means that a user will see what you intend to see
;;; You can affect this by screwing up the data behind this
;;; Or you can affect this by misdirecting the user to the wrong place
;;; Note: This shouldn't be a property of an os-instance, but rather a property 
;;; of a web-site or something like that.

(defrule os-presentation-integrity (:forward)
  if [object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance presentation-integrity])

(defrule servers-run-root-in-windows (:forward)
  if [and [object-type-of ?server-process server-process]
          [value-of (?server-process host-os) ?os-instance]
          [object-type-of ?os-instance windows]
          [value-of (?os-instance superuser) ?superuser]
          [object-type-of ?superuser user]]
  then [runs-with-permissions-of ?server-process ?superuser])

(defrule servers-run-root-in-unix (:forward)
  if [and [object-type-of ?server-process server-process]
	  [value-of (?server-process host-os) ?os-instance]
          [object-type-of ?os-instance unix]
          [value-of (?os-instance superuser) ?superuser]
          [object-type-of ?superuser user]]
  then [runs-with-permissions-of ?server-process ?superuser]) 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Componenets of attack planning
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; First a macro to make notation more abstract and clearer

(defmacro defattack-method (method-name 
			    &key desirable-property
				 target-component
				 target-system
				 attacker
				 prerequisites
				 sub-goals
				 plan)
  ;; provide names for unsupplied fields
  (when (Null plan)
    (setq plan  `(logic-variable-maker \?plan)))
  (when (null desirable-property)
    (setq desirable-property `(logic-variable-maker \?desirable-property)))
  (when (null target-component)
    (setq target-component `(logic-variable-maker \?resource)))
  (when (null target-system)
    (setq target-system `(logic-variable-maker \?os-instance)))
  (when (null attacker)
    (setq attacker `(logic-variable-maker \?attacker)))
  `(defrule ,method-name (:backward)
     then [affect ,attacker ,desirable-property ,target-component ,target-system
		  ((:goal (affect ,desirable-property ,target-system) :plan ,plan))
		  ]
     if [and ,@prerequisites
	     ,@sub-goals
	     ,(loop for sub-goal in sub-goals
		  for sub-goal-statement = (predication-maker-statement sub-goal)
		  for plan-variable = (first (last sub-goal-statement))
		  collect plan-variable into sub-plans
		  finally (return
			    (if (null (rest sub-plans))
				;; optimze for one sub-plan
				`(unify ,plan ,@sub-plans)				      
			      `(unify ,plan (append ,@sub-plans)))))
	     ]))

;;; How to hack a system

;;; all plan entries will be pairs of the goal, the subgoals and the plans for each subgoal

;;; take control of the component that controls the property

(defattack-method hack-property-directly
    :desirable-property ?desirable-property
    :target-component ?resource
    :target-system ?os-instance
    :prerequisites ([object-type-of ?os-instance operating-system]
		    [object-type-of ?resource computer-resource]
		    ;; check that the resouce belongs to the same machine as the os
		    [part-of (?computer os) ?os-instance]
		    [value-of (?resource machines) ?computer]
		    [desirable-property-of ?os-instance ?desirable-property]
		    [impacts ?component ?desirable-property ?os-instance ?resource]
		    [part-of ?os-instance ?component])
    :sub-goals ([takes-control-of ?attacker ?component ?control-plan]
		[uses-control-of-component-to-affect-resource ?attacker ?component ?desirable-property ?resource ?impact-plan])
    )

; (defrule hack-property-directly (:backward)
;   then [affect ?attacker ?desirable-property ?resource ?os-instance 
;                ((:goal (affect ?desirable-property ?os-instance) :plan ?plan))]
;   ;; assume we know the os-instance and resource
;   if [and [object-type-of ?os-instance operating-system]
;           [object-type-of ?resource computer-resource]
;           ;; check that the resouce belongs to the same machine as the os
;           [part-of (?computer os) ?os-instance]
;           [value-of (?resource machines) ?computer]
;           [desirable-property-of ?os-instance ?desirable-property]
;           [impacts ?component ?desirable-property ?os-instance ?resource]
;           [part-of ?os-instance ?component]
;           [takes-control-of ?attacker ?component ?control-plan]
; 	  [uses-control-of-component-to-affect-resource ?attacker ?component ?desirable-property ?resource ?impact-plan]
; 	  (unify ?plan (append ?control-plan ?impact-plan))])



;; As fas as I can tell this is completely redundant with the above
; (defrule hack-file-property-directly (:backward)
;   then [affect ?attacker ?desirable-property ?file ?os-instance
;                ((:goal (affect ?desirable-property ?os-instance) :plan ?plan))]
;   ;; assume we know the file
;   if [and [object-type-of ?file file]
;           [object-type-of ?os-instance operating-system]
;           [part-of (?machine os) ?os-instance]
;           [value-of (?file machines) ?machine]
;           [desirable-property-of ?os-instance ?desirable-property]
;           [impacts ?component ?desirable-property ?os-instance ?file]
;           [part-of ?os-instance ?component]
;           [takes-control-of ?attacker ?component ?control-plan]
; 	  [uses-control-of-component-to-affect-resource ?attacker ?component ?desirable-property ?resource ?affect-plan]
; 	  (unify ?plan (append ?control-plan ?affect-plan))])


(defattack-method read-file-property-directly
  :desirable-property data-privacy
  :target-component ?file
  :target-system ?os-instance
  :prerequisites ([object-type-of ?file file]
		  [object-type-of ?os-instance operating-system]
		  [desirable-property-of ?os-instance data-privacy])
  :sub-goals ([achieve-knowledge-of ?attacker (contents ?file) ?read-plan])
  )


; old-notation
; (defrule read-file-property-directly (:backward)
;   then [affect ?attacker data-privacy ?file ?os-instance 
; 	       ((:goal (affect data-privacy ?file) :plan ?read-plan))]
;   ;; assume we know the file
;   if [and [object-type-of ?file file]
; 	  [object-type-of ?os-instance operating-system]
;           ;; [part-of (?machine os) ?os-instance]
;           [desirable-property-of ?os-instance data-privacy]
;           [achieve-knowledge-of ?attacker (contents ?file) ?read-plan]])

(defrule write-file-property-directly (:backward)
  then [affect ?attacker data-integrity ?file ?os-instance 
	       ((:goal (affect data-integrity ?file) :plan ?write-plan))]
  ;; assume we know the file
  if [and [object-type-of ?file file]
          [object-type-of ?os-instance operating-system]
          ;; [part-of ?machine ?os-instance]
          [desirable-property-of ?os-instance data-integrity]
	  [modify ?attacker ?file ((:goal (modify ?file) 
                                    :plan ?write-plan))]])

;;; To affect the data-integrity of some data-set
;;; Get control of a process that produces the data-set
(defrule mung-process-output (:backward)
  then [affect ?attacker data-integrity ?data-set ?os-instance
	       ((:goal (affect data-integrity ?data-set) :plan ?mung-plan))]
  if [and [object-type-of ?os-instance operating-system]
	  [output-of ?process ?data-set]
	  [value-of (?process host-os) ?os-instance]
	  [takes-control-of ?attacker ?process ((:goal (control ?process) :plan ?control-plan))]
	  [uses-control-of-component-to-affect-resource ?attacker ?process data-integrity ?data-set ?modify-plan]
	  (unify ?mung-plan (append ?control-plan ?modify-plan))])

;;; If you control a process that produces an output
;;; you can use that control to mung the data-structure in core
(defrule mung-in-core-data-structures (:backward)
  then [uses-control-of-component-to-affect-resource ?attacker ?process data-integrity ?data-set ?modify-plan]
  if [and [object-type-of ?process process]
	  [output-of ?process ?data-set]
	  (unify ?modify-plan
		 `((:action (modify-in-core-data-structures
			     ,?process
			     ,?data-set))))])

;;; find an input of the component that controls the property and modify it

(defrule control-component-through-input (:backward)
  then [takes-control-of ?attacker ?thing ((:goal (control ?thing) 
                                            :plan ?input-modification-plan))]
  ;; assumption is that we know thing
  if [and [input-of ?thing ?input]
          [modify ?attacker ?input ?input-modification-plan]])

(defrule control-process-through-loadable-files (:backward)
  then [takes-control-of ?attacker ?thing ((:goal (control ?thing) 
					    :plan ?code-modification-plan))]
  if [and [object-type-of ?thing process]
	  [value-of (?thing program) ?program]
	  [object-type-of ?program program]
	  [value-of (?program load-files) ?file]
	  [object-type-of ?file dynamically-loadable-code-file]
	  [modify ?attacker ?file ?code-modification-plan]])

;;; This should be expressed in a more general way about transforming formats
;;; but it will do for now.
(defrule modify-loadable-code (:backward)
  then [modify ?attacker ?object-file ((:goal (modify ?object-file)
				        :plan ?composite-plan))]
  if [and [object-type-of ?object-file dynamically-loadable-code-file]
	  [value-of (?object-file source-file) ?source-file]
	  [modify ?attacker ?source-file ?mung-plan]
	  (unify ?composite-plan
		 (append ?mung-plan
			 `((:action (compile ,?source-file ,?object-file)))))
	  ])

(defrule modify-through-available-access-rights (:backward)
  then [modify ?attacker ?object ((:goal (modify ?object) 
                                   :plan ?composite-plan))]
  ;; assumption is that we know the object
  if [and [value-of (?object machines) ?computer]
          [object-type-of ?computer computer]
          [part-of (?computer os) ?os-instance]
          [object-type-of ?os-instance operating-system]
          [requires-access-right ?object write ?capability]
          [achieve-access-right ?attacker write ?object ?vehicle ?access-plan]
          (unify ?composite-plan 
                 (append ?access-plan 
                         `((:action (,(typecase ?vehicle
                                        (process 'overwrite-using-process-capability)
                                        (user 'overwrite-using-user-capability))
                                     ,?capability ,?vehicle ,?object)))))
          ]) 

(defrule modify-through-part (:backward)
  then [modify ?attacker ?object ((:goal (modify ?object) :plan ?modification-plan))]
  ;; assumption is that object is known
  if [and [object-type-of ?object ji::basic-object]
	  [part-of ?object ?component]
          [modify ?attacker ?component ?modification-plan]]) 

(defrule modify-through-controller (:backward)
   then [modify ?attacker ?object ((:goal (modify ?object) :plan ?plan))]
   ;; assumption is that object is known
   if [and [process-controls-data-set ?controller ?object]
           [takes-control-of ?attacker ?controller ?control-plan]
	   [uses-control-of-component-to-affect-resource ?attacker ?controller structure ?object ?affect-plan]
	   (unify ?plan (append ?control-plan ?affect-plan))
	   ])



(defrule buffer-overflow-can-control-server-processes (:backward)
  then [takes-control-of ?attacker ?process ((:goal (control ?process ?os-instance)
                                              :plan ((:action (buffer-overflow-attack ?process ?os-instance)))))]
  ;; assumption is that process is known
  if [and [object-type-of ?process process]
	  [value-of (?process host-os) ?os-instance]
	  (is-vulnerable-to ?process 'buffer-overflow-attack)])

;;; How to do the supertyping
(defun is-vulnerable-to (process attack)
  (labels ((do-one-type (type)
             (let ((type-name (ji::object-type-name type)))
               (ask `[protected-from ,type-name ,attack]
                    #'(lambda (just)
                        (declare (ignore just))
                        (return-from is-vulnerable-to (values nil))))
               (ask `[vulnerable-to ,type-name ,attack]
                    #'(lambda (just)
                        (declare (ignore just))
                        (return-from is-vulnerable-to (values t))))
               (loop for his-super in (ji::object-type-supertypes type)
                     do (do-one-type his-super)))))
    (let ((his-type (ji::basic-object-type process)))
      (do-one-type his-type))
    nil))

(defrule web-servers-are-vulnerable (:backward)
  then [vulnerable-to web-server-process buffer-overflow-attack]
  if t)

(defrule common-lisp-http-server-is-safe (:backward)
  then [protected-from cl-http-server-process buffer-overflow-attack]
  if t)


(defrule modify-active-user-set (:backward)
  then [modify ?attacker ?active-user-set ((:goal (modify ?active-user-set) :plan ?plan))]
  ;; assumption is that we know the active-user-ste
  if [and [object-type-of ?active-user-set user-set]
	  [value-of (?active-user-set os) ?os-instance]
          [object-type-of ?os-instance operating-system]
	  [make-member-of ?attacker ?user ?active-user-set ?plan]])

(defrule join-active-user-set (:backward)
  then [make-member-of ?attacker ?user ?active-user-set ((:goal (make-member ?user ?active-user-set) :plan ?logon-plan))]
  ;; assumption is that we know active-user
  if [and [object-type-of ?active-user-set user-set]
          [value-of (?active-user-set os) ?os-instance]
	  [object-type-of ?os-instance operating-system]
	  [logon ?attacker ?user ?os-instance ?logon-plan]])

(defrule how-to-logon (:backward)
  then [logon ?attacker ?user ?os-instance ((:goal (logon ?user ?os-instance) :plan ?composite-plan))]
  if [and [object-type-of ?os-instance operating-system]
          [value-of (?os-instance authorization-pool) ?pool]
          [object-type-of ?pool authorization-pool]
          [value-of (?pool users) ?user]
          [object-type-of ?user user]
	  [achieve-knowledge-of ?attacker (password ?user) ?password-plan]
          [or [achieve-connection ?attacker ?os-instance telnet ?connection-plan]
              [achieve-connection ?attacker ?os-instance ssh ?connection-plan]]
          (unify ?composite-plan (append ?password-plan ?connection-plan))])

(defrule user-knows-own-password (:backward)
  then [achieve-knowledge-of ?user (password ?user) ((:goal (know (password ?user))
							    :plan ((:action (use-own-password)))))]
  if t)
            
(defrule how-to-get-password-by-guessing (:backward)
  then [achieve-knowledge-of ?attacker (password ?user) ((:goal (know (password ?user))
                                                          :plan ((:action (password-guess ?user)))))]
  if [and (not (equal ?attacker ?user))
	  [guess ?attacker (password ?user)]]
	  )

(defrule guess-typical-user (:backward)
  then [guess ?attacker (password ?user)]
  if [and [object-type-of ?user typical-user]
          [object-type-of ?attacker attacker]
          (succeed)])

(defrule how-to-get-password-by-virus (:backward)
  then [achieve-knowledge-of ?attacker (password ?user) 
            ((:goal (know (password ?user)) 
		    :plan ((:goal (sniff (password ?user))
				  :plan ((:goal (achieve-email-connection-to ?os-instance) 
						:plan ?plan)
					 (:action (send-socially-engineered-virus ?user)))))))]
  if [and [object-type-of ?user user]
          [uses-machine ?machine ?user]
          [object-type-of ?machine computer]
          [part-of (?machine os) ?os-instance]
          [achieve-connection ?attacker ?os-instance email ?plan]
          ])

(defrule how-to-get-password-by-sniffing (:backward)
  then [achieve-knowledge-of ?attacker (password ?user) ((:goal (know (password ?user)) 
                                                          :plan (?observation-plan 
                                                                (:action (sniff-a-passward ?user ?subnet)))))]
  if [and [object-type-of ?user user]
          [uses-machine ?machine ?user]
          [object-type-of ?machine computer]
          [value-of (?machine subnets) ?subnet]
          [object-type-of ?subnet subnet]
          [observe ?attacker (network-traffic ?subnet) ?observation-plan]
          ])

;;; to be filled in: you can get his password by external sniffing of unsecured protocols
;;; such as smtp, pop

(defrule achieve-connection-by-protocol (:backward)
  then [achieve-connection ?attacker ?os-instance ?protocol-name ((:goal (connect ?machine)
                                                                  :plan ((:action (connect-via ?protocol-name ?machine)))))]
  ;; assumption is that we know the os-instance
  if [and [object-type-of ?os-instance operating-system]
	  [part-of (?machine os) ?os-instance]
	  [object-type-of ?machine computer]
	  [accepts-connection ?machine ?protocol-name ?attacker ?]]
          )

;;; to be filled in:
;;; if a remote request for a service arrives
;;; and the machine runs that service
;;; and the server admittance policy allows it
;;; then an instance of that server process is created
;;; this instance is part of the server workload
;;; it runs with the permissions of that server process type.

;;; if a user is logged in
;;; and the user requests a job to be started
;;; and if the user job admitter allows it
;;; then an instance of a user process is started
;;; it runs with the permission of the user 


;;; scheduler and its inputs
(defrule scheduler-input-workload (:backward)
  then [input-of ?scheduler ?workload]
  ;; assumption is that we know the scheduler
  if [and [object-type-of ?scheduler scheduler]
          [part-of (?os-instance scheduler) ?scheduler]
          [object-type-of ?os-instance operating-system]
          [value-of (?os-instance workload) ?workload]
          [object-type-of ?workload os-workload]
          ])

(defrule scheduler-input (:backward)
  then [input-of ?scheduler ?scheduler-policy-file]
  ;; assumption is that scheduler is known
  if [and [object-type-of ?scheduler scheduler]
          [part-of (?os-instance scheduler) ?scheduler]
          [object-type-of ?os-instance operating-system]
          [part-of (?computer os) ?os-instance]
          [object-type-of ?computer computer]
          [value-of (?computer resources) ?scheduler-policy-file]
          [object-type-of ?scheduler-policy-file scheduler-policy-file]])

;;; scheduler controls reliable performance
(defrule scheduler-process-controls-data-set-performance (:backward)
  then [impacts ?scheduler reliable-performance ?os-instance ?process]
  ;; assumption is that os is  known
  if [and [object-type-of ?os-instance operating-system]
          [part-of (?os-instance scheduler) ?scheduler]
          [object-type-of ?scheduler scheduler]
          ])

;;; access controller impacts privacy
(defrule access-controller-controls-privacy (:backward)
  then [impacts ?access-controller data-privacy ?os-instance ?file]
  ;; assumption is that os is known access controller isn't
  if [and [object-type-of ?os-instance operating-system]
          [part-of (?os-instance access-controller) ?access-controller]
          [object-type-of  ?access-controller access-controller]
          [object-type-of ?file file]
          [part-of (?computer os) ?os-instance]
          [value-of (?file machines) ?computer]
          ])

(defrule access-controller-input-password-file (:backward)
  then [input-of ?access-controller ?password-file]
  ;; assumption is that logon-controller is known
  if [and [object-type-of ?access-controller access-controller]
          [part-of (?os-instance access-controller) ?access-controller]
	  [object-type-of ?os-instance operating-system]
          [part-of (?computer os) ?os-instance]
          [object-type-of ?computer computer]
          [value-of (?computer resources) ?password-file]
          [object-type-of ?password-file password-file]
          ])

;;; access controller impacts integrity
(defrule access-controller-controls-integrity (:backward)
  then [impacts ?access-controller data-integrity ?os-instance ?file]
  ;; assumption is that os is known access controller isn't
  if [and [object-type-of ?os-instance operating-system]
          [part-of (?os-instance access-controller) ?access-controller]
          [object-type-of  ?access-controller access-controller]
          [object-type-of ?file file]
          [part-of (?computer os) ?os-instance]
          [value-of (?file machines) ?computer]
          ])

;;; what controls the parts of workload 

(defrule user-workload-controls (:backward)
  then [process-controls-data-set ?user-job-admitter ?user-workload]
  ;; assumption is that user-workload is bound
  ;; job-admitter isn't
  if [and [object-type-of ?user-workload workload]
          [value-of (?user-workload os) ?os-instance]
          [object-type-of ?os-instance operating-system]
          [value-of (?os-instance workload) ?workload]
          [object-type-of ?workload os-workload]
          [part-of (?workload user-workload) ?user-workload]
          [part-of (?os-instance job-admitter user-job-admitter) ?user-job-admitter]
          [object-type-of ?user-job-admitter job-launcher]
          ])

(defrule server-workload-controls (:backward)
  then [process-controls-data-set ?server-job-admitter ?server-workload]
  ;; assumption is that server-workload is bound
  ;; job-admitter isn't
  if [and [object-type-of ?server-workload workload]
          [value-of (?server-workload os) ?os-instance]
          [object-type-of ?os-instance operating-system]
          [value-of (?os-instance workload) ?workload]
          [object-type-of ?workload os-workload]
          [part-of (?workload server-workload) ?server-workload]
          [part-of (?os-instance job-admitter server-job-admitter) ?server-job-admitter]
          [object-type-of ?server-job-admitter job-launcher]
          ])

;;; an input to the job-admitter are the active user and server set (is this exactly right?
;;; shouldn't it be that the user-set makes requests and those are the inputs?)
;;; What controls the active server set?  "The Server manager".
(defrule user-job-admitter-inputs (:backward)
  then  [input-of ?user-job-admitter ?active-user-set]
  ;; assumption is that user-job-admitter is knownn
  if [and [object-type-of ?user-job-admitter job-launcher]
          [part-of (?os-instance job-admitter user-job-admitter) ?user-job-admitter]
          [object-type-of ?os-instance operating-system]
          [value-of (?os-instance user-set) ?active-user-set]
          [object-type-of ?active-user-set user-set]
          ])

(defrule server-job-admitter-inputs (:backward)
  then  [input-of ?server-job-admitter ?active-server-set]
  ;; assumption is that server-job-admitter is knownn
  if [and [object-type-of ?server-job-admitter job-launcher]
          [part-of (?os-instance job-admitter server-job-admitter) ?server-job-admitter]
          [object-type-of ?os-instance operating-system]
          [value-of (?os-instance server-set) ?active-server-set]
          [object-type-of ?active-server-set server-set]
          ]) 

;;; active user set
(defrule logon-controller-controls-active-user-set (:backward)
  then [process-controls-data-set ?logon-controller ?active-user-set]
  ;; assumption is that the user set is known but logon controller isn't
  if [and [object-type-of ?active-user-set user-set]
          [value-of (?active-user-set os) ?os-instance]
          [object-type-of ?os-instance operating-system]
          [part-of (?os-instance logon-controller) ?logon-controller]
          [object-type-of ?logon-controller logon-controller]
          ])

(defrule logon-controller-inputs (:backward)
  then [input-of ?logon-controller ?password-file]
  ;; assumption is that logon-controller is known
  if [and [object-type-of ?logon-controller logon-controller]
          [part-of (?os-instance logon-controller) ?logon-controller]
	  [object-type-of ?os-instance operating-system]
          [part-of (?computer os) ?os-instance]
          [object-type-of ?computer computer]
          [value-of (?computer resources) ?password-file]
          [object-type-of ?password-file password-file]
          ])

#|
;;; access controls
(defrule access-controller-inputs (:backward)
  then [input-of ?access-controller (?os-instance acls)]
  ;; assumption is that access-controller is known
  if [and [object-type-of ?access-controller access-controller]
          [part-of (?os-instance access-controller) ?access-controller]
          [object-type-of ?os-instance operating-system]
          ]) 

|#



;;; filtering policies

(defmacro tell-policy (bridge connection-type 
                              &key positive-location-mask positive-location-address 
                              negative-location-mask negative-location-address)
  `(let ((location (if (and ,positive-location-mask ,positive-location-address)
                    (make-positive-location-mask ,positive-location-address ,positive-location-mask)
                    (make-negative-location-mask ,negative-location-address ,negative-location-mask))))
     ,(if (eql bridge '*)
        `(tell `[policy-for ?anything ,',connection-type ,location]) 
        `(tell `[policy-for ,(follow-path '(,bridge)) ,',connection-type ,location])))) 


;;; this needs to use the rule below to get the path 
;;; and to check each boundary controller along the path. 

(defrule path-allows-connection (:backward)
  then [accepts-connection ?machine ?connection-type ?user ?path] 
  if [and [object-type-of ?machine computer]
          [object-type-of ?user user]
          [reachable-from ?machine ?user ?path]
          [value-of (?user location) ?location]
          (path-is-acceptable-for-connection-type (copy-object-if-necessary ?path)
                                                  ?location ?connection-type)
          ])

;; this forces the user to "own" every machine at his site
;; by forward reasoning.
(defrule user-can-use-computer (:forward)
  if [and [object-type-of ?user user]
          [value-of (?user location) ?location]
	  [object-type-of ?computer computer]
	  [value-of (?computer site) ?site]
	  [object-type-of ?site site]
	  (location-is-in-net-segment ?site ?location)]
  then [value-of (?user machines) ?computer])

(defrule bridges-on-pathway (:backward)
  then [reachable-from ?target-computer ?user ?path]
  if [and [object-type-of ?user user]
          [object-type-of ?target-computer computer]
          [value-of (?user machines) ?user-computer]
          [object-type-of ?user-computer computer]
          [connected ?user-computer ?target-computer ?path]])


;;; this handles the case for a user whose "location" in ip-space
;;; is known (by a mask) but for which we don't know a specific machine.
(defrule bridges-on-pathway-2 (:backward)
  then [reachable-from ?computer ?user (?router . ?path)]
  if [and [object-type-of ?user user]
          [value-of (?user location) ?location]
          [object-type-of ?computer computer]
          [value-of (?computer site) ?site]
          [object-type-of ?site site]
          (not (location-is-in-net-segment ?site ?location))
          [object-type-of ?router router]
          [value-of (?router site) ?site]
          ;; should really check for being the router to the outside
          [connected ?computer ?router ?path]])


(defrule guess-superuser-passwords (:backward)
  then [guess ?attacker (password ?user)]
  if [and [object-type-of ?user user]
          [value-of (?user machines) ?machine]
          [object-type-of ?machine computer]
          [value-of (?machine os superuser) ?user]]) 

(defun create-attacker (name &key positive-mask-address positive-mask-mask
                             negative-mask-address negative-mask-mask)
  (let* ((attacker (make-object 'attacker :name name)))
    (apply-positive-and-negative-masks attacker 
				       positive-mask-address positive-mask-mask
				       negative-mask-address negative-mask-mask)
    attacker))

(defrule control-the-network-stack (:backward)
  then [takes-control-of ?attacker ?network-stack ((:goal (control ?network-stack)
                                                   :plan ?logon-plan))]
  if [and [object-type-of ?network-stack network-stack]
          [part-of (?os-instance network-monitor) ?network-stack]
          [object-type-of ?os-instance operating-system]
          [value-of (?os-instance superuser) ?superuser]
          [object-type-of ?superuser user]
          [logon ?attacker ?superuser ?os-instance ?logon-plan]])

(defrule read-network-traffic (:backward)
  then [observe ?attacker (network-traffic ?subnet) (:goal (observe network-traffic ?subnet) 
                                                     :plan ?control-plan)]
  if [and [object-type-of ?subnet switched-subnet]
          [value-of (?subnet switch) ?switch]
          [object-type-of ?switch switch]
          [part-of (?switch os network-monitor) ?network-stack]
          [object-type-of ?network-stack network-stack]
          [takes-control-of ?attacker ?network-stack ?control-plan]])

(defun do-it (&key (attacker (follow-path '(test-attack)))
                   (property 'reliable-performance) (machine 'dopey) 
                   (resource (follow-path '(typical-dopey-process))))
  (let ((answers nil))
    (ask `[affect ,attacker ,property ,resource ,(follow-path `(,machine os)) ?plan]
         #'(lambda (just)
             (declare (ignore just))
             (pushnew (copy-object-if-necessary ?plan) answers :test #'equal)))
    answers))

;;; permissions
(defrule process-instance-has-permision (:backward)
  then [has-permission ?server-process ?an-operation ?an-object]
  If [and [object-type-of ?server-process server-process]
          [runs-with-permissions-of ?server-process ?user]
          [has-permission ?user ?an-operation ?an-object]
          ])

(defrule user-has-permission (:backward)
  then [has-permission ?user ?operation ?object]
  ;; assumption is that we know all the above
  if [and [object-type-of ?user user]
          [object-type-of ?object computer-resource]
          [value-of (?object capability-requirements) (?operation ?capability)]
          (has-capability ?user ?capability)])

(defun has-capability (user capability)
  (let ((his-capabilities (capabilities user)))
    (labels ((check-one (putative-capability)
               (when (eql putative-capability capability)
                 (return-from has-capability (values t)))
               (mapc #'check-one (more-specific putative-capability))))
      (mapc #'check-one his-capabilities))
    nil)) 

(defrule requires-access-right-translation (:backward)
  then [requires-access-right ?object ?operation ?capability]
  if [and [object-type-of ?object computer-resource]
          [value-of (?object capability-requirements) (?operation ?capability)]])

(defrule how-to-read-a-file (:backward)
  then [achieve-knowledge-of ?attacker (contents ?file) ((:goal (know-contents-of ?file)
                                                          :plan ?composite-plan
                                                          ))]
  if [and [object-type-of ?file file]
          [achieve-access-right ?attacker read ?file ?user ?plan]
          (unify ?composite-plan
                 (append ?plan `((:action (read-with-rights-of ,?user ,?file)))))
          ])


(defrule how-to-achieve-access-right (:backward)
  then [achieve-access-right ?attacker ?right ?object ?the-process ?control-plan]
  if [and [object-type-of ?object computer-resource]
          [value-of (?object machines) ?machine]
          [object-type-of ?machine computer]
          [part-of (?machine os) ?os-instance]
          [object-type-of ?os-instance operating-system]
          ;; all this is asking is there a process in the workload with 
          ;; useful access rights
          [value-of (?os-instance workload) ?os-workload]
          [object-type-of ?os-workload os-workload]
          [or [value-of (?os-workload server-workload processes) ?the-process]
              [value-of (?os-workload user-workload processes) ?the-process]]
          [object-type-of ?the-process process]
          [has-permission ?the-process ?right ?object]
          [takes-control-of ?attacker ?the-process ?control-plan]])


(defrule how-to-achieve-access-right-by-password-stealing (:backward)
  then [achieve-access-right ?attacker ?right ?object ?user
                                                      ((:goal (achieve-access-rights-to ?object ?right)
                                                        :plan ?password-plan))]
  if [and [object-type-of ?object computer-resource]
          [value-of (?object machines) ?machine]
          [object-type-of ?machine computer]
          [part-of (?machine os) ?os-instance]
          [object-type-of ?os-instance operating-system]
          [requires-access-right ?object ?right ?capability]
          [object-type-of ?user user]
          (has-capability ?user ?capability)
          [logon ?attacker ?user ?os-instance ?password-plan]
          ])

#|

Notes:

There are several cases where you want to get knowledge of something (e.g. a password)
and then use it later.  This can be dealt with either by careful
modularization which might be far too tricky, or by having a general
model that only runs rules on achieve-knowledge-of if there is no
predicate promising the thing is known.





This is redundant

(defrule get-knowledge-of-through-available-access-rights (:backward)
  then [achieve-knowledge-of ?attacker ?object ((:goal (know-contents-of ?object) 
                                                 :plan ?composite-plan))]
  ;; assumption is that we know the object
  if [and [object-type-of ?object computer-resource]
          [value-of (?object machines) ?computer]
          [object-type-of ?computer computer]
          [part-of (?computer os) ?os-instance]
          [object-type-of ?os-instance operating-system]
          [requires-access-right ?object read ?capability]
          [achieve-access-right ?attacker read ?object ?vehicle ?access-plan]
          (unify ?composite-plan 
                 (append ?access-plan 
                         `((:action (read-using-process-capability ,?capability ,?vehicle ,?object)))))
          ])


Residencies
Formats: source, class, jar in-core-code
Transformations: compilation jarification loading


|#

; Idea picked up at MRC PI Mtg
; Attacker let's lose a shit-storm with low value but high response cost
; Then uses the opportunity created by the diversion of attention to 
; launch a high-value but perhaps more risky attack.
;;;
;;; Knowledge of memory contents as pre-requisite to overwriting attacks
;;; Memory disclosure attacks as way to gain knowledge of memory contents
;;;  Ability to read memory as pre-requisite to that
;;;    Privilege escalation as way to that
;;;    Buffer overread as read to do that
;;; Having copy of system as way to have knowledge of memory contents

					