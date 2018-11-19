;;; -*- Syntax: Joshua; Package: APLAN; syntax: joshua; readtable: Joshua  -*-

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Descriptions of How to hack a system
;;; Returns a nested plan structure (through unification)
;;; consisting of :sequential/:parallel groupings
;;; of (:goal ... :plan ...) structures
;;; and (:action ... structures
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; take control of the component that controls the property

(in-package :aplan)

;;; the top level queries



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; the purpose field of the sub-goals
;;;     All the sub-goals have an extra argument which is the purpose of that subgoal
;;;     This field is a goal stack being passed down to sub-goals
;;;     So the format is ((mnemonic . args) . rest-of-stack)
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Any desirable property
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; This is set up to attack a desirable property of any computer resource?
;;; But the component it goes after is part of the OS.
;;; So this is one method, not the only.  It's the generic method that says
;;; go after some piece of the OS that can affect the desirable property of the victim.
;;; For example, if the victim is a web-server and the goal is to affect its data-privacy
;;; then one way you might go after this is to get hold of some piece of the os and use
;;; that to violate the web-server's data-privacy.
;;; But, there are other methods: for example penetrate some component of the web-server
;;; and use that to violate data-privacy.

(defattack-method affect-property-by-controlling-impacting-component
    :to-achieve [affect ?attacker ?desirable-property ?victim]
    ;; find some component of the OS of a machine that the victim runs on
    :bindings ([ltms:value-of (?victim machines) ?computer]
               [ltms:named-part-of ?computer os ?os-instance]
               [part-of ?os-instance ?component])
    :typing ([ltms:object-type-of ?victim computer-resource]
             [ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?component process])
    :prerequisites ([impacts ?component-property ?component ?desirable-property ?victim])
    :plan (:sequential
           ;; this breaks down into two steps:
           ;; 1) Get control of some component of the victime
           ;; 2) Use that control to affect the property of the victim
           ;; Notice that the first step is oblivous to its purpose
           ;; This certainly makes things simpler but might lead to getting control in a way
           ;; that doesn't actually work
           (:goal [takes-control-of ?attacker ?component-property ?component] :plan ?control-plan)
           (:goal [use-control-of-to-affect-resource ?attacker ?component ?desirable-property ?victim] :plan ?modification-plan))
    )

(defattack-method affect-property-by-affecting-input
    :to-achieve [affect ?attacker ?desirable-property ?victim]
    :prerequisites ([impacts ?resource-property ?resource ?desirable-property ?victim])
    :typing ([ltms:object-type-of ?resource computer-resource])
    :plan (:goal [affect ?attacker ?resource-property ?resource])
    )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Performance
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Note: This could be done more indirectly by saying that 
;;; performance is inversely proportional to workload size
;;; and then having a rule that says that to decrease something that
;;; is inversely proportional to something else increaese the something else

(defattack-method increase-workload-to-decrease-performance
    :to-achieve [affect ?attacker performance ?process]
    :prerequisites ([desirable-property-of ?process performance])
    :bindings ([ltms:value-of (?process host-os) ?os]
	       [ltms:value-of (?os workload) ?workload])
    :typing ([ltms:object-type-of ?process process]
	     [ltms:object-type-of ?os operating-system]
	     [ltms:object-type-of ?workload os-workload])
    :plan (:goal [increase-size ?attacker ?workload ?foothold-machine ?foothold-size])
    )


(defattack-method send-lots-of-emails
    :to-achieve [affect ?attacker performance ?process]
    :prerequisites ([desirable-property-of ?process performance])
    :bindings ([ltms:value-of (?process host-os) ?os-instance]
	       [ltms:value-of (?attacker machines) ?attacker-machine]
	       (unify ?path-so-far `((,?attacker-machine ,?attacker))))
    :typing ([ltms:object-type-of ?process email-server-process]
	     [ltms:object-type-of ?attacker-machine computer]
	     )
    :plan (:sequential
	   (:goal [achieve-connection ?attacker ?path-so-far ?os-instance email ?foothold-machine ?foothold-role])
	   (:repeated-action [submit-email ?attacker ?foothold-role large-email ?process ?foothold-machine])))

;;; now what we want to say is:
;;; Either 
;;; 1) find a process in the current workload that is capable of launching new jobs
;;; get control of that process and cause it launch jobs.  For example, a server that takes 
;;; requests through some protocol and launches jobs in response (e.g. web server ftp server)
;;; repeatedly connect to it and cause it to launch a job
;;; 2) Increase the size of the job launch queue

(defattack-method increase-workload-by-increasing-job-launch-queue
    :to-achieve [increase-size ?attacker ?workload ?foothold-machine ?foothold-role]
    :bindings ([ltms:value-of (?workload os) ?os]
	       [ltms:value-of (?os job-launch-queue) ?queue]
	       [ltms:named-part-of ?queue user-job-launch-request-queue ?user-job-launch-queue])
    :typing ([ltms:object-type-of ?workload os-workload]
	     [ltms:object-type-of ?os operating-system]
	     [ltms:object-type-of ?queue os-job-launch-request-queue]
	     [ltms:object-type-of ?user-job-launch-queue job-launch-request-queue])
    :plan (:goal [increase-size ?attacker ?user-job-launch-queue ?foothold-machine ?foothold-role]))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Data Privacy
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method read-file-property-directly
    :to-achieve [affect ?attacker data-privacy ?file]
    :prerequisites ([desirable-property-of ?file data-privacy])
    :typing ([ltms:object-type-of ?file data-resource])
    :plan (:goal [achieve-knowledge-of-contents ?attacker ?file])
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Data Integrity
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; Fix modify
(defattack-method write-file-property-directly
    :to-achieve [affect ?attacker data-integrity ?file]
    :typing ([ltms:object-type-of ?file file])
    :prerequisites ([desirable-property-of ?file data-integrity])
    :plan (:goal [modify ?attacker contents ?file])
    )

;;; To affect the data-integrity of some data-set
;;; Get control of a process that produces the data-set
(defattack-method mung-process-output
    :to-achieve [affect ?attacker data-integrity ?data-set]
    :bindings ([output-of ?process ?data-set])    
    :typing ([ltms:object-type-of ?process process])
    :plan (:sequential
           (:goal [takes-control-of ?attacker data-integrity ?process])
           (:goal [use-control-of-to-affect-resource ?attacker ?process data-integrity ?data-set]))
    )

(defattack-method mung-database
    :to-achieve [affect ?attacker data-integrity ?database]
    :bindings ([ltms:value-of (?database capability-requirements) (write ?requirement)]
	       [ltms:value-of (?attacker machines) ?attacker-machine]
	       [ltms:value-of (?database machines) ?database-machine]
	       [ltms:named-part-of ?database-machine os ?database-os]
	       (unify ?path-so-far `((,?attacker-machine ,?attacker)))
	       )
    :typing ([ltms:object-type-of ?database database]
	     [ltms:object-type-of ?attacker attacker]
	     [ltms:object-type-of ?database database]
	     [ltms:object-type-of ?database-os operating-system]
	     )
    :plan (:sequential
	   (:goal [achieve-connection ?attacker ?path-so-far ?database-os database-protocol ?foothold-machine ?foothold-role])
	   (:goal [modify ?attacker data-integrity ?database ?foothold-machine ?foothold-role])
	   )
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Direct Control
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method take-control-of-directly
    ;; Takes control of a component to ultimately affect some property of the target
    :to-achieve [takes-control-of ?attacker ?component-property ?component]
    :plan (:goal [takes-direct-control-of ?attacker ?component-property ?component]))

;;; one way to take direct control of a process is to
;;; first find some way to modify the loadable file so as to affect the property of the target
;;; and then cause the load of the loadable file of the program that's supposed to run in the process

;;; Fix modify
(defattack-method control-process-through-loadable-files
    :to-achieve [takes-direct-control-of ?attacker ?victim-property ?victim]
    :bindings ([ltms:value-of (?victim program) ?program]
               [ltms:value-of (?program load-files) ?file])
    :typing ([ltms:object-type-of ?victim process]
             [ltms:object-type-of ?program program]
             [ltms:object-type-of ?file dynamically-loadable-code-file])
    :plan (:sequential 
           (:goal [modify ?attacker contents ?file])
           ;; Note: this is a hack right now.  Really it should be a goal which would involve
           ;; a series of actions to cause the file to get loaded (logging in?, robooting?)
           ;; Need to avoid a recursion where you're trying to load the file into the process
           ;; in order to control the process but to do the load you post a sub-goal of taking
           ;; contro of the process
           (:action [load-file ?attacker ?file ?victim]))
    )

;;; Fixed:
;;; This mentions the host-os but it doesn't actually seem to carry through
;;; to the plan.  Just rationality check, I guess.
(defattack-method buffer-overflow-can-control-server-processes
    :to-achieve [takes-direct-control-of ?attacker ?process-property ?process]
    ;; :bindings ([ltms:value-of (?process host-os) ?os-instance])
    :typing ([ltms:object-type-of ?process process]
             ;; [ltms:object-type-of ?os-instance operating-system]
             )
    :prerequisites ((is-vulnerable-to ?process 'buffer-overflow-attack))
    :plan (:action [take-control-with-buffer-overflow ?attacker ?process])
    )

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Indirect Control
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method take-control-of-indirectly
    :to-achieve [takes-control-of ?attacker ?victim-property ?victim]
    :plan (:goal [takes-indirect-control-of ?attacker ?victim-property ?victim]))

;;; Find an input of the victim and modify its contents
;;; probably should say that the behavior is affected by the content
;;; Fix modify
(defattack-method control-component-through-input
    :to-achieve [takes-indirect-control-of ?attacker ?victim-property ?victim]
    ;; assumption is that we know thing
    :bindings ([input-of ?thing ?input])
    :plan (:goal [modify ?attacker contents ?input])
    )


;;; want to say that if the property is affected by the size of the input
;;; then change the size of the input

;;; fix modify
(defattack-method control-component-through-input-size
    :to-achieve [takes-indirect-control-of ?attacker ?victim-property ?victim]
    ;; assumption is that we know thing
    :bindings ([input-of ?victim ?input])
    :plan (:goal [modify ?attacker size ?input])
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;;  Modification 
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Note: Should this maybe be broken into two parts:
;;; 1) achieve ability to modify something
;;; 2) Modify it in a way that affects the victim's property
(defattack-method modify-through-part
    :to-achieve [modify ?attacker ?victim-property ?victim ?foothole-machine ?foothold-role]
    :typing ([ltms:object-type-of ?foothole-machine computer])
    :bindings ([ltms:part-of ?victim ?component])
    :prerequisites ([impacts ?component-property ?component ?victim-property ?victim])
    :plan (:goal [modify ?attacker ?component-property ?component ?foothole-machine ?foothold-role])
    )

;;; modify a data-set by controlling a process that controls the data-set
(defattack-method modify-through-controller
    :to-achieve [modify ?attacker ?victim-property ?victim ?foothold-machine ?foothold-role]
    :typing ([ltms:object-type-of ?controller process]
             [ltms:object-type-of ?victim data-set])
    :prerequisites ([process-controls-data-set ?controller ?victim])
    :plan (:sequential 
           (:goal [takes-control-of ?attacker (controlled-data-set ?victim) ?controller ?foothold-machine ?foothold-role] )
           (:goal [use-control-of-to-affect-resource ?attacker ?controller ?victim-property ?victim ?foothold-machine ?foothold-role])) 
    )

;;; NOTE: This should be expressed in a more general way about transforming formats
;;; but it will do for now.
(defattack-method modify-loadable-code
    :to-achieve [modify ?attacker ?file-property ?object-file ?Foothold-machine ?foothold-role]
    :prerequisites ([ltms:object-type-of ?object-file dynamically-loadable-code-file]
                    [ltms:value-of (?object-file source-file) ?source-file])
    :plan (:sequential (:goal [modify ?attacker code ?source-file ?Foothold-machine ])
                       (:goal [force-compilation ?attacker ?source-file ?object-file ?foothold-machine ?foothold-role]))
    )

;;; Here ?user is again feedback to the caller about whose rights you got
;;; Is that different than ?foothold role ?
(defattack-method modify-through-available-access-rights
    :to-achieve [modify ?attacker ?object-property ?object ?foothold-machine ?foothold-role]
    :bindings ([ltms:value-of (?object machines) ?computer])
    :typing ([ltms:object-type-of ?computer computer])
    :prerequisites ([requires-access-right ?object write ?capability])
    :plan (:sequential 
	   (:goal [achieve-access-right ?attacker write ?object ?user ?foothold-machine ?foothold-role])
	   (:action [use-access-right-to-modify ?attacker write ?user ?object ?foothold-machine ?foothold-role]))
    )

;;; To increase the size of the active user set of some OS
;;; Find a user in the authorization pool for the OS
;;; and make that user a member of the active user set
(defattack-method modify-size-by-increase-size
    :to-achieve [modify ?attacker size ?object ?foothold-machine ?foothold-role]
    :plan (:goal [increase-size ?attacker ?object ?foothold-machine ?foothold-role])
    )

(defattack-method modify-active-user-set
    :to-achieve [increase-size ?attacker ?active-user-set ?foothold-machine ?foothold-role]
    :bindings ([ltms:value-of (?active-user-set os) ?os-instance]
               [ltms:value-of (?os-instance authorization-pool) ?authorization-pool]
               [ltms:value-of (?authorization-pool users) ?user])
    :typing ([ltms:object-type-of ?active-user-set user-set]
             [ltms:object-type-of ?os-instance operating-system]
             [ltms:object-type-of ?authorization-pool authorization-pool]
             [ltms:object-type-of ?user user])
    :plan (:goal [make-member-of ?attacker ?user ?active-user-set])
    )

;;; NOTE: There are other ways of doing this, e.g. find some logged in user and take over his process
;;; in order to submit lots of jobs

;;; Here entity can be passed in unbound and will be unified
(defattack-method remote-execution-to-remote-shell
    :to-achieve [achieve-remote-execution ?attacker ?user ?os-instance ?foothold-machine ?foothold-role]
    :bindings ([ltms:value-of (?os-instance users) ?user]
	       )
    :typing ([ltms:object-type-of ?os-instance operating-system]
             [ltms:object-type-of ?user user]
	     [ltms:object-type-of ?foothold-machine computer])
    :plan (:goal [achieve-remote-shell ?attacker ?user ?os-instance ?foothold-machine ?foothold-role]))

(defattack-method remote-execution-to-code-injection
    :to-achieve [achieve-remote-execution ?attacker ?process ?os-instance ?foothold-machine ?foothold-role]
    :bindings ([ltms:value-of (?os-instance processes) ?process])
    :typing ([ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?process process]
	     [ltms:object-type-of ?foothold-machine computer])
    :plan (:goal [achieve-code-injection ?attacker ?process ?os-instance ?foothold-machine ?foothold-role]))

(defattack-method code-injection-against-web-server
    :to-achieve [achieve-code-injection ?attacker ?process ?os-instance ?foothold-machine ?foothold-role]
    :typing ([ltms:object-type-of ?process web-server-process])
    :prerequisites ([vulnerable-to-overflow-attack ?process])
    :plan (:action [launch-code-injection-attack ?attacker ?process ?foothold-machine ?foothold-role]))

(defattack-method remote-execution-to-code-reuse
    :to-achieve [achieve-remote-execution ?attacker ?process ?os-instance ?foothold-machine ?foothold-role]
    :bindings ([ltms:value-of (?os-instance processes) ?process])
    :typing ([ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?process process]
	     [ltms:object-type-of ?foothold-machine computer])
    :plan (:goal [achieve-code-reuse ?attacker ?process ?os-instance ?foothold-machine ?foothold-role]))

(defattack-method code-reuse-against-web-server
    :to-achieve [achieve-code-reuse ?attacker ?process ?os-instance ?foothold-machine ?foothold-role]
    :typing ([ltms:object-type-of ?process web-server-process]
	     [ltms:object-type-of ?foothold-machine computer])
    :prerequisites ([vulnerable-to-overflow-attack ?process])
    :plan (:action [launch-code-reuse-attack ?attacker ?process ?foothold-machine ?foothold-role]))

;;; Note: It's more general if we just say to achieve remote-execution
;;; and let the system determine whether that meant remote-shell, code-injection, code-reuse, etc.
;;; In deterimining how to do that it also determines what entity to do it as.

(defattack-method modify-job-request-queue
    :to-achieve [increase-size ?attacker ?user-job-launch-queue ?foothold-machine ?foothold-role]
    :bindings ([ltms:named-part-of ?full-job-launch-queue user-job-launch-request-queue ?user-job-launch-queue]
               [ltms:value-of (?full-job-launch-queue os) ?os-instance]
	       [ltms:value-of (?os-instance job-launch-queue) ?full-job-launch-queue]
	       [ltms:value-of (?attacker machines) ?attacker-machine]
	       )
    :typing ([ltms:object-type-of ?user-job-launch-queue job-launch-request-queue]
             [ltms:object-type-of ?full-job-launch-queue os-job-launch-request-queue]
             [ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?attacker-machine computer])
    :plan (:sequential
           (:goal [achieve-remote-execution ?attacker ?entity ?os-instance ?attacker-machine ?attacker])
           (:repeated-action [submit-user-jobs ?entity ?user-job-launch-queue])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Performance related specifics
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; If somebody has goined direct control of the job-launcher
;;; They can affect performance by adding jobs
(defattack-method add-jobs-after-job-launcher-is-hacked
    :to-achieve [use-control-of-to-affect-resource ?attacker ?controller performance ?target]
    :bindings ([ltms:named-part-of ?os job-admitter ?controller]
               [ltms:value-of (?os-instance workload) ?input])
    :typing ([ltms:object-type-of ?controller os-job-admitter]
             [ltms:object-type-of ?os operating-system]
             [ltms:object-type-of ?input os-workload]
	     [ltms:object-type-of ?target process])
    :plan (:action [add-user-jobs ?attacker ?input]))
    
;;; If you control a process that produces an output
;;; you can use that control to mung the data-structure in core
(defattack-method mung-in-core-data-structures
    :to-achieve [use-control-of-to-affect-resource ?attacker ?process data-integrity ?data-set]
    :bindings ([output-of ?process ?data-set])
    :typing ([ltms:object-type-of ?process process])
    :plan (:action [modify-in-core-data-structures ?process ?data-set]))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Methods for hacking access rights and gaining access
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method how-to-read-a-file
    :to-achieve [achieve-knowledge-of-contents ?attacker ?file]
    :bindings ([ltms:value-of (?attacker machines) ?attacker-machine])
    :typing ([ltms:object-type-of ?file file])
    :plan (:sequential
           (:goal [achieve-access-right ?attacker read ?file ?user])
           (:action [read-with-rights-of ?attacker ?user ?file])
	   (:action [open-ftp-connection ?attacker ?attacker-machine])
	   (:action [trasmit-data ?attacker ?file ?attacker-machine])
	   )
    )

;;; If your foothold role already has the access rights
;;; do nothing
(defattack-method achieve-a-right-you-already-have 
    :to-achieve [achieve-access-right ?attacker ?object ?right ?user ?foothole-machine ?foothold-role]
    :prerequisites ([has-permission ?foothold-role ?object ?right])
    :bindings ([unify ?user ?foothold-role])
    :plan ()
    )

;;; The ?user part of this is actually to feed back to the higher
;;; level that it should read the file with the access rights of the user
;;; but is that really necessary, why isn't the process enough

;;; Note that this approach would normally be used from a remote foothold
;;; That can reach whatever process you want, and such that this process can 
;;; then make a contact to the victim object.
;;; So the strategy would be to identify a process that runs on a machine that can reach the target
;;; and that has the accesss rights you need.
;;; Then figure out how to get to a foothold that can reach the process's machine
;;; then do this.

(defattack-method achieve-access-right-by-process-subversion
    :to-achieve [achieve-access-right ?attacker ?right ?object ?user ?foothole-machine ?foothold-role]
    ;; all this is asking is there a process in the workload
    ;; and if so with which user's permissions is it running
    :bindings ([ltms:value-of (?object machines) ?machine]
               [ltms:named-part-of ?machine os ?os-instance]
               [ltms:value-of (?os-instance workload) ?os-workload]
               [or [ltms:value-of (?os-workload server-workload processes) ?the-process]
                   [ltms:value-of (?os-workload user-workload processes) ?the-process]]
               [runs-with-permissions-of ?the-process ?user]
               )
    :typing ([ltms:object-type-of ?object computer-resource]
             [ltms:object-type-of ?machine computer]
             [ltms:object-type-of ?os-instance operating-system]
             [ltms:object-type-of ?os-workload os-workload]
             [ltms:object-type-of ?the-process process]           
             )
    ;; This is the key pre-req: The process has the desired right to the object
    :prerequisites ([has-permission ?the-process ?right ?object])
    :plan (:sequential
	   (:goal [takes-direct-control-of ?attacker execution ?the-process ?foothole-machine])
	   (:action [uses-control-to-achieve-access-right ?attacker ?right ?object ?foothole-machine]))
    )


;;; similar comment to above about foothold etc
(defattack-method how-to-achieve-access-right-by-remote-shell-on-target
    :to-achieve [achieve-access-right ?attacker ?right ?object ?user ?foothold-machine ?foothold-role]
    :bindings ([ltms:value-of (?object machines) ?machine]
               [ltms:named-part-of ?machine os ?os-instance]
               [requires-access-right ?object ?right ?capability]
	       [ltms:value-of (?os-instance authorization-pool) ?pool]
	       [ltms:named-part-of ?foothold-machine os ?foothold-os]
	       [ltms:value-of (?pool users) ?user])
    :typing ([ltms:object-type-of ?object computer-resource]
             [ltms:object-type-of ?machine computer]
             [ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?pool authorization-pool]
             [ltms:object-type-of ?user user])
    ;; Note: has-capability is a function not an assertion
    :prerequisites ((has-capability ?user ?capability))
    :plan (:goal [achieve-remote-shell ?attacker ?user ?foothold-os ?foothold-machine ?foothold-role])
    )

;;;;;; Note & Fix: This calls itself recursively but has no protection against
;;;;;; ping-ponging
;;;(defattack-method how-to-achieve-access-right-by-remote-shell-indirectly
;;;    :to-achieve [achieve-access-right ?attacker ?right ?object ?user ?foothold-machine ?foothold-role]
;;;    :bindings ([ltms:value-of (?object machines) ?machine]
;;;               [ltms:named-part-of ?machine os ?os-instance]
;;;               [requires-access-right ?object ?right ?capability]
;;;	       [ltms:value-of (?os-instance authorization-pool) ?pool]
;;;	       [ltms:value-of (?pool users) ?user]
;;;	       ;; all this is about finding another machine in the enclave
;;;	       [ltms:value-of (?machine site) ?site]
;;;	       [ltms:value-of (?site enterprise) ?enterprise]
;;;	       [ltms:value-of (?enterprise sites) ?other-site]
;;;	       [ltms:value-of (?other-site subnets) ?other-subnet]
;;;	       [ltms:value-of (?other-subnet computers) ?other-machines]
;;;	       [ltms:named-part-of ?other-machine os ?other-os]
;;;	       )
;;;    :typing ([ltms:object-type-of ?object computer-resource]
;;;             [ltms:object-type-of ?machine computer]
;;;             [ltms:object-type-of ?os-instance operating-system]
;;;	     [ltms:object-type-of ?pool authorization-pool]
;;;             [ltms:object-type-of ?user user])
;;;    ;; Note: has-capability is a function not an assertion
;;;    :PREREQUISITES ((not (eql ?other-machines ?machine))
;;;		    [reachable-from ?machine ?other-machine ?]
;;;		    [reachable-from ?other-machine ?attacker ?]
;;;		    (has-capability ?user ?capability)
;;;		    (break "~a ~a ~a" ?user ?other-machine ?other-os))
;;;    :plan (:goal [achieve-remote-execution ?attacker ?user ?other-os ?foothold-machine ?foothold-role])
;;;    )




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Active User Set and Logging in 
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method join-active-user-set
    :to-achieve [make-member-of ?attacker ?user ?active-user-set]
    :bindings ([ltms:value-of (?active-user-set os) ?os-instance])
    :typing ([ltms:object-type-of ?active-user-set user-set]
             [ltms:object-type-of ?os-instance operating-system])
    :plan (:goal [achieve-remote-shell ?attacker ?user ?os-instance ?foothold-machine ?foothold-role])
    )

;;; Telnet version
(defattack-method how-to-logon-1
    :to-achieve [achieve-remote-shell ?attacker ?user ?os-instance ?foothold-machine ?foothold-role]
    :bindings ([ltms:value-of (?os-instance users) ?user]
	       [ltms:value-of (?os-instance authorization-pool) ?pool]
	       [ltms:value-of (?os-instance machine) ?victim-machine])
    :typing (
             [ltms:object-type-of ?os-instance operating-system]
             [ltms:object-type-of ?pool authorization-pool]
	     [ltms:object-type-of ?victim-machine computer]
	     [ltms:object-type-of ?foothold-machine computer]
	     [ltms:object-type-of ?user user])
    :prerequisites ()
    :plan (:sequential
           (:goal [achieve-knowledge-of-password ?attacker ?user ?pool ?foothold-machine ?foothold-role])
           (:action [login ?attacker ?user ?os-instance ?foothold-machine])))

;;; SSH version
(defattack-method how-to-logon-2
    :to-achieve [achieve-remote-shell ?attacker ?user ?os-instance ?foothold-machine ?foothold-role]
    :bindings ([ltms:value-of (?os-instance users) ?user]
	       [ltms:value-of (?os-instance authorization-pool) ?pool]
	       [ltms:value-of (?os-instance machine) ?victim-machine]
	       )
    :typing (
             [ltms:object-type-of ?os-instance operating-system]
             [ltms:object-type-of ?pool authorization-pool]
	     [ltms:object-type-of ?victim-machine computer]
	     [ltms:object-type-of ?foothold-machine computer]
	     [ltms:object-type-of ?user user])
    :prerequisites ()
    :plan (:sequential
           (:goal [achieve-knowledge-of-password ?attacker ?user ?pool ?foothold-machine ?foothold-role])
           (:action [login ?attacker ?user ?os-instance ?foothold-machine])))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Passwords and secrets
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method user-knows-own-password
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?resource ?foothold-machine ?foothold-role]
    :prerequisites ((equal ?attacker ?user))
    :plan (:action [use-own-password ?user ?resource ?foothold-machine])
    )
            
(defattack-method how-to-get-password-by-guessing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?resource ?foothold-machine ?foothold-role]
    :prerequisites ((not (equal ?attacker ?user)))
    :plan (:goal [guess-password ?attacker ?user ?resource ])
    )

(defattack-method guess-typical-user
    :to-achieve [guess-password ?attacker ?user ?resource]
    :typing ([ltms:object-type-of ?user user]
	     [ltms:value-of (?user typical-p) t]
             [ltms:object-type-of ?attacker attacker])
    :plan (:action [password-dictionary-lookup-attack ?attacker ?user ?resource])
    )

(defattack-method guess-superuser-passwords
    :to-achieve [guess-password ?attacker ?user ?resource]
    :typing ([ltms:value-of (?user machines) ?machine]
             [ltms:value-of (?machine os superuser) ?user])
    :bindings ([ltms:object-type-of ?user user]
               [ltms:object-type-of ?machine computer])
    :plan (:action [password-dictionary-lookup-attack ?attacker ?user ?resource])
    )

(defattack-method get-sysadmin-password-by-bricking
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?resource ?foothold-machine ?foothold-role]
    :typing ([ltms:value-of (?user machines) ?machine])
    :bindings ([ltms:object-type-of ?user user]
               [ltms:object-type-of ?machine computer])
    :prerequisites ([ltms:value-of (?machine os superuser) ?user])
    :plan (:sequential
	    (:goal [install-malware ?attacker ?foothold-machine key-logger])
	    (:goal [brick-machine ?attacker ?foothold-machine])
	    (:action [capture-password-through-keylogger ?attacker ?foothold-machine])
	    ))

(defattack-method brick-machine-by-kill-disk
    :to-achieve [brick-machine ?attacker ?foothold-machine]
    :plan (:sequential
	   (:goal [install-malware ?attacker ?foothold-machine kill-disk])
	   (:action [fill-disk ?attacker ?foothold-machine kill-disk])
	   ))

;note: need plan for install malware

;;; Fix This
(defattack-method how-to-get-password-by-phishing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?resource ?foothold-machine ?foothold-role]
    :bindings ([email-client-of ?user ?process]
	       [ltms:value-of (?attacker machines) ?attacker-machine]
	       [ltms:value-of (?process host-os) ?os-instance]
	       [ltms:named-part-of ?machine os ?os-instance]
	       (unify ?path-so-far `((,?attacker-machine ?attacker)))
	       )
    :typing ([ltms:object-type-of ?user user]
	     [ltms:object-type-of ?process email-server-process]
	     [ltms:object-type-of ?os-instance operating-system]
             [ltms:object-type-of ?machine computer]
	     [ltms:object-type-of ?attacker-machine computer])
    :plan (:sequential
           (:goal [achieve-connection ?attacker ?path-so-far ?os-instance email nil ?foothold-machine ?foothold-role])
           (:action [phishing-attack ?attacker ?user ?process ?foothold-machine]))
    )


; This stuff was in the thing above, but I'm not sure what it was trying to say

; ((:goal (know (password ?user)) 
; 	:plan ((:goal (sniff (password ?user))
; 		      :plan ((:goal (achieve-email-connection-to ?os-instance) 
; 				    :plan ?plan)
; 			     )))))

(defattack-method how-to-get-password-by-sniffing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?resource ?foothold-machine ?foothold-role]
    :typing ([ltms:object-type-of ?user user]
             [ltms:object-type-of ?machine computer]
             [ltms:object-type-of ?subnet subnet])
    :bindings ([uses-machine ?user ?machine]
               [ltms:value-of (?machine subnets) ?subnet]
               )
    :plan (:parallel 
           (:goal [observe-network-traffic ?attacker ?subnet])
           (:action [sniff-a-password ?attacker ?user ?subnet]))
    )

 ; ((:goal (know (password ?user)) 
 ; 	 :plan (?observation-plan 
 ; 		(:action (sniff-a-passward ?user ?subnet)))))

;;; to be filled in: you can get his password by external sniffing of unsecured protocols
;;; such as smtp, pop

;;; ((:goal (connect ?machine) :plan ((:action (connect-via ?protocol-name ?machine)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Connecting
;;; Achieve-connection is given the following "In Arguments"
;;;  The attacker
;;;  Where  the attacker is starting from
;;;  The victim os instance
;;;  and what protocol he's trying
;;;  the path taken so far
;;; There is an "Out Argument" which is the first machine on the path from here
;;; and this machine is guaranteed to be directly reachable by the attacker
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; Direct Method, applicable when you can get from this foothold to the target-machine 
;;; so the foothold is the where this step is taking place from and the role is the attacker
;;; Fix: This seems to say that you can pass in either a machine or a user.  Does that make any sense?
(defattack-method achieve-connection-by-protocol
    :to-achieve [achieve-connection ?attacker ((?attacker-machine ?attacker-role) . ?rest-of-path)
				    ?victim-os-instance ?protocol-name ?attaker-machine ?attacker-role]
    :bindings ([ltms:named-part-of ?victim-machine os ?victim-os-instance])
    :typing ([ltms:object-type-of ?victim-os-instance operating-system]
	     [ltms:object-type-of ?victim-machine computer]
	     [ltms:object-type-of ?attacker-machine computer]
	     )
    :prerequisites ([accepts-connection ?victim-machine ?protocol-name ?attacker-machine ?]
		    )
    :plan (:action [connect-via ?attacker ?attacker-machine ?victim-machine ?protocol-name])
    )

;;; Lateral Motion
;;; If you're trying to achieve a connection to a machine
;;; One way to do so is to find a different machine in the same enterprise
;;; Gain remote-execution on that machine and then
;;; Achieve the connection from the remote machine
;;; Note: the way this currently works, the recusive call doesn't specify the next intermediate machine
;;; which will allow it to form multi-hop routes.  Note that the intermediate-machine that's bound here
;;; is the first hop from the attacker on the path to the victim

(defattack-method lateral-motion
    :to-achieve [achieve-connection ?attacker ?path-so-far ?victim-os-instance ?protocol-name ?intermediate-computer ?as-what]
    :bindings (
	       [ltms:value-of (?victim-os-instance machine) ?victim-machine]
	       [ltms:value-of (?victim-machine site) ?site]
	       [ltms:value-of (?site enterprise) ?enterprise]
	       [ltms:value-of (?enterprise sites) ?intermediate-site]
	       [ltms:value-of (?intermediate-site subnets) ?intermediate-subnet]
	       [ltms:value-of (?intermediate-subnet computers) ?intermediate-computer]
	       [ltms:named-part-of ?intermediate-computer os ?intermediate-os-instance]
	       (unify ?new-path-so-far `((,?intermediate-computer ,?as-what) ,@?path-so-far))
	       (unify ?attacker-machine (first (first ?path-so-far)))
	       (unify ?attacker-role (second (first ?path-so-far)))
	       )
    :typing ([ltms:object-type-of ?victim-os-instance operating-system]
	     [ltms:object-type-of ?victim-machine computer]
	     [ltms:object-type-of ?attacker-machine computer]
	     [ltms:object-type-of ?site site]
	     [ltms:object-type-of ?enterprise enterprise]
	     [ltms:object-type-of ?intermediate-site site]
	     [ltms:object-type-of ?intermediate-subnet subnet]
	     [ltms:object-type-of ?intermediate-computer computer]
	     [ltms:object-type-of ?intermediate-os-instance operating-system]
	     )
    :prerequisites (
		    [reachable-for-remote-execution ?intermediate-computer ?attacker-machine ssh]
		    [accepts-connection ?victim-machine ?protocol-name ?intermediate-computer ?]
		    (not (member ?intermediate-computer ?path-so-far :key #'first))
		    )
    :plan (:sequential
	   (:goal [achieve-remote-execution ?attacker ?as-what ?intermediate-os-instance ?attacker-machine ?attacker-role])
	   (:goal [achieve-connection ?attacker ?new-path-so-far ?victim-os-instance ?protocol-name ?intermediate-computer ?as-what])
	   ))

(defun reachable-for-remote-execution (victim attacker)
  (ask* `[reachable-for-remote-execution ,victim ,attacker ?protocol]
	(return-from reachable-for-remote-execution ?protocol))
  nil)

;;; These are the ways an attacker could possibly
;;; make a connection to get remote execution
(defrule can-be-reached-for-remote-execution-ssh (:backward)
  then [reachable-for-remote-execution ?victim ?attacker ssh]
  if [accepts-connection ?victim ssh ?attacker ?])

(defrule can-be-reached-for-remote-execution-telnet (:backward)
  then [reachable-for-remote-execution ?victim ?attacker telnet]
  if [accepts-connection ?victim telnet ?attacker ?])

(defrule can-be-reached-for-remote-executon-email (:backward)
  then [reachable-for-remote-execution ?victim ?attacker email]
  if [accepts-connection ?victim email ?attacker ?])

(defrule can-be-reached-for-remote-execution-http (:backward)
  then [reachable-for-remote-execution ?victim ?attacker http]
  if [accepts-connection ?victim http ?attacker ?])

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


;;; These next several sections really are just knowledge rules
;;; not rules about attacking

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Network Traffic
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method control-the-network-stack
    :to-achieve [takes-direct-control-of ?attacker ?stack-property ?network-stack]
    :bindings ([ltms:named-part-of ?os-instance network-monitor ?network-stack]
               [ltms:value-of (?os-instance superuser) ?superuser]
	       [ltms:value-of (?attacker machines) ?attacker-machine])
    :typing ([ltms:object-type-of ?network-stack network-stack]
             [ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?attacker-machine computer]
             [ltms:object-type-of ?superuser user])
    :plan (:sequential 
           (:goal [achieve-remote-shell ?attacker ?superuser ?os-instance ?attacker-machine])
           (:action [control ?attacker ?network-stack ?attacker-machine])))

(defattack-method read-network-traffic
    :to-achieve [observe-network-traffic ?attacker ?subnet]
    :bindings ([ltms:value-of (?subnet switch) ?switch]
               [ltms:value-of (?switch os) ?os]
               [ltms:named-part-of ?os network-monitor ?network-stack])
    :typing ([ltms:object-type-of ?subnet switched-subnet]
             [ltms:object-type-of ?switch switch]
             [ltms:object-type-of ?network-stack network-stack])
    :plan (:sequential (:goal [takes-direct-control-of ?attacker network-traffic ?network-stack])
                       (:action [observe ?attacker network-traffic ?subnet]))
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Knowledge about Connectivity, Access Rights and filtering policies
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
 
;;; this needs to use the rule below to get the path 
;;; and to check each boundary controller along the path. 

;;; Note, this rule is really here only for reasoning about what the attacker can 
;;; do.  The "Location" slot is unique to attacker.  Normally, we'll make queries 
;;; about machine to machine connections as in the next rule.
(defrule path-allows-connection-from-attacker (:backward)
  then [accepts-connection ?machine ?connection-type ?attacker ?path] 
  if [and [ltms:object-type-of ?machine computer]
	  [ltms:object-type-of ?attacker attacker]
	  [reachable-from ?machine ?attacker ?path]
	  [ltms:value-of (?attacker location) ?location]
	  (host-allows-connection-type ?machine ?location ?connection-type)
          (path-is-acceptable-for-connection-type (copy-object-if-necessary ?path)
                                                  ?location ?connection-type)
          ])

;;; This one is here specifically for the attacker machine
(defrule path-allows-connection-from-attacker-machine (:backward)
  then [accepts-connection ?machine ?connection-type ?attacker-machine ?path] 
  if [and [ltms:object-type-of ?attacker-machine attacker-computer]
	  [ltms:value-of (?attacker-machine users) ?attacker]
          [accepts-connection ?machine ?connection-type ?attacker ?path]
	  ])

(defrule path-allows-connect-from-normal-machine (:backward)
  then [accepts-connection ?target-machine ?connection-type ?attacker-machine ?path]
  if [and [ltms:object-type-of ?target-machine computer]
	  [ltms:object-type-of ?attacker-machine computer]
	  [reachable-from ?target-machine ?attacker-machine ?path]
	  [ltms:value-of (?attacker-machine ip-addresses) ?attacker-ip-address]
	  (host-allows-connection-type ?target-machine ?attacker-ip-address ?connection-type)
          (path-is-acceptable-for-connection-type (copy-object-if-necessary ?path)
                                                  ?attacker-ip-address ?connection-type)
          ]
  )


(defrule reachable-machine-to-machine (:backward)
  then [reachable-from ?target-computer ?source-computer ?path]
  if [and [ltms:object-type-of ?target-computer computer]
	  [ltms:object-type-of ?source-computer computer]
	  [connected ?target-computer ?source-computer ?path]
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
          [connected ?target-computer ?user-computer ?path]
	  ]
  )

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
  if [and [ltms:object-type-of ?object computer-resource]
	  [ltms:value-of (?object machines) ?computer]
          [ltms:object-type-of ?computer computer]
          [part-of (?computer os) ?os-instance]
          [ltms:object-type-of ?os-instance operating-system]
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



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Things relevant to control systems
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; If you want to affect the accuracy of a control process
;;; find it's sensors and then find a bus (or network) that
;;; those sensors are on and that the control process is also on
;;; the find another process that is also on that bus
;;; and send fake sensor data reports for that sensor to the control process


(defattack-method fake-sensor-data
    :to-achieve [affect ?attacker accuracy ?controller-process]
    :bindings ([ltms:value-of (?controller-process machines) ?controller-machine]
	       ;; does that machine play the part of a controller in some control system
	       [system-role ?system controller ?controller-machine]
	       ;; if so find a sensor in that same system
	       [system-role ?system sensor ?sensor-machine]
	       ;; and a bus that both the sensor and the controller are on
	       [connected-to ?sensor-machine ? ?bus ?]
	       [connected-to ?controller-machine ? ?bus ?]

	       ;; now find a another (or the same) machine that's on that machine
	       [connected-to ?attacker-machine ? ?bus ?]
	       ;; then find a process runnning on that machine
	       [ltms:named-part-of ?attacker-machine os ?attacker-os]
	       )
    :prerequisites ([output-of ?sensor-machine ?signal]
		    ;; the output of the sensor must be an input to 
		    ;; the controller process
		    [input-of ?controller-process ?signal]
		    [or [can-be-mastered-by ?controller-machine ?attacker-machine ?bus]
			(equal ?controller-machine ?attacker-machine)]

		    )
    :typing ([ltms:object-type-of ?controller-machine computer]
	     [ltms:object-type-of ?attacker-machine computer]
	     [ltms:object-type-of ?controller-process control-system-process]
	     [ltms:object-type-of ?system system]
	     [ltms:object-type-of ?sensor-machine computer]
	     [ltms:object-type-of ?signal sensor-signal]
	     [ltms:object-type-of ?bus unmastered-medium]
	     [ltms:object-type-of ?attacker-os operating-system]
	     )
    :plan (:sequential
	   ;; You have to specify what the entity here is
	   ;; it can either be a user or a process
	   ;; shouldn't really be in the operators that detemine how to do the remote execution
	   (:goal [achieve-remote-execution ?attacker ?entity ?attacker-os ?attacker-machine ?attacker])
	   ;; issue a false sensor data report to the controller from the attacker machine over the bus
	   ;; of the sensor type 
	   (:action [issue-false-sensor-data-report ?attacker ?controller-machine ?attacker-machine ?bus ?signal]))
    )

; (defattack-method fake-command-data
;     :to-achieve [affect ?attacker accuracy ?controller-process]
;     :bindings ([ltms:value-of (?controller-process machines) ?machine]
; 	       [connected-to-bus ?machine ?interface ?bus ?slot]
; 	       [connected-to-bus ?other-machine ?other-interface ?bus ?other-slot]
; 	       [ltms:named-part-of ?other-machine os ?os])
;     :prerequisites ((not (eql ?machine ?other-machine))
; 		    [can-be-mastered-by ?machine ?other-machine ?bus])
;     :typing ([ltms:object-type-of ?machine computer]
; 	     [ltms:object-type-of ?other-machine computer]
; 	     [ltms:object-type-of ?os operating-system]
; 	     [ltms:object-type-of ?bus bus])
;     :plan (:sequential
; 	   (:goal [remote-execution ?attacker ?entity ?os])
; 	   (:action [issue-incorrect-setpoint ?attacker ?machine ?other-machine ?bus]))
;     )

(defattack-method sensor-injection-attack
    :to-achieve [affect ?attacker data-integrity ?signal]
    :bindings ([ltms:value-of (?signal  machines) ?machine])
    :prerequisites ([system-role ?system sensor ?machine]
		    [is-proximate-to ?attacker ?victim radio])
    :typing ([ltms:object-type-of ?machine computer]
	     [ltms:object-type-of ?signal sensor-signal]
	     [ltms:object-type-of ?system system])
    :plan (:action [signal-noise-injection ?attacker ?machine ?signal]))
