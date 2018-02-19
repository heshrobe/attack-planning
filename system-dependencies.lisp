;;; -*- Syntax: Joshua; Package: APLAN; Mode: JOSHUA; syntax: joshua; readtable: Joshua  -*-

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
    :bindings ([value-of (?victim machines) ?computer]
               [named-part-of ?computer os ?os-instance]
               [part-of ?os-instance ?component])
    :typing ([object-type-of ?victim computer-resource]
             [object-type-of ?os-instance operating-system]
	     [object-type-of ?component process])
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
    :bindings ([value-of (?process host-os) ?os]
	       [value-of (?os workload) ?workload])
    :typing ([object-type-of ?process process]
	     [object-type-of ?os operating-system]
	     [object-type-of ?workload os-workload])
    :plan (:goal [increase-size ?attacker ?workload])
    )

;;; now what we want to say is:
;;; Either 
;;; 1) find a process in the current workload that is capable of launching new jobs
;;; get control of that process and cause it launch jobs.  For example, a server that takes 
;;; requests through some protocol and launches jobs in response (e.g. web server ftp server)
;;; repeatedly connect to it and cause it to launch a job
;;; 2) Increase the size of the job launch queue

(defattack-method increase-workload-by-increasing-job-launch-queue
    :to-achieve [increase-size ?attacker ?workload]
    :bindings ([value-of (?workload os) ?os]
	       [value-of (?os job-launch-queue) ?queue]
	       [named-part-of ?queue user-job-launch-request-queue ?user-job-launch-queue])
    :typing ([object-type-of ?workload os-workload]
	     [object-type-of ?os operating-system]
	     [object-type-of ?queue os-job-launch-request-queue]
	     [object-type-of ?user-job-launch-queue job-launch-request-queue])
    :plan (:goal [increase-size ?attacker ?user-job-launch-queue]))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Data Privacy
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method read-file-property-directly
    :to-achieve [affect ?attacker data-privacy ?file]
    :prerequisites ([desirable-property-of ?file data-privacy])
    :typing ([object-type-of ?file data-resource])
    :plan (:goal [achieve-knowledge-of-contents ?attacker ?file])
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Data Integrity
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method write-file-property-directly
    :to-achieve [affect ?attacker data-integrity ?file]
    :typing ([object-type-of ?file file])
    :prerequisites ([desirable-property-of ?file data-integrity])
    :plan (:goal [modify ?attacker contents ?file])
    )

;;; To affect the data-integrity of some data-set
;;; Get control of a process that produces the data-set
(defattack-method mung-process-output
    :to-achieve [affect ?attacker data-integrity ?data-set]
    :bindings ([output-of ?process ?data-set])    
    :typing ([object-type-of ?process process])
    :plan (:sequential
           (:goal [takes-control-of ?attacker data-integrity ?process])
           (:goal [use-control-of-to-affect-resource ?attacker ?process data-integrity ?data-set]))
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

(defattack-method control-process-through-loadable-files
    :to-achieve [takes-direct-control-of ?attacker ?victim-property ?victim]
    :bindings ([value-of (?victim program) ?program]
               [value-of (?program load-files) ?file])
    :typing ([object-type-of ?victim process]
             [object-type-of ?program program]
             [object-type-of ?file dynamically-loadable-code-file])
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
    ;; :bindings ([value-of (?process host-os) ?os-instance])
    :typing ([object-type-of ?process process]
             ;; [object-type-of ?os-instance operating-system]
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
(defattack-method control-component-through-input
    :to-achieve [takes-indirect-control-of ?attacker ?victim-property ?victim]
    ;; assumption is that we know thing
    :bindings ([input-of ?thing ?input])
    :plan (:goal [modify ?attacker contents ?input])
    )


;;; want to say that if the property is affected by the size of the input
;;; then change the size of the input

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
    :to-achieve [modify ?attacker ?victim-property ?victim]
    :bindings ([part-of ?victim ?component])
    :prerequisites ([impacts ?component-property ?component ?victim-property ?victim])
    :plan (:goal [modify ?attacker ?component-property ?component])
    )

;;; modify a data-set by controlling a process that controls the data-set
(defattack-method modify-through-controller
    :to-achieve [modify ?attacker ?victim-property ?victim]
    :typing ([object-type-of ?controller process]
             [object-type-of ?victim data-set])
    :prerequisites ([process-controls-data-set ?controller ?victim])
    :plan (:sequential 
           (:goal [takes-control-of ?attacker (controlled-data-set ?victim) ?controller])
           (:goal [use-control-of-to-affect-resource ?attacker ?controller ?victim-property ?victim])) 
    )

;;; NOTE: This should be expressed in a more general way about transforming formats
;;; but it will do for now.
(defattack-method modify-loadable-code
    :to-achieve [modify ?attacker ?file-property ?object-file]
    :prerequisites ([object-type-of ?object-file dynamically-loadable-code-file]
                    [value-of (?object-file source-file) ?source-file])
    :plan (:sequential (:goal [modify ?attacker code ?source-file])
                       (:goal [force-compilation ?attacker ?source-file ?object-file]))
    )

(defattack-method modify-through-available-access-rights
    :to-achieve [modify ?attacker ?object-property ?object]
    :bindings ([value-of (?object machines) ?computer])
    :typing ([object-type-of ?computer computer])
    :prerequisites ([requires-access-right ?object write ?capability])
    :plan (:sequential (:goal [achieve-access-right ?attacker write ?object ?user])
                       (:action [use-access-right-to-modify ?attacker write ?user ?object]))
    )

;;; To increase the size of the active user set of some OS
;;; Find a user in the authorization pool for the OS
;;; and make that user a member of the active user set
(defattack-method modify-size-by-increase-size
    :to-achieve [modify ?attacker size ?object]
    :plan (:goal [increase-size ?attacker ?object])
    )

(defattack-method modify-active-user-set
    :to-achieve [increase-size ?attacker ?active-user-set]
    :bindings ([value-of (?active-user-set os) ?os-instance]
               [value-of (?os-instance authorization-pool) ?authorization-pool]
               [value-of (?authorization-pool users) ?user])
    :typing ([object-type-of ?active-user-set user-set]
             [object-type-of ?os-instance operating-system]
             [object-type-of ?authorization-pool authorization-pool]
             [object-type-of ?user user])
    :plan (:goal [make-member-of ?attacker ?user ?active-user-set])
    )

;;; NOTE: There are other ways of doing this, e.g. find some logged in user and take over his process
;;; in order to submit lots of jobs



(defattack-method modify-job-request-queue
    :to-achieve [increase-size ?attacker ?user-job-launch-queue]
    :bindings ([named-part-of ?full-job-launch-queue user-job-launch-request-queue ?user-job-launch-queue]
               [value-of (?full-job-launch-queue os) ?os-instance]
	       [value-of (?os-instance job-launch-queue) ?full-job-launch-queue])
    :typing ([object-type-of ?user-job-launch-queue job-launch-request-queue]
             [object-type-of ?full-job-launch-queue os-job-launch-request-queue]
             [object-type-of ?os-instance operating-system])
    :plan (:sequential
           (:goal [logon ?attacker ?user ?os-instance])
           (:repeated-action [submit-user-jobs ?user ?user-job-launch-queue])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Performance related specifics
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; If somebody has goined direct control of the job-launcher
;;; They can affect performance by adding jobs
(defattack-method add-jobs-after-job-launcher-is-hacked
    :to-achieve [use-control-of-to-affect-resource ?attacker ?controller performance ?target]
    :bindings ([named-part-of ?os job-admitter ?controller]
               [value-of (?os-instance workload) ?input])
    :typing ([object-type-of ?controller os-job-admitter]
             [object-type-of ?os operating-system]
             [object-type-of ?input os-workload]
	     [object-type-of ?target process])
    :plan (:action [add-user-jobs ?attacker ?input]))



;;; If you control a process that produces an output
;;; you can use that control to mung the data-structure in core
(defattack-method mung-in-core-data-structures
    :to-achieve [use-control-of-to-affect-resource ?attacker ?process data-integrity ?data-set]
    :bindings ([output-of ?process ?data-set])
    :typing ([object-type-of ?process process])
    :plan (:action [modify-in-core-data-structures ?process ?data-set]))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Methods for hacking access rights and gaining access
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method how-to-read-a-file
    :to-achieve [achieve-knowledge-of-contents ?attacker ?file]
    :typing ([object-type-of ?file file])
    :plan (:sequential
           (:goal [achieve-access-right ?attacker read ?file ?user])
           (:action [read-with-rights-of ?attacker ?user ?file]))
    )

;;; The ?user part of this is actually to feed back to the higher
;;; level that it should read the file with the access rights of the user
;;; but is that really necessary, why isn't the process enough
(defattack-method how-to-achieve-access-right
    :to-achieve [achieve-access-right ?attacker ?right ?object ?user]
    ;; all this is asking is there a process in the workload
    ;; and if so with which user's permissions is it running
    :bindings ([value-of (?object machines) ?machine]
               [named-part-of ?machine os ?os-instance]
               [value-of (?os-instance workload) ?os-workload]
               [or [value-of (?os-workload server-workload processes) ?the-process]
                   [value-of (?os-workload user-workload processes) ?the-process]]
               [runs-with-permissions-of ?the-process ?user]
               )
    :typing ([object-type-of ?object computer-resource]
             [object-type-of ?machine computer]
             [object-type-of ?os-instance operating-system]
             [object-type-of ?os-workload os-workload]
             [object-type-of ?the-process process]           
             )
    ;; This is the key pre-req: The process has the desired right to the object
    :prerequisites ([has-permission ?the-process ?right ?object])
    :plan (:goal [takes-direct-control-of ?attacker (access-right ?right ?object) ?the-process])
    )


(defattack-method how-to-achieve-access-right-by-password-stealing
    :to-achieve [achieve-access-right ?attacker ?right ?object ?user]
    :bindings ([value-of (?object machines) ?machine]
               [named-part-of ?machine os ?os-instance]
               [requires-access-right ?object ?right ?capability])
    ;; Note: has-capability is a function not an assertion
    :PREREQUISITES ((has-capability ?user ?capability))
    :typing ([object-type-of ?object computer-resource]
             [object-type-of ?machine computer]
             [object-type-of ?os-instance operating-system]
             [object-type-of ?user user])
    :plan (:goal [logon ?attacker ?user ?os-instance])
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Active User Set and Logging in 
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method join-active-user-set
    :to-achieve [make-member-of ?attacker ?user ?active-user-set]
    :bindings ([value-of (?active-user-set os) ?os-instance])
    :typing ([object-type-of ?active-user-set user-set]
             [object-type-of ?os-instance operating-system])
    :plan (:goal [logon ?attacker ?user ?os-instance])
    )

(defattack-method how-to-logon-1
    :to-achieve [logon ?attacker ?user ?os-instance]
    :bindings ([value-of (?os-instance authorization-pool) ?pool]
               [value-of (?pool users) ?user])
    :typing ([object-type-of ?os-instance operating-system]
             [object-type-of ?pool authorization-pool]
             [object-type-of ?user user])
    :plan (:sequential
           (:goal [achieve-knowledge-of-password ?attacker ?user ?pool])
           (:goal [achieve-connection ?attacker ?os-instance telnet])
           (:action [logon ?attacker ?user ?os-instance])))

(defattack-method how-to-logon-2
    :to-achieve [logon ?attacker ?user ?os-instance]
    :bindings ([value-of (?os-instance authorization-pool) ?pool]
               [value-of (?pool users) ?user])
    :typing ([object-type-of ?os-instance operating-system]
             [object-type-of ?pool authorization-pool]
             [object-type-of ?user user])
    :plan (:sequential
           (:goal [achieve-knowledge-of-password ?attacker ?user ?pool])
           (:goal [achieve-connection ?attacker ?os-instance ssh])
           (:action [logon ?attacker ?user ?os-instance])))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Passwords and secrets
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method user-knows-own-password
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?resource]
    :prerequisites ((equal ?attacker ?user))
    :plan (:action [use-own-password ?user ?resource])
    )
            
(defattack-method how-to-get-password-by-guessing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?resource]
    :prerequisites ((not (equal ?attacker ?user)))
    :plan (:goal [guess-password ?attacker ?user ?resource])
    )

(defattack-method guess-typical-user
    :to-achieve [guess-password ?attacker ?user ?resource]
    :typing ([object-type-of ?user typical-user]
             [object-type-of ?attacker attacker])
    :plan (:action [password-dictionary-lookup-attack ?attacker ?user ?resource])
    )

(defattack-method guess-superuser-passwords
    :to-achieve [guess-password ?attacker ?user ?resource]
    :typing ([value-of (?user machines) ?machine]
             [value-of (?machine os superuser) ?user])
    :bindings ([object-type-of ?user user]
               [object-type-of ?machine computer])
    :plan (:action [password-dictionary-lookup-attack ?attacker ?user ?resource])
    )

(defattack-method how-to-get-password-by-virus
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?resource]
    :typing ([object-type-of ?user user]
             [object-type-of ?machine computer])
    :bindings ([uses-machine ?machine ?user]
               [named-part-of ?machine os ?os-instance])
    :plan (:sequential
           (:goal [achieve-connection ?attacker ?os-instance email])
           (:action [social-engineering-attack ?attacker ?user]))
    )

; This stuff was in the thing above, but I'm not sure what it was trying to say

; ((:goal (know (password ?user)) 
; 	:plan ((:goal (sniff (password ?user))
; 		      :plan ((:goal (achieve-email-connection-to ?os-instance) 
; 				    :plan ?plan)
; 			     )))))

(defattack-method how-to-get-password-by-sniffing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?resource]
    :typing ([object-type-of ?user user]
             [object-type-of ?machine computer]
             [object-type-of ?subnet subnet])
    :bindings ([uses-machine ?machine ?user]
               [value-of (?machine subnets) ?subnet]
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
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method achieve-connection-by-protocol
    :to-achieve [achieve-connection ?attacker ?os-instance ?protocol-name]
    :bindings ([named-part-of ?machine os ?os-instance])
    :typing ([object-type-of ?os-instance operating-system]
             [object-type-of ?machine computer])
    :prerequisites ([accepts-connection ?machine ?protocol-name ?attacker ?])
    :plan (:action [connect-via ?attacker ?machine ?protocol-name])
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


;;; These next several sections really are just knowledge rules
;;; not rules about attacking

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Network Traffic
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method control-the-network-stack
    :to-achieve [takes-direct-control-of ?attacker ?stack-property ?network-stack]
    :bindings ([named-part-of ?os-instance network-monitor ?network-stack]
               [value-of (?os-instance superuser) ?superuser])
    :typing ([object-type-of ?network-stack network-stack]
             [object-type-of ?os-instance operating-system]
             [object-type-of ?superuser user])
    :plan (:sequential 
           (:goal [logon ?attacker ?superuser ?os-instance])
           (:action [control ?attacker ?network-stack])))

(defattack-method read-network-traffic
    :to-achieve [observe-network-traffic ?attacker ?subnet]
    :bindings ([value-of (?subnet switch) ?switch]
               [value-of (?switch os) ?os]
               [named-part-of ?os network-monitor ?network-stack])
    :typing ([object-type-of ?subnet switched-subnet]
             [object-type-of ?switch switch]
             [object-type-of ?network-stack network-stack])
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

(defrule path-allows-connection (:backward)
  then [accepts-connection ?machine ?connection-type ?user ?path] 
  if [and [object-type-of ?machine computer]
          [object-type-of ?user user]
          [reachable-from ?machine ?user ?path]
	  [value-of (?user location) ?location]
          (path-is-acceptable-for-connection-type (copy-object-if-necessary ?path)
                                                  ?location ?connection-type)
          ])

(defrule bridges-on-pathway (:backward)
  then [reachable-from ?target-computer ?user ?path]
  if [and [object-type-of ?user user]
          [object-type-of ?target-computer computer]
          [uses-machine ?user-computer ?user]
          [object-type-of ?user-computer computer]
          [connected ?target-computer ?user-computer ?path]
	  ]
  )


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
					